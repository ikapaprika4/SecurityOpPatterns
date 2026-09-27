"""
Host inventory -- the NetworkMiner "Hosts" tab: IP/MAC pairing, a rough OS
guess, open ports, and sent/received traffic volume, built from nothing but
the packet fields already extracted by pcapread.

OS fingerprinting is intentionally simple (initial TTL bucket + SYN window
size), the same signal NetworkMiner's own backends (Satori, p0f) lean on.
It is a guess, not ground truth -- `os_confidence` stays "low" unless both
signals agree, and callers should treat it as a triage hint, never evidence.
"""

from __future__ import annotations

from .models import Conversation, Host, PacketRecord

# (max_ttl_seen_le, likely_family) -- real TTL erodes by 1 per hop, so we
# bucket against the common starting values (64/128/255) rather than an
# exact match.
_TTL_BUCKETS = [
    (34, "Windows (old, TTL~32)"),
    (66, "Linux / Unix / macOS (TTL~64)"),
    (130, "Windows (TTL~128)"),
    (256, "Network device / Solaris / some Unix (TTL~255)"),
]

# Window sizes are noisy across OS versions and middleboxes rewrite them --
# used only to raise confidence when it agrees with the TTL bucket, never
# to override it.
_WINDOW_HINTS = {
    64240: "Linux",
    5840: "Linux (older)",
    29200: "Linux",
    65535: "Windows / macOS / BSD",
    8192: "Windows (older)",
    14600: "Linux",
}


def _unicast_mac(mac: str) -> bool:
    """False for broadcast/multicast (the I/G bit of the first octet):
    ff:ff:ff:ff:ff:ff, 01:00:5e:*, 33:33:* name a group, never a host."""
    try:
        return not int(mac[:2], 16) & 1
    except ValueError:
        return False


def _ttl_bucket(ttl: int) -> str:
    for ceiling, label in _TTL_BUCKETS:
        if ttl <= ceiling:
            return label
    return "unknown"


def build_hosts(packets: list[PacketRecord]) -> dict[str, Host]:
    hosts: dict[str, Host] = {}

    def get(ip: str) -> Host:
        if ip not in hosts:
            hosts[ip] = Host(ip=ip)
        return hosts[ip]

    # A DHCP DISCOVER/REQUEST is sent from 0.0.0.0 -- the hostname it claims
    # belongs to whatever IP that client's MAC is later handed by the ACK,
    # not to "0.0.0.0". Build that mapping first so the main pass can attach
    # the hostname to the real address.
    mac_to_assigned_ip: dict[str, str] = {}
    mac_to_claimed_hostname: dict[str, str] = {}
    for p in packets:
        f = p.fields
        mac = f.get("dhcp.hw.mac_addr")
        if not mac:
            continue
        if f.get("dhcp.option.dhcp") == 5 and f.get("dhcp.yiaddr"):  # ACK
            mac_to_assigned_ip[mac] = f["dhcp.yiaddr"]
        if f.get("dhcp.option.hostname"):
            mac_to_claimed_hostname[mac] = f["dhcp.option.hostname"]
    for mac, hostname in mac_to_claimed_hostname.items():
        assigned = mac_to_assigned_ip.get(mac)
        if assigned:
            get(assigned).hostnames.add(hostname)
            get(assigned).macs.add(mac)

    for p in packets:
        f = p.fields
        if p.proto == "arp":
            src_ip, dst_ip = f.get("arp.src.proto_ipv4"), f.get("arp.dst.proto_ipv4")
            if src_ip:
                h = get(src_ip)
                h.touch(p.ts)
                if f.get("arp.src.hw_mac"):
                    h.macs.add(f["arp.src.hw_mac"])
            continue

        if not p.src_ip:
            continue

        src, dst = get(p.src_ip), get(p.dst_ip) if p.dst_ip else None
        src.touch(p.ts)
        if dst:
            dst.touch(p.ts)
        if p.src_mac and _unicast_mac(p.src_mac):
            src.macs.add(p.src_mac)
        if dst and p.dst_mac and _unicast_mac(p.dst_mac):
            dst.macs.add(p.dst_mac)

        src.packets_sent += 1
        src.bytes_sent += p.length
        if dst:
            dst.packets_recv += 1
            dst.bytes_recv += p.length

        # Open-port inference: a SYN,ACK response means the destination of
        # the original SYN has that port open.
        if p.proto == "tcp" and f.get("tcp.flags.syn") == 1 and f.get("tcp.flags.ack") == 1:
            src.open_ports.add(p.src_port)

        # OS fingerprint from the *client's* initial SYN (TTL/window are most
        # reliable before any reply has been seen).
        if p.proto == "tcp" and f.get("tcp.flags.syn") == 1 and f.get("tcp.flags.ack") == 0:
            ttl = f.get("ip.ttl", f.get("ipv6.hlim"))      # IPv6's hop limit is the same signal
            window = f.get("tcp.window_size")
            if ttl is not None and not src.os_guess:
                bucket = _ttl_bucket(int(ttl))
                hint = _WINDOW_HINTS.get(int(window)) if window is not None else None
                src.os_guess = f"{bucket}" + (f" -- consistent with {hint}" if hint else "")
                src.os_confidence = "medium" if hint else "low"

        # Hostnames observed in the clear: DHCP request, DNS answer, NBNS,
        # HTTP Host header, TLS SNI -- whichever host owns the source IP of
        # that packet is the one making the claim.
        if f.get("dhcp.option.hostname"):
            src.hostnames.add(f["dhcp.option.hostname"])
        owner = nbns_owner(p)
        if owner:
            get(owner).hostnames.add(f["nbns.name"])
        if f.get("http.host") and dst:
            dst.hostnames.add(f["http.host"])
        if f.get("kerberos.hostname"):
            src.hostnames.add(f["kerberos.hostname"].rstrip("$"))

    return hosts


# NBNS opcodes in which a host asserts a name as its own.
_NBNS_CLAIMS = {5, 8, 9, 15}        # registration, refresh (x2), multi-homed registration


def nbns_owner(p: PacketRecord):
    """The IP that owns the NBNS name in this packet, or None. A plain name
    *query* only says who is being looked for -- attributing it to the
    querier labelled every workstation with every name it looked up (WPAD,
    file servers, printers...). Registrations and positive responses carry
    the owner's address. (Packets from the scapy backend carry no opcode;
    they keep the old source-IP attribution.)"""
    f = p.fields
    if not f.get("nbns.name"):
        return None
    if "nbns.opcode" not in f:
        return p.src_ip
    if f["nbns.opcode"] in _NBNS_CLAIMS:
        return f.get("nbns.addr") or p.src_ip
    if f["nbns.opcode"] == 0 and f.get("nbns.flags.response") and f.get("nbns.addr"):
        return f["nbns.addr"]
    return None


def resolved_addresses(packets: list[PacketRecord]) -> dict[str, set[str]]:
    """DNS answers seen in the capture: IP -> {hostnames}, the NetworkMiner
    / Wireshark "Resolved Addresses" view. Every A record of an answer counts,
    so a CNAME chain maps its final address back to the name queried."""
    out: dict[str, set[str]] = {}
    for p in packets:
        f = p.fields
        qname = f.get("dns.qry.name")
        if not qname or f.get("dns.qry.type") != 1:            # A queries
            continue
        for answer in f.get("dns.a_all") or ([f["dns.a"]] if f.get("dns.a") else []):
            out.setdefault(answer, set()).add(qname)
    return out


def build_conversations(packets: list[PacketRecord]) -> list[Conversation]:
    convos: dict[tuple, Conversation] = {}
    for p in packets:
        if not p.src_ip or not p.dst_ip or p.proto not in ("tcp", "udp"):
            continue
        c = Conversation(proto=p.proto, a_addr=p.src_ip, b_addr=p.dst_ip,
                          a_port=p.src_port, b_port=p.dst_port)
        key = c.key
        existing = convos.get(key)
        if existing is None:
            c.packets, c.bytes = 1, p.length
            c.start = c.end = p.ts
            convos[key] = c
        else:
            existing.packets += 1
            existing.bytes += p.length
            existing.start = min(existing.start, p.ts)
            existing.end = max(existing.end, p.ts)
    return sorted(convos.values(), key=lambda c: c.bytes, reverse=True)
