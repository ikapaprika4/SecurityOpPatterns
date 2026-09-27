"""
PCAP ingestion -- turns every frame into a PacketRecord with a flat,
Wireshark-named field dict.

Two backends:

  native (default)  soccore.pcap: stdlib only, pcap + pcapng (+gzip), IPv4 and
                    IPv6, Ethernet/VLAN/SLL/raw-IP link layers. Verified field
                    for field against the scapy backend with
                    tools/compare_pcap_backends.py.
  scapy  (opt-in)   the original implementation, kept for comparison. Select
                    with read_pcap(path, backend="scapy") or the environment
                    variable TRAFKIT_BACKEND=scapy.

Either way a packet trafkit doesn't fully understand still yields whatever it
*does* understand instead of aborting the read -- the same "one bad frame
can't kill the run" isolation the detectors use.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from soccore import pcap as _native
from soccore.pcap import ber_general_strings as _ber_general_strings  # noqa: F401 (re-export)
from soccore.pcap import extract_sni as _extract_sni

from .models import PacketRecord

_DNS_QTYPES = _native.DNS_QTYPES
_FTP_COMMANDS = _native.FTP_COMMANDS
_HTTP_METHODS = set(_native.HTTP_METHODS)


def read_pcap(path: str, backend: Optional[str] = None,
              max_packets: Optional[int] = None, status: Optional[dict] = None) -> list[PacketRecord]:
    """Read every frame in `path` into a list[PacketRecord], in file order.
    `status` (native backend): filled with `frames` and `problem` -- None
    when the file was read to a clean end, else why reading stopped early."""
    backend = (backend or os.environ.get("TRAFKIT_BACKEND") or "native").lower()
    if backend == "scapy":
        return _read_pcap_scapy(path, max_packets)
    if backend != "native":
        raise ValueError(f"unknown pcap backend {backend!r} (native | scapy)")
    return _native.read_packets(path, max_packets=max_packets, factory=PacketRecord, status=status)


# --------------------------------------------------------------------------
# scapy backend (opt-in)
# --------------------------------------------------------------------------

def _read_pcap_scapy(path: str, max_packets: Optional[int] = None) -> list[PacketRecord]:
    # `scapy.all` must be imported before PcapReader opens the file: it's
    # what registers the link-layer-type -> dissector table (Ether for
    # LINKTYPE_ETHERNET etc.). Importing it lazily inside `_extract()` is too
    # late -- PcapReader resolves the file's link type once at open time, so
    # a process that hasn't loaded scapy.all yet gets every frame back as
    # undissected Raw bytes instead of Ether/IP/...
    try:
        import scapy.all  # noqa: F401
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise RuntimeError("the scapy backend needs scapy: pip install scapy "
                           "(or use the default native backend)") from exc

    records: list[PacketRecord] = []
    with PcapReader(path) as reader:
        for i, pkt in enumerate(reader, start=1):
            if max_packets is not None and i > max_packets:
                break
            try:
                rec = _extract(pkt, i)
            except Exception:
                rec = PacketRecord(frame_number=i, ts=float(getattr(pkt, "time", 0.0) or 0.0),
                                    length=len(pkt), fields={}, summary="malformed")
            records.append(rec)
    return records


def _extract(pkt, frame_number: int) -> PacketRecord:
    from scapy.all import ARP, ICMP, IP, TCP, UDP

    ts = float(getattr(pkt, "time", 0.0) or 0.0)
    length = len(pkt)
    f: dict[str, Any] = {
        "frame.number": frame_number,
        "frame.time_epoch": ts,
        "frame.len": length,
    }
    rec = PacketRecord(frame_number=frame_number, ts=ts, length=length, fields=f,
                        summary=pkt.summary())

    if pkt.haslayer("Ether"):
        eth = pkt.getlayer("Ether")
        f["eth.src"] = str(eth.src)
        f["eth.dst"] = str(eth.dst)
        rec.src_mac, rec.dst_mac = f["eth.src"], f["eth.dst"]

    # ---- ARP --------------------------------------------------------
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        f["arp.opcode"] = int(arp.op)
        f["arp.src.proto_ipv4"] = str(arp.psrc)
        f["arp.dst.proto_ipv4"] = str(arp.pdst)
        f["arp.src.hw_mac"] = str(arp.hwsrc)
        f["arp.dst.hw_mac"] = str(arp.hwdst)
        f["arp.duplicate-address-detected"] = bool(
            arp.op == 2 and arp.psrc == arp.pdst
        )
        rec.proto = "arp"
        rec.src_ip, rec.dst_ip = f["arp.src.proto_ipv4"], f["arp.dst.proto_ipv4"]
        return rec

    if not pkt.haslayer(IP):
        return rec

    ip = pkt[IP]
    f["ip.src"] = str(ip.src)
    f["ip.dst"] = str(ip.dst)
    f["ip.ttl"] = int(ip.ttl)
    f["ip.proto"] = int(ip.proto)
    f["ip.flags"] = str(ip.flags)
    f["ip.frag"] = int(ip.frag)
    f["ip.len"] = int(getattr(ip, "len", length) or length)
    rec.src_ip, rec.dst_ip = f["ip.src"], f["ip.dst"]

    # ---- ICMP ---------------------------------------------------------
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        f["icmp.type"] = int(icmp.type)
        f["icmp.code"] = int(icmp.code)
        f["data.len"] = len(bytes(icmp.payload))
        rec.proto = "icmp"
        # Destination-unreachable etc. encapsulate the original packet --
        # that's how a UDP port scan's closed-port response is attributed
        # back to the probed port (Wireshark: Traffic Analysis, UDP scans).
        # Scapy dissects the encapsulated packet as IPerror/UDPerror/TCPerror
        # (distinct classes from IP/UDP/TCP), not the normal layer classes.
        try:
            from scapy.layers.inet import IPerror, TCPerror, UDPerror
            if icmp.haslayer(IPerror):
                inner_ip = icmp[IPerror]
                f["icmp.orig.ip.src"] = str(inner_ip.src)
                f["icmp.orig.ip.dst"] = str(inner_ip.dst)
                if icmp.haslayer(UDPerror):
                    f["icmp.orig.udp.srcport"] = int(icmp[UDPerror].sport)
                    f["icmp.orig.udp.dstport"] = int(icmp[UDPerror].dport)
                elif icmp.haslayer(TCPerror):
                    f["icmp.orig.tcp.srcport"] = int(icmp[TCPerror].sport)
                    f["icmp.orig.tcp.dstport"] = int(icmp[TCPerror].dport)
        except Exception:
            pass
        return rec

    # ---- TCP ------------------------------------------------------------
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.proto = "tcp"
        rec.src_port, rec.dst_port = int(tcp.sport), int(tcp.dport)
        f["tcp.srcport"] = rec.src_port
        f["tcp.dstport"] = rec.dst_port
        flags = int(tcp.flags)
        f["tcp.flags"] = flags
        f["tcp.flags.fin"] = int(bool(flags & 0x01))
        f["tcp.flags.syn"] = int(bool(flags & 0x02))
        f["tcp.flags.reset"] = int(bool(flags & 0x04))
        f["tcp.flags.push"] = int(bool(flags & 0x08))
        f["tcp.flags.ack"] = int(bool(flags & 0x10))
        f["tcp.flags.urg"] = int(bool(flags & 0x20))
        f["tcp.window_size"] = int(tcp.window)
        f["tcp.seq"] = int(tcp.seq)
        f["tcp.ack"] = int(tcp.ack)
        f["tcp.port"] = rec.src_port  # `tcp.port == N` matches either direction
        # Use the TCP layer's own `.payload`, not `pkt[Raw]` -- once any
        # scapy contrib module binds a dissector to this port (e.g. the
        # HTTP layer binding itself to port 80 the first time it's
        # imported), later packets on that port are no longer left as a
        # bare Raw layer, and pkt.haslayer(Raw) would silently go False.
        tcp_payload = bytes(tcp.payload)
        f["data.len"] = len(tcp_payload)
        _apply_application_layer(f, rec, tcp_payload)
        return rec

    # ---- UDP --------------------------------------------------------------
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.proto = "udp"
        rec.src_port, rec.dst_port = int(udp.sport), int(udp.dport)
        f["udp.srcport"] = rec.src_port
        f["udp.dstport"] = rec.dst_port
        f["udp.port"] = rec.src_port
        udp_payload = bytes(udp.payload)
        f["data.len"] = len(udp_payload)
        _apply_application_layer(f, rec, udp_payload)
        _apply_dns(f, pkt)
        _apply_dhcp(f, pkt)
        _apply_nbns(f, pkt)
        _apply_kerberos(f, pkt, udp_payload)
        return rec

    rec.proto = "ip"
    return rec


def _apply_application_layer(f: dict, rec: PacketRecord, payload: bytes) -> None:
    port_pair = {rec.src_port, rec.dst_port}
    if not payload:
        return

    if port_pair & {80, 8080, 8000, 8888}:
        _apply_http(f, payload)
    if port_pair & {21}:
        _apply_ftp(f, payload)
    # Not port-gated: a TLS record's first bytes (0x16 0x03 0x0X, handshake
    # content type + version) are a strong enough signature on their own,
    # and catching a handshake on an *unexpected* port is the whole point
    # of TLS-PORT-01 -- gating this on port 443 would make that detector
    # blind to exactly the traffic it exists to catch.
    _apply_tls(f, payload)


def _apply_http(f: dict, payload: bytes) -> None:
    text_head = payload[:16]
    is_request = any(text_head.startswith(m.encode()) for m in _HTTP_METHODS)
    is_response = text_head.startswith(b"HTTP/")
    if not (is_request or is_response):
        return
    try:
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    except Exception:
        return
    try:
        h = HTTP(payload)
    except Exception:
        return

    def s(v) -> Optional[str]:
        if v is None:
            return None
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)

    if h.haslayer(HTTPRequest):
        r = h[HTTPRequest]
        f["http.request"] = True
        f["http.request.method"] = s(r.Method)
        f["http.request.uri"] = s(r.Path)
        f["http.request.full_uri"] = s(r.Path)
        f["http.host"] = s(r.Host)
        f["http.user_agent"] = s(r.User_Agent)
        if s(r.Authorization):
            f["http.authorization"] = s(r.Authorization)
        if s(r.Cookie):
            f["http.cookie"] = s(r.Cookie)
        body = _http_body(h, r)
        if body:
            f["http.file_data"] = body
    if h.haslayer(HTTPResponse):
        r = h[HTTPResponse]
        f["http.response"] = True
        code = s(r.Status_Code)
        f["http.response.code"] = int(code) if code and code.isdigit() else code
        f["http.server"] = s(r.Server)
        f["http.content_type"] = s(r.Content_Type)
        cd = s(getattr(r, "Content_Disposition", None))
        if cd:
            f["http.content_disposition"] = cd


def _http_body(h, layer) -> Optional[str]:
    try:
        rest = bytes(layer.payload)
        if rest:
            return rest[:4096].decode("latin-1", "replace")
    except Exception:
        pass
    return None


def _apply_tls(f: dict, payload: bytes) -> None:
    """TLS record/handshake type plus ClientHello SNI extraction."""
    if len(payload) < 6 or payload[0] != 0x16:      # not a TLS handshake record
        return
    handshake_type = payload[5]
    f["tls.handshake.type"] = handshake_type
    f["tls.record.content_type"] = payload[0]

    if handshake_type != 0x01:  # only ClientHello carries SNI
        return
    sni = _extract_sni(payload)
    if sni:
        f["tls.handshake.extensions_server_name"] = sni


def _apply_ftp(f: dict, payload: bytes) -> None:
    text = payload[:2048].decode("latin-1", "replace")
    line = text.split("\r\n", 1)[0].strip()
    if not line:
        return
    if line[:3].isdigit() and (len(line) == 3 or line[3] in " -"):
        f["ftp.response.code"] = int(line[:3])
        f["ftp.response.arg"] = line[4:].strip() if len(line) > 4 else ""
        return
    parts = line.split(None, 1)
    cmd = parts[0].upper()
    if cmd in _FTP_COMMANDS:
        f["ftp.request.command"] = cmd
        f["ftp.request.arg"] = parts[1] if len(parts) > 1 else ""


def _apply_dns(f: dict, pkt) -> None:
    from scapy.all import DNS
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    f["dns.flags.response"] = int(bool(dns.qr))
    if dns.qd is not None:
        try:
            f["dns.qry.name"] = dns.qd.qname.decode("utf-8", "replace").rstrip(".")
            f["dns.qry.name.len"] = len(f["dns.qry.name"])
            qtype = int(dns.qd.qtype)
            f["dns.qry.type"] = qtype
            f["dns.qry.type.name"] = _DNS_QTYPES.get(qtype, str(qtype))
        except Exception:
            pass
    f["dns.rcode"] = int(getattr(dns, "rcode", 0) or 0)
    ancount = int(getattr(dns, "ancount", 0) or 0)
    if ancount and dns.an is not None:
        answers = []
        rr = dns.an
        for _ in range(ancount):
            if rr is None:
                break
            rdata = getattr(rr, "rdata", None)
            if isinstance(rdata, (list, tuple)):
                rdata = b"".join(x if isinstance(x, bytes) else str(x).encode() for x in rdata)
            val = rdata.decode("utf-8", "replace") if isinstance(rdata, bytes) else str(rdata)
            answers.append(val)
            rr = rr.payload if hasattr(rr, "payload") and rr.payload else None
        if answers:
            f["dns.a"] = answers[0]
            f["dns.resp.ttl"] = int(getattr(dns.an, "ttl", 0) or 0)
            f["dns.resp_all"] = answers


def _apply_dhcp(f: dict, pkt) -> None:
    from scapy.layers.dhcp import BOOTP, DHCP
    if not pkt.haslayer(BOOTP):
        return
    bootp = pkt[BOOTP]
    try:
        f["dhcp.hw.mac_addr"] = bootp.chaddr[:6].hex(":") if isinstance(bootp.chaddr, bytes) else None
    except Exception:
        pass
    if str(getattr(bootp, "yiaddr", "0.0.0.0")) not in (None, "0.0.0.0"):
        f["dhcp.yiaddr"] = str(bootp.yiaddr)
    if not pkt.haslayer(DHCP):
        return
    opt_map = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) >= 1:
            opt_map[opt[0]] = opt[1] if len(opt) > 1 else None

    def text(v) -> str:
        return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)

    if "message-type" in opt_map:
        f["dhcp.option.dhcp"] = int(opt_map["message-type"])
    if opt_map.get("hostname") is not None:
        f["dhcp.option.hostname"] = text(opt_map["hostname"])
    if "requested_addr" in opt_map:
        f["dhcp.option.requested_ip_address"] = str(opt_map["requested_addr"])
    if opt_map.get("domain") is not None:
        f["dhcp.option.domain_name"] = text(opt_map["domain"])
    if "lease_time" in opt_map:
        f["dhcp.option.ip_address_lease_time"] = int(opt_map["lease_time"])
    if opt_map.get("message") is not None:
        f["dhcp.option.message"] = text(opt_map["message"])
    if "client_id" in opt_map:
        f["dhcp.option.client_id"] = str(opt_map["client_id"])


def _apply_nbns(f: dict, pkt) -> None:
    try:
        from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
    except Exception:
        return
    layer = None
    if pkt.haslayer(NBNSQueryRequest):
        layer = pkt[NBNSQueryRequest]
    elif pkt.haslayer(NBNSQueryResponse):
        layer = pkt[NBNSQueryResponse]
    if layer is None:
        return
    name = getattr(layer, "QUESTION_NAME", None)
    if name:
        try:
            decoded = name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)
            f["nbns.name"] = decoded.strip().rstrip("\x00")
        except Exception:
            pass


def _apply_kerberos(f: dict, pkt, payload: bytes) -> None:
    """Best-effort Kerberos field extraction (scapy backend). The native
    backend parses RFC 4120 structures directly; see soccore.pcap."""
    if 88 not in (f.get("udp.srcport"), f.get("udp.dstport")):
        return
    f["kerberos"] = True

    try:
        import scapy.layers.kerberos as krb
        pkt_krb = krb.KRB_AS_REQ(payload)
        body = pkt_krb.reqBody
        f["kerberos.pvno"] = int(pkt_krb.pvno)
        f["kerberos.realm"] = _s(body.realm)
        f["kerberos.CNameString"] = "/".join(_s(x) for x in body.cname.nameString)
        f["kerberos.SNameString"] = "/".join(_s(x) for x in body.sname.nameString)
        return
    except Exception:
        pass

    strings = _ber_general_strings(payload)
    if strings:
        f["kerberos.strings"] = strings
        realms = [s for s in strings if "." in s]
        if realms:
            f["kerberos.realm"] = max(realms, key=len)
        names = [s for s in strings if "." not in s]
        if names:
            f["kerberos.CNameString"] = "/".join(n for n in names if not n.endswith("$"))
            hostnames = [n for n in names if n.endswith("$")]
            if hostnames:
                f["kerberos.hostname"] = hostnames[0]


def _s(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
