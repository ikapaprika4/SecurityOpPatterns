"""
Dependency-free pcap / pcapng reader and packet dissector.

Every frame becomes a flat dict keyed by Wireshark display-filter field names
(`ip.src`, `tcp.flags.syn`, `dns.qry.name`, ...) -- exactly the shape trafkit's
filter engine and detectors read -- plus a few promoted attributes and a one
line summary in the spirit of Wireshark's Info column.

This is the default packet backend for trafkit and nsmkit. It needs no install
step, reads IPv6 (the scapy backend only ever looked at IPv4), and bounds every
payload by the IP/UDP length fields so Ethernet padding is never mistaken for
data. scapy remains available as an opt-in backend in trafkit.

Supported containers : pcap (usec + nsec, both byte orders, Kuznetzov variant),
                       pcapng (SHB/IDB/EPB/SPB/PB, if_tsresol, if_tsoffset),
                       either of them gzip-compressed.
Supported link types : Ethernet (+802.1Q/QinQ), Linux SLL/SLL2, BSD NULL/LOOP,
                       raw IPv4/IPv6.
Dissectors           : ARP, IPv4, IPv6 (+ext headers), ICMP (+quoted packet),
                       ICMPv6, TCP, UDP, DNS/mDNS/LLMNR, DHCP, NBNS, Kerberos
                       (UDP + TCP), HTTP/1.x, FTP control, TLS ClientHello SNI.

Everything is defensive: a truncated or malformed frame keeps whatever parsed
before the damage and is never allowed to raise out of `iter_packets`; a
damaged file yields the frames before the damage, and the optional `status`
dict says what stopped the read, so a half-read capture is never mistaken
for a complete one.
"""

from __future__ import annotations

import gzip
import socket
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator, Optional

__all__ = ["Packet", "PcapError", "iter_frames", "iter_packets", "read_packets",
           "dissect", "sniff_capture", "extract_sni", "ber_general_strings"]


class PcapError(ValueError):
    """The file is not a capture this module can read."""


# --------------------------------------------------------------------------
# Container formats
# --------------------------------------------------------------------------

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, 16),      # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, 16),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, 16),  # nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, 16),
    b"\x34\xcd\xb2\xa1": ("<", 1_000_000, 24),      # Kuznetzov "modified" pcap
    b"\xa1\xb2\xcd\x34": (">", 1_000_000, 24),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_MAX_FRAME = 256 * 1024 * 1024        # anything larger is a corrupt length field


def sniff_capture(head: bytes) -> Optional[str]:
    """'pcap' | 'pcapng' | 'pcap.gz' | None, from the first bytes of a file."""
    if head[:2] == b"\x1f\x8b":
        return "pcap.gz"
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    if head[:4] == _PCAPNG_SHB:
        return "pcapng"
    return None


def _open(path: str) -> BinaryIO:
    fh = open(path, "rb")
    if fh.read(2) == b"\x1f\x8b":
        fh.close()
        return gzip.open(path, "rb")   # type: ignore[return-value]
    fh.seek(0)
    return fh


def iter_frames(path: str, status: Optional[dict] = None) -> Iterator[tuple[float, int, bytes, int]]:
    """Yield `(timestamp, linktype, frame_bytes, original_length)` per frame.

    Raises PcapError only if the file is not a capture at all; a capture that
    is truncated or damaged mid-way ends early instead. Pass a dict as
    `status` to learn which: once the file has been read to its end it holds
    `frames` (how many were yielded) and `problem` -- None for a clean end of
    file, else why reading stopped early.
    """
    frames, problem = 0, None
    with _open(path) as fh:
        head = fh.read(4)
        if head in _PCAP_MAGICS:
            inner = _iter_pcap(fh, head)
        elif head == _PCAPNG_SHB:
            inner = _iter_pcapng(fh, head)
        else:
            raise PcapError(f"{path}: not a pcap/pcapng capture (magic {head.hex() or 'empty'})")
        try:
            while True:
                try:
                    frame = next(inner)
                except StopIteration as stop:
                    problem = stop.value
                    break
                frames += 1
                yield frame
        except (EOFError, OSError, zlib.error) as exc:       # damaged .gz stream
            problem = f"the compressed stream is damaged ({exc})"
    if status is not None:
        status.update(frames=frames, problem=problem)


def _iter_pcap(fh: BinaryIO, magic: bytes):
    """Frames of a classic pcap; returns None at a clean end of file, else a
    description of the damage that stopped the read."""
    endian, divisor, rec_len = _PCAP_MAGICS[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        return "the file header is incomplete"
    linktype = struct.unpack(endian + "I", rest[16:20])[0] & 0xFFFF
    rec = struct.Struct(endian + "IIII")          # Kuznetzov records carry 8 more bytes we skip
    while True:
        at = fh.tell()
        hdr = fh.read(rec_len)
        if not hdr:
            return None
        if len(hdr) < rec_len:
            return f"the file ends inside a record header (byte {at:,})"
        sec, frac, incl, orig = rec.unpack_from(hdr, 0)
        if incl > _MAX_FRAME:
            return f"corrupt record length {incl:,} at byte {at:,}"
        data = fh.read(incl)
        if data:
            yield sec + frac / divisor, linktype, data, orig
        if len(data) < incl:                       # truncated mid-record: stop cleanly
            return "the last frame is cut short -- the capture was truncated"


def _pcapng_options(body: bytes, start: int, endian: str):
    p, n = start, len(body)
    opt = struct.Struct(endian + "HH")
    while p + 4 <= n:
        code, length = opt.unpack_from(body, p)
        p += 4
        if code == 0:
            return
        yield code, body[p:p + length]
        p += (length + 3) & ~3


def _iter_pcapng(fh: BinaryIO, first: bytes):
    """Frames of a pcapng; returns None at a clean end of file, else a
    description of the damage that stopped the read."""
    endian = "<"
    interfaces: list[tuple[int, int, float]] = []   # (linktype, ts divisor, ts offset)
    pending = first
    while True:
        at = fh.tell() - len(pending)
        hdr = pending + fh.read(8 - len(pending))
        pending = b""
        if not hdr:
            return None
        if len(hdr) < 8:
            return f"the file ends inside a block header (byte {at:,})"
        if hdr[:4] == _PCAPNG_SHB:
            bom = fh.read(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                return f"corrupt section header at byte {at:,} (bad byte-order magic)"
            total = struct.unpack(endian + "I", hdr[4:8])[0]
            if total < 28 or total > _MAX_FRAME:
                return f"corrupt section header length {total:,} at byte {at:,}"
            fh.read(total - 12)
            interfaces = []                      # a new section resets interfaces
            continue
        btype, total = struct.unpack(endian + "II", hdr)
        if total < 12 or total > _MAX_FRAME:
            return f"corrupt block length {total:,} at byte {at:,}"
        body = fh.read(total - 8)
        if len(body) < total - 8:
            return "the last block is cut short -- the capture was truncated"
        body = body[:-4]
        if btype == 1 and len(body) >= 8:                          # Interface Description
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            divisor, offset = 1_000_000, 0.0
            for code, val in _pcapng_options(body, 8, endian):
                if code == 9 and val:                               # if_tsresol
                    b = val[0]
                    divisor = 2 ** (b & 0x7F) if b & 0x80 else 10 ** b
                elif code == 14 and len(val) >= 8:                  # if_tsoffset
                    offset = float(struct.unpack(endian + "q", val[:8])[0])
            interfaces.append((linktype, divisor, offset))
        elif btype == 6 and len(body) >= 20:                        # Enhanced Packet
            iface, hi, lo, cap, orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface < len(interfaces):
                linktype, divisor, offset = interfaces[iface]
                yield ((hi << 32) | lo) / divisor + offset, linktype, body[20:20 + cap], orig
        elif btype == 3 and len(body) >= 4 and interfaces:          # Simple Packet
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            linktype = interfaces[0][0]
            yield 0.0, linktype, body[4:4 + orig], orig
        elif btype == 2 and len(body) >= 20:                        # obsolete Packet Block
            iface, _drops, hi, lo, cap, orig = struct.unpack_from(endian + "HHIIII", body, 0)
            if iface < len(interfaces):
                linktype, divisor, offset = interfaces[iface]
                yield ((hi << 32) | lo) / divisor + offset, linktype, body[20:20 + cap], orig
        # anything else (name resolution, statistics, custom, ...) is skipped


# --------------------------------------------------------------------------
# Packet
# --------------------------------------------------------------------------

@dataclass(slots=True)
class Packet:
    frame_number: int
    ts: float
    length: int
    fields: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    proto: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None


def iter_packets(path: str, max_packets: Optional[int] = None, factory=Packet,
                 status: Optional[dict] = None) -> Iterator[Any]:
    """Dissect every frame of `path`. `factory` builds the record (anything
    accepting Packet's keyword fields -- trafkit passes its PacketRecord).
    `status`: see iter_frames; also gets `limited=True` if max_packets cut
    the read short."""
    for n, (ts, linktype, data, orig) in enumerate(iter_frames(path, status), start=1):
        if max_packets is not None and n > max_packets:
            if status is not None:
                status.update(frames=max_packets, limited=True)
            return
        yield dissect(data, linktype, n, ts, orig, factory)


def read_packets(path: str, max_packets: Optional[int] = None, factory=Packet,
                 status: Optional[dict] = None) -> list[Any]:
    return list(iter_packets(path, max_packets, factory, status))


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_u16 = struct.Struct("!H").unpack_from
_u32 = struct.Struct("!I").unpack_from
_ETH = struct.Struct("!6s6sH")
_IP4 = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIHH")
_UDP = struct.Struct("!HHHH")
_DNSH = struct.Struct("!HHHHHH")


def _mac(b: bytes) -> str:
    return b.hex(":")


_ip4 = socket.inet_ntoa


def _ip6(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


# scapy's str() of the 3-bit IPv4 flags field, kept identical so existing
# filters ("ip.flags == DF") keep working.
_IP_FLAGS = ("", "MF", "DF", "MF+DF", "evil", "MF+evil", "DF+evil", "MF+DF+evil")

_TCP_FLAG_NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                   (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))

DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 39: "DNAME",
              41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB",
              65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA"}

_ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench",
               5: "Redirect", 8: "Echo (ping) request", 11: "Time-to-live exceeded",
               12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply"}
_ICMP_UNREACH = {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable",
                 3: "Port unreachable", 4: "Fragmentation needed", 9: "Network prohibited",
                 10: "Host prohibited", 13: "Communication administratively filtered"}
# Only error messages quote the offending packet (same set scapy dissects).
_ICMP_ERRORS = {3, 4, 5, 11, 12}

HTTP_METHODS = ("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE")
_HTTP_METHODS_B = tuple(m.encode() + b" " for m in HTTP_METHODS)
HTTP_PORTS = frozenset({80, 8080, 8000, 8888})

FTP_COMMANDS = frozenset({"USER", "PASS", "STOR", "RETR", "LIST", "CWD", "PASV", "PORT",
                          "QUIT", "TYPE", "MKD", "DELE", "SIZE", "EPSV", "NLST", "APPE",
                          "SYST", "FEAT", "OPTS", "AUTH", "RNFR", "RNTO", "RMD", "PWD",
                          "XPWD", "EPRT", "REST", "ACCT", "MDTM", "STAT", "HELP", "NOOP"})

_DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK",
               7: "Release", 8: "Inform"}
_KRB_MSG = {10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP", 30: "KRB-ERROR"}


# --------------------------------------------------------------------------
# Dissection
# --------------------------------------------------------------------------

def dissect(data: bytes, linktype: int, frame_number: int = 0, ts: float = 0.0,
            orig_len: Optional[int] = None, factory=Packet) -> Any:
    """Dissect one frame. Never raises: damage yields a partial record."""
    length = orig_len if orig_len else len(data)
    f: dict[str, Any] = {"frame.number": frame_number, "frame.time_epoch": ts,
                         "frame.len": length, "frame.cap_len": len(data)}
    pkt = factory(frame_number=frame_number, ts=ts, length=length, fields=f)
    try:
        _dissect_link(data, linktype, pkt)
    except Exception as exc:  # noqa: BLE001 -- one bad frame must not stop the read
        pkt.summary = f"[malformed: {type(exc).__name__}] {pkt.summary}".strip()
    if not pkt.summary:
        pkt.summary = f"{len(data)} bytes, link type {linktype}"
    return pkt


def _dissect_link(data: bytes, linktype: int, pkt: Packet) -> None:
    f = pkt.fields
    n = len(data)
    if linktype == 1:                                     # Ethernet
        if n < 14:
            pkt.summary = "Truncated Ethernet frame"
            return
        dst, src, etype = _ETH.unpack_from(data, 0)
        pkt.src_mac = f["eth.src"] = _mac(src)
        pkt.dst_mac = f["eth.dst"] = _mac(dst)
        off = 14
        while etype in (0x8100, 0x88A8, 0x9100) and n >= off + 4:
            tci, etype = struct.unpack_from("!HH", data, off)
            f.setdefault("vlan.id", tci & 0x0FFF)
            off += 4
        f["eth.type"] = etype
        if etype < 0x0600:
            pkt.summary = "IEEE 802.3 / LLC frame"
            return
    elif linktype == 113:                                 # Linux cooked capture v1
        if n < 16:
            return
        _ptype, _hatype, alen = struct.unpack_from("!HHH", data, 0)
        if alen == 6:
            pkt.src_mac = f["sll.src.eth"] = _mac(data[6:12])
        etype, off = _u16(data, 14)[0], 16
    elif linktype == 276:                                 # Linux cooked capture v2
        if n < 20:
            return
        etype = _u16(data, 0)[0]
        if data[11] == 6:
            pkt.src_mac = f["sll.src.eth"] = _mac(data[12:18])
        off = 20
    elif linktype in (0, 108):                            # BSD loopback / OpenBSD loop
        if n < 4:
            return
        fam = struct.unpack_from(">I" if linktype == 108 else "<I", data, 0)[0]
        if linktype == 0 and fam > 0xFFFF:
            fam = struct.unpack_from(">I", data, 0)[0]
        etype = 0x0800 if fam == 2 else (0x86DD if fam in (10, 23, 24, 28, 30) else 0)
        off = 4
    elif linktype in (101, 12, 14, 228, 229):             # raw IP
        if not n:
            return
        etype = 0x0800 if data[0] >> 4 == 4 else (0x86DD if data[0] >> 4 == 6 else 0)
        off = 0
    else:
        pkt.summary = f"Unsupported link-layer type {linktype}"
        return

    if etype == 0x0800:
        _ipv4(data, off, pkt)
    elif etype == 0x86DD:
        _ipv6(data, off, pkt)
    elif etype == 0x0806:
        _arp(data, off, pkt)
    else:
        pkt.summary = f"EtherType 0x{etype:04x}"


def _arp(data: bytes, off: int, pkt: Packet) -> None:
    f = pkt.fields
    if len(data) < off + 8:
        return
    _htype, _ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, off)
    pkt.proto = "arp"
    f["arp.opcode"] = op
    if hlen != 6 or plen != 4 or len(data) < off + 28:
        pkt.summary = f"ARP opcode {op}"
        return
    sha, spa = data[off + 8:off + 14], data[off + 14:off + 18]
    tha, tpa = data[off + 18:off + 24], data[off + 24:off + 28]
    f["arp.src.hw_mac"] = _mac(sha)
    f["arp.src.proto_ipv4"] = pkt.src_ip = _ip4(spa)
    f["arp.dst.hw_mac"] = _mac(tha)
    f["arp.dst.proto_ipv4"] = pkt.dst_ip = _ip4(tpa)
    f["arp.duplicate-address-detected"] = op == 2 and spa == tpa
    f["arp.isgratuitous"] = spa == tpa
    if op == 1:
        pkt.summary = f"ARP Who has {f['arp.dst.proto_ipv4']}? Tell {f['arp.src.proto_ipv4']}"
    elif op == 2:
        pkt.summary = f"ARP {f['arp.src.proto_ipv4']} is at {f['arp.src.hw_mac']}"
    else:
        pkt.summary = f"ARP opcode {op}"


def _ipv4(data: bytes, off: int, pkt: Packet) -> None:
    f = pkt.fields
    if len(data) < off + 20:
        pkt.summary = "Truncated IPv4 header"
        return
    vihl, _tos, tot_len, ident, flags_frag, ttl, proto, _csum, src, dst = _IP4.unpack_from(data, off)
    ihl = (vihl & 0x0F) * 4
    f["ip.version"] = vihl >> 4
    f["ip.src"] = pkt.src_ip = _ip4(src)
    f["ip.dst"] = pkt.dst_ip = _ip4(dst)
    f["ip.ttl"] = ttl
    f["ip.proto"] = proto
    flags, frag = flags_frag >> 13, flags_frag & 0x1FFF
    f["ip.flags"] = _IP_FLAGS[flags & 7]
    f["ip.flags.df"] = (flags >> 1) & 1
    f["ip.flags.mf"] = flags & 1
    f["ip.frag"] = frag
    f["ip.len"] = tot_len
    f["ip.id"] = ident
    if ihl < 20:
        pkt.proto = "ip"
        pkt.summary = "IPv4 header length invalid"
        return
    # Bound the payload by the IP total length: anything past it is link
    # padding (a 60-byte minimum Ethernet frame), not transport data.
    end = off + tot_len if ihl <= tot_len and off + tot_len <= len(data) else len(data)
    if frag:
        pkt.proto = "ip"
        pkt.summary = f"IPv4 fragment (offset {frag * 8}, proto {proto})"
        return
    _transport(proto, data, off + ihl, end, pkt, v6=False)


_V6_EXT = frozenset({0, 43, 60})


def _ipv6(data: bytes, off: int, pkt: Packet) -> None:
    f = pkt.fields
    if len(data) < off + 40:
        pkt.summary = "Truncated IPv6 header"
        return
    plen, nxt, hlim = struct.unpack_from("!HBB", data, off + 4)
    f["ipv6.src"] = pkt.src_ip = _ip6(data[off + 8:off + 24])
    f["ipv6.dst"] = pkt.dst_ip = _ip6(data[off + 24:off + 40])
    f["ipv6.plen"] = plen
    f["ipv6.nxt"] = nxt
    f["ipv6.hlim"] = hlim
    p = off + 40
    end = p + plen if plen and p + plen <= len(data) else len(data)
    for _ in range(8):                                   # extension-header chain
        if nxt in _V6_EXT and p + 2 <= end:
            nxt, p = data[p], p + (data[p + 1] + 1) * 8
        elif nxt == 44 and p + 8 <= end:                 # fragment header
            frag_off = _u16(data, p + 2)[0] >> 3
            nxt, p = data[p], p + 8
            if frag_off:
                pkt.proto = "ipv6"
                pkt.summary = f"IPv6 fragment (offset {frag_off * 8})"
                return
        elif nxt == 51 and p + 2 <= end:                 # AH
            nxt, p = data[p], p + (data[p + 1] + 2) * 4
        else:
            break
    _transport(nxt, data, p, end, pkt, v6=True)


def _transport(proto: int, data: bytes, off: int, end: int, pkt: Packet, v6: bool) -> None:
    if proto == 6:
        _tcp(data, off, end, pkt)
    elif proto == 17:
        _udp(data, off, end, pkt)
    elif proto == 1 and not v6:
        _icmp(data, off, end, pkt)
    elif proto == 58 and v6:
        _icmpv6(data, off, end, pkt)
    else:
        pkt.proto = "ipv6" if v6 else "ip"
        pkt.summary = f"{'IPv6' if v6 else 'IPv4'} protocol {proto}"


def _icmp(data: bytes, off: int, end: int, pkt: Packet) -> None:
    f = pkt.fields
    pkt.proto = "icmp"
    if end - off < 4:
        pkt.summary = "Truncated ICMP"
        return
    itype, code = data[off], data[off + 1]
    f["icmp.type"] = itype
    f["icmp.code"] = code
    f["data.len"] = max(0, end - off - 8)
    desc = _ICMP_TYPES.get(itype, f"ICMP type {itype}")
    if itype in (0, 8) and end - off >= 8:
        ident, seq = struct.unpack_from("!HH", data, off + 4)
        f["icmp.ident"] = ident
        f["icmp.seq"] = seq
        # First 512 payload bytes: enough for an entropy check on a possible
        # tunnel, small enough not to matter on a large capture.
        f["data.data"] = data[off + 8:min(end, off + 8 + 512)]
        desc += f" id=0x{ident:04x}, seq={seq}, {end - off - 8} bytes"
    elif itype == 3:
        desc += f" ({_ICMP_UNREACH.get(code, f'code {code}')})"
    pkt.summary = desc
    if itype in _ICMP_ERRORS:
        _icmp_quoted(data, off + 8, end, f)


def _icmp_quoted(data: bytes, off: int, end: int, f: dict) -> None:
    """The offending packet an ICMP error quotes -- how a UDP scan's closed
    ports get attributed back to the probe that caused them."""
    if end - off < 20 or data[off] >> 4 != 4:
        return
    ihl = (data[off] & 0x0F) * 4
    proto = data[off + 9]
    f["icmp.orig.ip.src"] = _ip4(data[off + 12:off + 16])
    f["icmp.orig.ip.dst"] = _ip4(data[off + 16:off + 20])
    l4 = off + ihl
    if end - l4 >= 4:
        sport, dport = struct.unpack_from("!HH", data, l4)
        if proto == 17:
            f["icmp.orig.udp.srcport"], f["icmp.orig.udp.dstport"] = sport, dport
        elif proto == 6:
            f["icmp.orig.tcp.srcport"], f["icmp.orig.tcp.dstport"] = sport, dport


def _icmpv6(data: bytes, off: int, end: int, pkt: Packet) -> None:
    f = pkt.fields
    pkt.proto = "icmpv6"
    if end - off < 4:
        return
    itype, code = data[off], data[off + 1]
    f["icmpv6.type"] = itype
    f["icmpv6.code"] = code
    f["data.len"] = max(0, end - off - 8)
    names = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
             128: "Echo (ping) request", 129: "Echo (ping) reply", 133: "Router solicitation",
             134: "Router advertisement", 135: "Neighbor solicitation", 136: "Neighbor advertisement"}
    pkt.summary = "ICMPv6 " + names.get(itype, f"type {itype}")


def _tcp(data: bytes, off: int, end: int, pkt: Packet) -> None:
    f = pkt.fields
    pkt.proto = "tcp"
    if end - off < 4:
        pkt.summary = "Truncated TCP header"
        return
    if end - off < 20:
        pkt.src_port, pkt.dst_port = struct.unpack_from("!HH", data, off)
        f["tcp.srcport"], f["tcp.dstport"] = pkt.src_port, pkt.dst_port
        pkt.summary = "Truncated TCP header"
        return
    sport, dport, seq, ack, offflags, win = _TCP.unpack_from(data, off)
    pkt.src_port, pkt.dst_port = sport, dport
    flags = offflags & 0x1FF
    doff = (offflags >> 12) * 4
    f["tcp.srcport"] = sport
    f["tcp.dstport"] = dport
    f["tcp.flags"] = flags
    f["tcp.flags.fin"] = flags & 1
    f["tcp.flags.syn"] = (flags >> 1) & 1
    f["tcp.flags.reset"] = (flags >> 2) & 1
    f["tcp.flags.push"] = (flags >> 3) & 1
    f["tcp.flags.ack"] = (flags >> 4) & 1
    f["tcp.flags.urg"] = (flags >> 5) & 1
    f["tcp.flags.ecn"] = (flags >> 6) & 1
    f["tcp.flags.cwr"] = (flags >> 7) & 1
    f["tcp.window_size"] = win
    f["tcp.seq"] = seq
    f["tcp.ack"] = ack
    f["tcp.port"] = sport          # direction-blind aliases are resolved by the filter engine
    f["tcp.hdr_len"] = doff
    payload = data[off + doff:end] if 20 <= doff <= end - off else b""
    f["data.len"] = f["tcp.len"] = len(payload)
    flag_txt = ", ".join(name for bit, name in _TCP_FLAG_NAMES if flags & bit)
    pkt.summary = f"TCP {sport} → {dport} [{flag_txt}] Len={len(payload)}"
    if payload:
        _application(payload, pkt)
        if 88 in (sport, dport) and len(payload) > 4:
            _kerberos(payload[4:], pkt)                 # TCP Kerberos: 4-byte record mark


def _udp(data: bytes, off: int, end: int, pkt: Packet) -> None:
    f = pkt.fields
    pkt.proto = "udp"
    if end - off < 8:
        pkt.summary = "Truncated UDP header"
        return
    sport, dport, ulen, _csum = _UDP.unpack_from(data, off)
    pkt.src_port, pkt.dst_port = sport, dport
    f["udp.srcport"] = sport
    f["udp.dstport"] = dport
    f["udp.port"] = sport
    f["udp.length"] = ulen
    pend = off + ulen if 8 <= ulen <= end - off else end
    payload = data[off + 8:pend]
    f["data.len"] = len(payload)
    pkt.summary = f"UDP {sport} → {dport} Len={len(payload)}"
    if not payload:
        return
    _application(payload, pkt)
    ports = (sport, dport)
    if 53 in ports or 5353 in ports or 5355 in ports:
        _dns(payload, pkt)
    if sport in (67, 68) and dport in (67, 68):
        _dhcp(payload, pkt)
    if 137 in ports:
        _nbns(payload, pkt)
    if 88 in ports:
        _kerberos(payload, pkt)


# --------------------------------------------------------------------------
# Application layer
# --------------------------------------------------------------------------

def _application(payload: bytes, pkt: Packet) -> None:
    ports = {pkt.src_port, pkt.dst_port}
    if ports & HTTP_PORTS:
        _http(payload, pkt)
    if 21 in ports:
        _ftp(payload, pkt)
    # Deliberately not port-gated: TLS on an unexpected port is exactly what
    # trafkit's TLS-PORT-01 exists to find.
    _tls(payload, pkt)


def _http(payload: bytes, pkt: Packet) -> None:
    head = payload[:16]
    is_request = head.startswith(_HTTP_METHODS_B)
    if not is_request and not head.startswith(b"HTTP/"):
        return
    f = pkt.fields
    cut = payload.find(b"\r\n\r\n")
    block = payload[:cut] if cut >= 0 else payload[:8192]
    body = payload[cut + 4:] if cut >= 0 else b""
    lines = block.split(b"\r\n")
    start = lines[0].decode("latin-1", "replace")
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        name, sep, value = ln.partition(b":")
        if sep:
            key = name.strip().lower().decode("latin-1", "replace")
            headers.setdefault(key, value.strip().decode("utf-8", "replace"))
    if is_request:
        parts = start.split(" ")
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else ""
        host = headers.get("host")
        f["http.request"] = True
        f["http.request.method"] = method
        f["http.request.uri"] = uri
        f["http.request.full_uri"] = (f"http://{host}{uri}" if host and uri.startswith("/") else uri)
        if len(parts) > 2:
            f["http.request.version"] = parts[2]
        for hname, fname in (("host", "http.host"), ("user-agent", "http.user_agent"),
                             ("authorization", "http.authorization"), ("cookie", "http.cookie"),
                             ("referer", "http.referer"), ("content-type", "http.content_type"),
                             ("content-length", "http.content_length_header"),
                             ("x-forwarded-for", "http.x_forwarded_for")):
            if hname in headers:
                f[fname] = headers[hname]
        if body:
            f["http.file_data"] = body[:4096].decode("latin-1", "replace")
        pkt.summary = f"HTTP {start[:200]}"
    else:
        parts = start.split(" ", 2)
        code = parts[1] if len(parts) > 1 else ""
        f["http.response"] = True
        f["http.response.code"] = int(code) if code.isdigit() else code
        if len(parts) > 2:
            f["http.response.phrase"] = parts[2]
        for hname, fname in (("server", "http.server"), ("content-type", "http.content_type"),
                             ("content-disposition", "http.content_disposition"),
                             ("location", "http.location"), ("set-cookie", "http.set_cookie"),
                             ("content-length", "http.content_length_header")):
            if hname in headers:
                f[fname] = headers[hname]
        pkt.summary = f"HTTP {start[:200]}"


def _ftp(payload: bytes, pkt: Packet) -> None:
    f = pkt.fields
    line = payload[:2048].decode("latin-1", "replace").split("\r\n", 1)[0].strip()
    if not line:
        return
    if line[:3].isdigit() and (len(line) == 3 or line[3] in " -"):
        f["ftp.response.code"] = int(line[:3])
        f["ftp.response.arg"] = line[4:].strip() if len(line) > 4 else ""
        pkt.summary = f"FTP Response: {line[:200]}"
        return
    parts = line.split(None, 1)
    cmd = parts[0].upper()
    if cmd in FTP_COMMANDS:
        f["ftp.request.command"] = cmd
        f["ftp.request.arg"] = parts[1] if len(parts) > 1 else ""
        shown = "PASS ********" if cmd == "PASS" else line
        pkt.summary = f"FTP Request: {shown[:200]}"


def _tls(payload: bytes, pkt: Packet) -> None:
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return
    f = pkt.fields
    htype = payload[5]
    f["tls.record.content_type"] = payload[0]
    f["tls.record.version"] = _u16(payload, 1)[0]
    f["tls.handshake.type"] = htype
    if htype == 1:
        sni = extract_sni(payload)
        if sni:
            f["tls.handshake.extensions_server_name"] = sni
        pkt.summary = "TLS Client Hello" + (f" (SNI={sni})" if sni else "")
    elif htype == 2:
        pkt.summary = "TLS Server Hello"
    else:
        pkt.summary = f"TLS Handshake type {htype}"


def _valid_hostname(s: str) -> bool:
    return (2 < len(s) < 254 and "." in s
            and all(c.isalnum() or c in ".-_" for c in s)
            and not s.startswith(".") and not s.endswith("."))


def extract_sni(payload: bytes) -> Optional[str]:
    """ClientHello server_name, walking record -> handshake -> extensions and
    falling back to a pattern scan so a segment split mid-record still yields
    the hostname."""
    try:
        if len(payload) >= 45 and payload[0] == 0x16 and payload[5] == 0x01:
            p = 5 + 4 + 2 + 32
            p += 1 + payload[p]                                   # session id
            p += 2 + int.from_bytes(payload[p:p + 2], "big")      # cipher suites
            p += 1 + payload[p]                                   # compression
            if p + 2 <= len(payload):
                end = min(len(payload), p + 2 + int.from_bytes(payload[p:p + 2], "big"))
                p += 2
                while p + 4 <= end:
                    etype = int.from_bytes(payload[p:p + 2], "big")
                    elen = int.from_bytes(payload[p + 2:p + 4], "big")
                    body = payload[p + 4:p + 4 + elen]
                    if etype == 0 and len(body) >= 5:
                        nlen = int.from_bytes(body[3:5], "big")
                        name = body[5:5 + nlen].decode("ascii", "ignore")
                        if _valid_hostname(name):
                            return name.lower()
                    p += 4 + elen
    except IndexError:
        pass
    i = 0
    while True:
        i = payload.find(b"\x00\x00", i)
        if i == -1 or i + 9 > len(payload):
            return None
        if payload[i + 4:i + 5] == b"\x00":
            nlen = int.from_bytes(payload[i + 5:i + 7], "big")
            cand = payload[i + 7:i + 7 + nlen].decode("ascii", "ignore")
            if _valid_hostname(cand):
                return cand.lower()
        i += 1


# ---- DNS ------------------------------------------------------------------

def _dns_name(buf: bytes, p: int) -> tuple[Optional[str], int]:
    """Decode a (possibly compressed) name. Returns (name, offset after it)."""
    labels: list[bytes] = []
    after = None
    jumps = 0
    n = len(buf)
    while p < n:
        ln = buf[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0 == 0xC0:
            if p + 1 >= n or jumps > 20:
                return None, n
            target = ((ln & 0x3F) << 8) | buf[p + 1]
            if after is None:
                after = p + 2
            if target >= p:                      # pointers must point backwards
                return None, n
            p = target
            jumps += 1
            continue
        if ln & 0xC0:
            return None, n
        labels.append(buf[p + 1:p + 1 + ln])
        p += 1 + ln
    name = b".".join(labels).decode("utf-8", "replace")
    return name, (after if after is not None else p)


def _dns_rdata(buf: bytes, p: int, rtype: int, rdlen: int) -> str:
    rd = buf[p:p + rdlen]
    if rtype == 1 and rdlen == 4:
        return _ip4(rd)
    if rtype == 28 and rdlen == 16:
        return _ip6(rd)
    if rtype in (2, 5, 12, 39):
        return _dns_name(buf, p)[0] or ""
    if rtype == 15 and rdlen > 2:
        return _dns_name(buf, p + 2)[0] or ""
    if rtype == 33 and rdlen > 6:
        return _dns_name(buf, p + 6)[0] or ""
    if rtype == 6:
        return _dns_name(buf, p)[0] or ""
    if rtype == 16:
        out, q = [], 0
        while q < len(rd):
            seg = rd[q + 1:q + 1 + rd[q]]
            out.append(seg)
            q += 1 + rd[q]
        return b"".join(out).decode("utf-8", "replace")
    return rd.hex()


def _dns(payload: bytes, pkt: Packet) -> None:
    if len(payload) < 12:
        return
    f = pkt.fields
    tid, flags, qd, an, _ns, _ar = _DNSH.unpack_from(payload, 0)
    if flags & 0x7800:                   # opcode != QUERY (updates, notifies, ...)
        return
    qr = flags >> 15
    f["dns.id"] = tid
    f["dns.flags.response"] = qr
    f["dns.rcode"] = flags & 0xF
    f["dns.count.queries"] = qd
    f["dns.count.answers"] = an
    p = 12
    qname, qtype = None, None
    for i in range(qd):
        name, p = _dns_name(payload, p)
        if name is None or p + 4 > len(payload):
            return
        t = _u16(payload, p)[0]
        p += 4
        if i == 0:
            qname, qtype = name, t
            f["dns.qry.name"] = name
            f["dns.qry.name.len"] = len(name)
            f["dns.qry.type"] = t
            f["dns.qry.type.name"] = DNS_QTYPES.get(t, str(t))
    answers: list[str] = []
    a_records: list[str] = []
    first_ttl = None
    by_type: dict[int, str] = {}
    for _ in range(an):
        _name, p = _dns_name(payload, p)
        if _name is None or p + 10 > len(payload):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack_from("!HHIH", payload, p)
        p += 10
        if p + rdlen > len(payload):
            break
        value = _dns_rdata(payload, p, rtype, rdlen)
        p += rdlen
        answers.append(value)
        by_type.setdefault(rtype, value)
        if rtype == 1:
            a_records.append(value)
        if first_ttl is None:
            first_ttl = ttl
    if answers:
        # Wireshark semantics: dns.a is an A-record address, so a CNAME chain
        # (www -> edge -> 192.0.2.10) resolves to the address, not the alias.
        f["dns.answer"] = answers[0]
        f["dns.resp.ttl"] = first_ttl
        f["dns.resp_all"] = answers
        if a_records:
            f["dns.a"] = a_records[0]
            f["dns.a_all"] = a_records
        for rtype, key in ((28, "dns.aaaa"), (5, "dns.cname"), (16, "dns.txt")):
            if rtype in by_type:
                f[key] = by_type[rtype]
    tname = DNS_QTYPES.get(qtype, str(qtype)) if qtype is not None else ""
    if qr:
        rc = {0: "", 2: " server failure", 3: " No such name", 5: " refused"}.get(flags & 0xF, "")
        shown = " ".join(answers[:3])
        pkt.summary = f"DNS Standard query response 0x{tid:04x}{rc} {tname} {qname or ''}".rstrip() \
            + (f" → {shown}" if shown else "")
    else:
        pkt.summary = f"DNS Standard query 0x{tid:04x} {tname} {qname or ''}".rstrip()


# ---- DHCP -----------------------------------------------------------------

def _dhcp(payload: bytes, pkt: Packet) -> None:
    if len(payload) < 240:
        return
    f = pkt.fields
    chaddr = payload[28:34]
    f["dhcp.hw.mac_addr"] = _mac(chaddr)
    yiaddr = payload[16:20]
    if yiaddr != b"\x00\x00\x00\x00":
        f["dhcp.yiaddr"] = f["dhcp.ip.your"] = _ip4(yiaddr)
    ciaddr = payload[12:16]
    if ciaddr != b"\x00\x00\x00\x00":
        f["dhcp.ip.client"] = _ip4(ciaddr)
    if payload[236:240] != b"\x63\x82\x53\x63":
        pkt.summary = "BOOTP"
        return
    p, n = 240, len(payload)
    mtype = None
    while p < n:
        code = payload[p]
        if code == 255:
            break
        if code == 0:
            p += 1
            continue
        if p + 1 >= n:
            break
        ln = payload[p + 1]
        val = payload[p + 2:p + 2 + ln]
        p += 2 + ln

        def text(v: bytes = val) -> str:
            return v.rstrip(b"\x00").decode("utf-8", "replace")

        if code == 53 and val:
            mtype = f["dhcp.option.dhcp"] = val[0]
        elif code == 12:
            f["dhcp.option.hostname"] = text()
        elif code == 50 and len(val) == 4:
            f["dhcp.option.requested_ip_address"] = _ip4(val)
        elif code == 15:
            f["dhcp.option.domain_name"] = text()
        elif code == 51 and len(val) == 4:
            f["dhcp.option.ip_address_lease_time"] = _u32(val, 0)[0]
        elif code == 54 and len(val) == 4:
            f["dhcp.option.dhcp_server_id"] = _ip4(val)
        elif code == 56:
            f["dhcp.option.message"] = text()
        elif code == 60:
            f["dhcp.option.vendor_class_id"] = text()
        elif code == 61 and val:
            f["dhcp.option.client_id"] = (_mac(val[1:7]) if val[0] == 1 and len(val) == 7
                                          else val.hex(":"))
        elif code == 81 and len(val) > 3:
            f["dhcp.option.fqdn.name"] = text(val[3:])
    xid = _u32(payload, 4)[0]
    pkt.summary = f"DHCP {_DHCP_TYPES.get(mtype, 'message')} - Transaction ID 0x{xid:08x}"


# ---- NBNS -----------------------------------------------------------------

def _netbios_name(buf: bytes, p: int) -> Optional[tuple[str, int]]:
    """First-level NetBIOS decoding: 32 'A'-'P' characters -> 16 bytes, the
    last of which is the service suffix."""
    if p >= len(buf) or buf[p] != 32 or p + 33 > len(buf):
        return None
    enc = buf[p + 1:p + 33]
    try:
        raw = bytes(((enc[i] - 0x41) << 4) | (enc[i + 1] - 0x41) for i in range(0, 32, 2))
    except ValueError:
        return None
    name = raw[:15].decode("ascii", "replace").rstrip(" \x00")
    return name, raw[15]


def _nbns(payload: bytes, pkt: Packet) -> None:
    if len(payload) < 12:
        return
    f = pkt.fields
    tid, flags, qd, an, _ns, ar = _DNSH.unpack_from(payload, 0)
    opcode = (flags >> 11) & 0xF
    response = flags >> 15
    if not (qd or an):
        return
    decoded = _netbios_name(payload, 12)
    if not decoded:
        return
    name, suffix = decoded
    f["nbns.name"] = name
    f["nbns.suffix"] = suffix
    f["nbns.opcode"] = opcode
    f["nbns.flags.response"] = response
    # NB_ADDRESS of the first NB record: the answer of a positive query
    # response, or the additional record of a registration/refresh. That is
    # who owns the name -- a plain query only names who is being looked for.
    p = _dns_name(payload, 12)[1] + (4 if qd else 0)
    for _ in range(an + _ns + ar):
        rr_name, p = _dns_name(payload, p)
        if rr_name is None or p + 10 > len(payload):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", payload, p)
        p += 10
        if rtype == 0x20 and rdlen >= 6 and p + 6 <= len(payload):
            f["nbns.addr"] = _ip4(payload[p + 2:p + 6])
            break
        p += rdlen
    kind = {0: "Name query", 5: "Registration", 6: "Release", 7: "WACK", 8: "Refresh",
            15: "Multi-homed registration"}.get(opcode, f"opcode {opcode}")
    pkt.summary = f"NBNS {kind}{' response' if response else ''} {name}<{suffix:02x}>"


# ---- Kerberos -------------------------------------------------------------

def _ber(buf: bytes, p: int, end: int) -> Optional[tuple[int, int, int]]:
    """(tag, value_start, value_end) of the TLV at p, or None."""
    if p + 2 > end:
        return None
    tag, ln = buf[p], buf[p + 1]
    p += 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or nbytes > 4 or p + nbytes > end:
            return None
        ln = int.from_bytes(buf[p:p + nbytes], "big")
        p += nbytes
    if p + ln > end:
        return None
    return tag, p, p + ln


def _ber_children(buf: bytes, p: int, end: int) -> dict[int, tuple[int, int, int]]:
    out: dict[int, tuple[int, int, int]] = {}
    while p < end:
        tlv = _ber(buf, p, end)
        if tlv is None:
            break
        out.setdefault(tlv[0], tlv)
        p = tlv[2]
    return out


def _ber_int(buf: bytes, tlv) -> Optional[int]:
    inner = _ber(buf, tlv[1], tlv[2])
    if not inner or inner[0] != 0x02:
        return None
    return int.from_bytes(buf[inner[1]:inner[2]], "big", signed=True)


def _ber_str(buf: bytes, tlv) -> Optional[str]:
    inner = _ber(buf, tlv[1], tlv[2])
    if not inner or inner[0] not in (0x1B, 0x16, 0x13, 0x0C):
        return None
    return buf[inner[1]:inner[2]].decode("utf-8", "replace")


def _ber_principal(buf: bytes, tlv) -> Optional[str]:
    seq = _ber(buf, tlv[1], tlv[2])
    if not seq or seq[0] != 0x30:
        return None
    kids = _ber_children(buf, seq[1], seq[2])
    names = kids.get(0xA1)
    if not names:
        return None
    lst = _ber(buf, names[1], names[2])
    if not lst or lst[0] != 0x30:
        return None
    parts, p = [], lst[1]
    while p < lst[2]:
        s = _ber(buf, p, lst[2])
        if s is None:
            break
        if s[0] == 0x1B:
            parts.append(buf[s[1]:s[2]].decode("utf-8", "replace"))
        p = s[2]
    return "/".join(parts) if parts else None


def _kerberos_strict(payload: bytes) -> Optional[dict[str, Any]]:
    """RFC 4120 KDC-REQ / KDC-REP / KRB-ERROR, just the identity fields.
    Returns None unless the structure genuinely matches (pvno == 5)."""
    top = _ber(payload, 0, len(payload))
    if not top or top[0] not in (0x6A, 0x6B, 0x6C, 0x6D, 0x7E):
        return None
    app = top[0] & 0x1F
    seq = _ber(payload, top[1], top[2])
    if not seq or seq[0] != 0x30:
        return None
    k = _ber_children(payload, seq[1], seq[2])
    out: dict[str, Any] = {}
    if app in (10, 12):                                   # KDC-REQ
        if k.get(0xA1) is None or _ber_int(payload, k[0xA1]) != 5:
            return None
        body_tag = k.get(0xA4)
        if not body_tag:
            return None
        body = _ber(payload, body_tag[1], body_tag[2])
        if not body or body[0] != 0x30:
            return None
        b = _ber_children(payload, body[1], body[2])
        realm = _ber_str(payload, b[0xA2]) if 0xA2 in b else None
        if realm is None:
            return None
        out["kerberos.realm"] = realm
        if 0xA1 in b:
            out["kerberos.CNameString"] = _ber_principal(payload, b[0xA1]) or ""
        if 0xA3 in b:
            out["kerberos.SNameString"] = _ber_principal(payload, b[0xA3]) or ""
        if 0xA8 in b:
            lst = _ber(payload, b[0xA8][1], b[0xA8][2])
            etypes, p = [], (lst[1] if lst else 0)
            while lst and p < lst[2]:
                e = _ber(payload, p, lst[2])
                if e is None:
                    break
                if e[0] == 0x02:
                    etypes.append(int.from_bytes(payload[e[1]:e[2]], "big", signed=True))
                p = e[2]
            out["kerberos.etype"] = etypes
    elif app in (11, 13):                                 # KDC-REP
        if k.get(0xA0) is None or _ber_int(payload, k[0xA0]) != 5:
            return None
        if 0xA3 in k:
            out["kerberos.realm"] = _ber_str(payload, k[0xA3]) or ""
        if 0xA4 in k:
            out["kerberos.CNameString"] = _ber_principal(payload, k[0xA4]) or ""
    else:                                                 # KRB-ERROR
        if k.get(0xA0) is None or _ber_int(payload, k[0xA0]) != 5:
            return None
        if 0xA6 in k:
            out["kerberos.error_code"] = _ber_int(payload, k[0xA6])
        if 0xA9 in k:
            out["kerberos.realm"] = _ber_str(payload, k[0xA9]) or ""
        if 0xA8 in k:
            out["kerberos.CNameString"] = _ber_principal(payload, k[0xA8]) or ""
        if 0xAA in k:
            out["kerberos.SNameString"] = _ber_principal(payload, k[0xAA]) or ""
    out["kerberos.pvno"] = 5
    out["kerberos.msg_type"] = app
    return out


def ber_general_strings(payload: bytes) -> list[str]:
    """Every short ASN.1 GeneralString/PrintableString/IA5String primitive in
    `payload`, ignoring the surrounding structure -- recovers realm and
    principal names from a message too damaged for a strict parse."""
    out: list[str] = []
    i, n = 0, len(payload)
    while i < n - 1:
        if payload[i] in (0x1B, 0x13, 0x1A):
            ln = payload[i + 1]
            if ln < 0x80 and i + 2 + ln <= n:
                chunk = payload[i + 2:i + 2 + ln]
                if chunk and all(32 <= b < 127 for b in chunk):
                    out.append(chunk.decode("ascii", "ignore"))
                i += 2 + ln
                continue
        i += 1
    return out


def _kerberos(payload: bytes, pkt: Packet) -> None:
    f = pkt.fields
    f["kerberos"] = True
    strict = None
    try:
        strict = _kerberos_strict(payload)
    except Exception:  # noqa: BLE001
        strict = None
    if strict:
        f.update(strict)
        what = _KRB_MSG.get(strict.get("kerberos.msg_type"), "Kerberos")
        who = strict.get("kerberos.CNameString") or strict.get("kerberos.SNameString") or ""
        err = strict.get("kerberos.error_code")
        pkt.summary = f"KRB5 {what}" + (f" {who}" if who else "") + (
            f" (error {err})" if err is not None else "")
        return
    strings = ber_general_strings(payload)
    if not strings:
        pkt.summary = "KRB5 (undecoded)"
        return
    f["kerberos.strings"] = strings
    realms = [s for s in strings if "." in s]
    if realms:
        f["kerberos.realm"] = max(realms, key=len)
    names = [s for s in strings if "." not in s]
    if names:
        f["kerberos.CNameString"] = "/".join(n for n in names if not n.endswith("$"))
        hosts = [n for n in names if n.endswith("$")]
        if hosts:
            f["kerberos.hostname"] = hosts[0]
    pkt.summary = "KRB5 " + " ".join(strings[:4])
