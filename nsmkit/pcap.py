"""
PCAP ingestion.

Three backends:
  1. native  -- soccore.pcap: stdlib only, always available, IPv4 + IPv6.
                The default.
  2. scapy   -- the original pure-Python backend (needs `pip install scapy`).
  3. tshark  -- for captures too large to hold in memory; invoked with -T fields.

All emit the same Event stream as the text parsers, so the MITM, ICMP and DNS
detectors work identically on a capture or a log export. Capture timestamps
are UTC epochs and are converted to naive UTC datetimes -- the convention the
log parsers use -- rather than to the analysing machine's local time.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timedelta
from typing import Optional

from .models import Action, Event, EventKind

_EPOCH = datetime(1970, 1, 1)


def _utc(ts: float) -> datetime:
    return _EPOCH + timedelta(seconds=float(ts))


# --------------------------------------------------------------------------
# native backend (default)
# --------------------------------------------------------------------------

def _read_pcap_native(path: str) -> list[Event]:
    from soccore.pcap import iter_packets
    status: dict = {}
    events = events_from_packets(iter_packets(path, status=status))
    if status.get("problem"):
        import warnings
        warnings.warn(f"{path}: the capture is damaged ({status['problem']}); only the "
                      f"first {status.get('frames', 0):,} frame(s) were read", RuntimeWarning, stacklevel=3)
    return events


def events_from_packets(packets) -> list[Event]:
    """Convert dissected packets (soccore.pcap.Packet, or trafkit's
    PacketRecord -- same attributes) into nsmkit Events, so one parse of a
    capture can feed both toolkits."""
    events: list[Event] = []
    for p in packets:
        f = p.fields
        base = dict(timestamp=_utc(p.ts), source_type="pcap", raw=p.summary)

        if p.proto == "arp":
            if "arp.src.proto_ipv4" not in f:
                continue
            op = f.get("arp.opcode")
            gratuitous = bool(op == 2 and (
                f["arp.src.proto_ipv4"] == f["arp.dst.proto_ipv4"]
                or (p.dst_mac or "").lower() == "ff:ff:ff:ff:ff:ff"))
            events.append(Event(
                **base, kind=EventKind.ARP, action=Action.UNKNOWN,
                src_mac=p.src_mac, dst_mac=p.dst_mac,
                arp_opcode=op,
                arp_sender_ip=f["arp.src.proto_ipv4"], arp_sender_mac=f.get("arp.src.hw_mac"),
                arp_target_ip=f["arp.dst.proto_ipv4"],
                arp_is_gratuitous=gratuitous,
                src_ip=f["arp.src.proto_ipv4"], dst_ip=f["arp.dst.proto_ipv4"],
                protocol="arp",
            ))
            continue

        if not p.src_ip:
            continue
        common = dict(base, src_ip=p.src_ip, dst_ip=p.dst_ip,
                      src_mac=p.src_mac, dst_mac=p.dst_mac)

        if p.proto == "icmp":
            payload = f.get("data.data", b"")
            events.append(Event(
                **common, kind=EventKind.ICMP, protocol="icmp",
                icmp_type=f.get("icmp.type"),
                icmp_payload_len=f.get("data.len", 0),
                bytes_out=p.length,
                extra={"payload": payload.decode("latin-1")} if payload else {},
            ))
            continue

        proto = p.proto if p.proto in ("tcp", "udp") else "ip"
        ports = dict(src_port=p.src_port, dst_port=p.dst_port)

        if "dns.flags.response" in f:
            events.append(Event(
                **common, **ports, kind=EventKind.DNS, protocol=proto,
                dns_query=f.get("dns.qry.name"),
                dns_qtype=f.get("dns.qry.type.name"),
                # An A record when there is one: that is what a spoofed answer forges.
                dns_answer=f.get("dns.a") or f.get("dns.answer"),
                dns_ttl=f.get("dns.resp.ttl"),
                dns_rcode=str(f["dns.rcode"]) if "dns.rcode" in f else None,
                dns_is_response=bool(f.get("dns.flags.response")),
                bytes_out=p.length,
            ))
            continue

        if f.get("http.request") or f.get("http.response"):
            events.append(Event(
                **common, **ports, kind=EventKind.HTTP, protocol=proto,
                http_method=f.get("http.request.method"), http_uri=f.get("http.request.uri"),
                http_host=f.get("http.host"),
                http_status=f.get("http.response.code") if isinstance(
                    f.get("http.response.code"), int) else None,
                user_agent=f.get("http.user_agent"),
                bytes_out=f.get("data.len", 0),
                extra={"body": (f.get("http.file_data") or "")[:1024]},
            ))
            continue

        if f.get("ftp.request.command"):
            events.append(Event(
                **common, **ports, kind=EventKind.FTP, protocol=proto,
                ftp_command=f["ftp.request.command"], ftp_arg=f.get("ftp.request.arg") or None,
                bytes_out=f.get("data.len", 0),
            ))
            continue

        if 443 in (p.src_port, p.dst_port) or "tls.handshake.type" in f:
            events.append(Event(
                **common, **ports, kind=EventKind.TLS, protocol=proto,
                http_host=f.get("tls.handshake.extensions_server_name"),
                bytes_out=p.length,
            ))
            continue

        events.append(Event(**common, **ports, kind=EventKind.NETWORK_FLOW, protocol=proto,
                            bytes_out=p.length))

    events.sort(key=lambda e: e.timestamp)
    return events


# --------------------------------------------------------------------------
# scapy backend
# --------------------------------------------------------------------------

def _read_pcap_scapy(path: str) -> list[Event]:
    from scapy.all import (ARP, DNS, ICMP, IP, TCP, UDP, PcapReader, Raw)  # type: ignore

    events: list[Event] = []
    with PcapReader(path) as reader:
        for pkt in reader:
            ts = _utc(float(pkt.time))
            base = dict(timestamp=ts, source_type="pcap", raw=pkt.summary())

            # ---- ARP ----
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                # Gratuitous: an unsolicited reply where sender IP == target IP,
                # or a reply broadcast to ff:ff:ff:ff:ff:ff.
                gratuitous = bool(
                    arp.op == 2 and (arp.psrc == arp.pdst
                                     or str(pkt.dst).lower() == "ff:ff:ff:ff:ff:ff")
                )
                events.append(Event(
                    **base, kind=EventKind.ARP, action=Action.UNKNOWN,
                    src_mac=str(pkt.src), dst_mac=str(pkt.dst),
                    arp_opcode=int(arp.op),
                    arp_sender_ip=str(arp.psrc), arp_sender_mac=str(arp.hwsrc),
                    arp_target_ip=str(arp.pdst),
                    arp_is_gratuitous=gratuitous,
                    src_ip=str(arp.psrc), dst_ip=str(arp.pdst),
                    protocol="arp",
                ))
                continue

            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            common = dict(base, src_ip=str(ip.src), dst_ip=str(ip.dst),
                          src_mac=str(pkt.src) if hasattr(pkt, "src") else None,
                          dst_mac=str(pkt.dst) if hasattr(pkt, "dst") else None)

            # ---- ICMP ----
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                payload = bytes(icmp.payload) if icmp.payload else b""
                events.append(Event(
                    **common, kind=EventKind.ICMP, protocol="icmp",
                    icmp_type=int(icmp.type),
                    icmp_payload_len=len(payload),
                    bytes_out=len(pkt),
                    extra={"payload": payload[:512].decode("latin-1", "replace")},
                ))
                continue

            sport = int(pkt[TCP].sport) if pkt.haslayer(TCP) else (
                int(pkt[UDP].sport) if pkt.haslayer(UDP) else None)
            dport = int(pkt[TCP].dport) if pkt.haslayer(TCP) else (
                int(pkt[UDP].dport) if pkt.haslayer(UDP) else None)
            proto = "tcp" if pkt.haslayer(TCP) else ("udp" if pkt.haslayer(UDP) else "ip")

            # ---- DNS ----
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                qname = None
                qtype = None
                if dns.qd is not None:
                    try:
                        qname = dns.qd.qname.decode("utf-8", "replace").rstrip(".")
                        qtype = str(dns.qd.qtype)
                    except Exception:
                        pass
                answer, ttl = None, None
                if dns.an is not None and int(getattr(dns, "ancount", 0) or 0) > 0:
                    try:
                        rr = dns.an[0] if hasattr(dns.an, "__getitem__") else dns.an
                        rdata = getattr(rr, "rdata", None)
                        answer = (rdata.decode("utf-8", "replace")
                                  if isinstance(rdata, bytes) else str(rdata))
                        ttl = int(getattr(rr, "ttl", 0))
                    except Exception:
                        pass
                events.append(Event(
                    **common, kind=EventKind.DNS, protocol=proto,
                    src_port=sport, dst_port=dport,
                    dns_query=qname,
                    dns_qtype=_DNS_TYPES.get(int(qtype), qtype) if qtype and qtype.isdigit() else qtype,
                    dns_answer=answer, dns_ttl=ttl,
                    dns_rcode=str(dns.rcode) if hasattr(dns, "rcode") else None,
                    dns_is_response=bool(dns.qr),
                    bytes_out=len(pkt),
                ))
                continue

            # ---- HTTP / FTP (cleartext, from Raw payload) ----
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            text = payload[:4096].decode("latin-1", "replace")

            if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
                method, uri, host = _parse_http_request(text)
                if method or "HTTP/" in text:
                    events.append(Event(
                        **common, kind=EventKind.HTTP, protocol=proto,
                        src_port=sport, dst_port=dport,
                        http_method=method, http_uri=uri, http_host=host,
                        bytes_out=len(payload),
                        extra={"body": text.split("\r\n\r\n", 1)[1][:1024]
                               if "\r\n\r\n" in text else ""},
                    ))
                    continue

            if dport in (21,) or sport in (21,):
                cmd, arg = _parse_ftp(text)
                if cmd:
                    events.append(Event(
                        **common, kind=EventKind.FTP, protocol=proto,
                        src_port=sport, dst_port=dport,
                        ftp_command=cmd, ftp_arg=arg,
                        bytes_out=len(payload),
                    ))
                    continue

            # ---- TLS ClientHello (SNI) ----
            if dport == 443 or sport == 443:
                sni = _extract_sni(payload)
                events.append(Event(
                    **common, kind=EventKind.TLS, protocol=proto,
                    src_port=sport, dst_port=dport,
                    http_host=sni, bytes_out=len(pkt),
                ))
                continue

            # ---- generic flow ----
            events.append(Event(
                **common, kind=EventKind.NETWORK_FLOW, protocol=proto,
                src_port=sport, dst_port=dport, bytes_out=len(pkt),
            ))

    events.sort(key=lambda e: e.timestamp)
    return events


_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def _parse_http_request(text: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    lines = text.split("\r\n")
    if not lines:
        return None, None, None
    parts = lines[0].split()
    method = uri = None
    if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "HEAD", "DELETE",
                                        "OPTIONS", "PATCH", "CONNECT"):
        method, uri = parts[0], parts[1]
    host = None
    for ln in lines[1:]:
        if ln.lower().startswith("host:"):
            host = ln.split(":", 1)[1].strip()
            break
    return method, uri, host


_FTP_COMMANDS = {"USER", "PASS", "STOR", "RETR", "LIST", "CWD", "PASV", "PORT",
                 "QUIT", "TYPE", "MKD", "DELE", "SIZE", "EPSV", "NLST", "APPE"}


def _parse_ftp(text: str) -> tuple[Optional[str], Optional[str]]:
    line = text.split("\r\n", 1)[0].strip()
    if not line:
        return None, None
    parts = line.split(None, 1)
    cmd = parts[0].upper()
    if cmd not in _FTP_COMMANDS:
        return None, None
    return cmd, (parts[1] if len(parts) > 1 else None)


def _valid_hostname(s: str) -> bool:
    return (2 < len(s) < 254 and "." in s
            and all(c.isalnum() or c in ".-_" for c in s)
            and not s.startswith(".") and not s.endswith("."))


def _extract_sni(payload: bytes) -> Optional[str]:
    """
    ClientHello SNI extraction.

    Walks the TLS record -> handshake -> extension list properly, then falls
    back to a byte-pattern scan for the server_name extension so a truncated or
    reassembled segment still yields the hostname.
    """
    try:
        if len(payload) < 45 or payload[0] != 0x16:       # not a handshake record
            return None
        # TLSPlaintext: type(1) version(2) length(2) | Handshake: type(1) length(3)
        if payload[5] != 0x01:                            # not a ClientHello
            return None
        p = 5 + 4                                          # skip handshake header
        p += 2 + 32                                        # client_version + random
        sid_len = payload[p]; p += 1 + sid_len             # session_id
        cs_len = int.from_bytes(payload[p:p + 2], "big"); p += 2 + cs_len
        comp_len = payload[p]; p += 1 + comp_len
        if p + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[p:p + 2], "big"); p += 2
        end = min(len(payload), p + ext_total)
        while p + 4 <= end:
            ext_type = int.from_bytes(payload[p:p + 2], "big")
            ext_len = int.from_bytes(payload[p + 2:p + 4], "big")
            body = payload[p + 4:p + 4 + ext_len]
            if ext_type == 0x0000 and len(body) >= 5:      # server_name
                # ServerNameList: list_len(2) name_type(1) name_len(2) name
                name_len = int.from_bytes(body[3:5], "big")
                name = body[5:5 + name_len].decode("ascii", "ignore")
                if _valid_hostname(name):
                    return name.lower()
            p += 4 + ext_len
    except Exception:
        pass

    # Fallback: locate the extension header pattern anywhere in the buffer.
    try:
        i = 0
        while True:
            i = payload.find(b"\x00\x00", i)
            if i == -1 or i + 9 > len(payload):
                return None
            if payload[i + 4:i + 5] == b"\x00":            # name_type == host_name
                name_len = int.from_bytes(payload[i + 5:i + 7], "big")
                cand = payload[i + 7:i + 7 + name_len].decode("ascii", "ignore")
                if _valid_hostname(cand):
                    return cand.lower()
            i += 1
    except Exception:
        return None


# --------------------------------------------------------------------------
# tshark backend
# --------------------------------------------------------------------------

def _read_pcap_tshark(path: str) -> list[Event]:
    fields = [
        "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "eth.src", "eth.dst",
        "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4",
        "arp.isgratuitous", "arp.duplicate-address-detected",
        "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.a", "dns.resp.ttl",
        "icmp.type", "data.len",
        "http.request.method", "http.request.uri", "http.host", "http.response.code",
        "ftp.request.command", "ftp.request.arg",
        "tls.handshake.extensions_server_name",
    ]
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=\x01", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if out.returncode != 0:
        raise RuntimeError(f"tshark failed: {out.stderr[:400]}")

    events: list[Event] = []
    for line in out.stdout.splitlines():
        cols = line.split("\x01")
        if len(cols) < len(fields):
            cols += [""] * (len(fields) - len(cols))
        g = dict(zip(fields, cols))

        def val(k):
            v = g.get(k, "").strip()
            return v or None

        def ival(k):
            v = val(k)
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        try:
            ts = _utc(float(g["frame.time_epoch"]))
        except (KeyError, ValueError):
            continue

        src_port = ival("tcp.srcport") or ival("udp.srcport")
        dst_port = ival("tcp.dstport") or ival("udp.dstport")
        proto = "tcp" if val("tcp.srcport") else ("udp" if val("udp.srcport") else None)

        if val("arp.opcode"):
            events.append(Event(
                timestamp=ts, kind=EventKind.ARP, source_type="pcap", raw=line[:500],
                src_mac=val("eth.src"), dst_mac=val("eth.dst"),
                arp_opcode=ival("arp.opcode"),
                arp_sender_ip=val("arp.src.proto_ipv4"),
                arp_sender_mac=val("arp.src.hw_mac"),
                arp_target_ip=val("arp.dst.proto_ipv4"),
                arp_is_gratuitous=val("arp.isgratuitous") in ("1", "True"),
                src_ip=val("arp.src.proto_ipv4"), dst_ip=val("arp.dst.proto_ipv4"),
                protocol="arp",
            ))
            continue

        kind = EventKind.NETWORK_FLOW
        if val("dns.qry.name"):
            kind = EventKind.DNS
        elif val("http.request.method"):
            kind = EventKind.HTTP
        elif val("ftp.request.command"):
            kind = EventKind.FTP
        elif val("icmp.type"):
            kind = EventKind.ICMP
        elif val("tls.handshake.extensions_server_name"):
            kind = EventKind.TLS

        events.append(Event(
            timestamp=ts, kind=kind, source_type="pcap", raw=line[:500],
            src_ip=val("ip.src"), dst_ip=val("ip.dst"),
            src_port=src_port, dst_port=dst_port,
            protocol="icmp" if val("icmp.type") else proto,
            src_mac=val("eth.src"), dst_mac=val("eth.dst"),
            bytes_out=ival("frame.len") or 0,
            dns_query=val("dns.qry.name"),
            dns_qtype=_DNS_TYPES.get(ival("dns.qry.type") or -1),
            dns_answer=val("dns.a"), dns_ttl=ival("dns.resp.ttl"),
            dns_is_response=(val("dns.flags.response") == "1"),
            http_method=val("http.request.method"), http_uri=val("http.request.uri"),
            http_host=val("http.host") or val("tls.handshake.extensions_server_name"),
            http_status=ival("http.response.code"),
            ftp_command=(val("ftp.request.command") or "").upper() or None,
            ftp_arg=val("ftp.request.arg"),
            icmp_type=ival("icmp.type"),
            icmp_payload_len=ival("data.len"),
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


# --------------------------------------------------------------------------

def read_pcap(path: str, backend: str = "auto") -> list[Event]:
    """Read a capture into Events. backend: 'auto' (= native) | 'native' |
    'scapy' | 'tshark'."""
    if backend in ("auto", "native"):
        return _read_pcap_native(path)
    if backend == "scapy":
        try:
            import scapy  # noqa: F401
        except ImportError:
            raise RuntimeError("scapy is not installed: pip install scapy "
                               "(or use the default native backend)")
        return _read_pcap_scapy(path)
    if backend == "tshark":
        if not shutil.which("tshark"):
            raise RuntimeError("tshark is not on PATH (install Wireshark, or use the "
                               "default native backend)")
        return _read_pcap_tshark(path)
    raise ValueError(f"unknown pcap backend {backend!r}")
