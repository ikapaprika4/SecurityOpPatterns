"""
soccore test suite: the native pcap/pcapng reader, address classification,
and the O(n) sliding windows.

Run with: python tests/test_soccore.py

Frames here are built byte by byte (no scapy), so every container format,
link type and malformation is exercised without any dependency. Field-level
equivalence with the old scapy backend is checked separately by
tools/compare_pcap_backends.py against a golden dump.
"""

from __future__ import annotations

import gzip
import os
import random
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soccore import netaddr  # noqa: E402
from soccore.pcap import (PcapError, dissect, extract_sni, iter_frames,  # noqa: E402
                          read_packets, sniff_capture)
from soccore.windows import densest, most_distinct  # noqa: E402


# --------------------------------------------------------------------------
# Tiny packet builder
# --------------------------------------------------------------------------

MAC_A, MAC_B = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def eth(payload: bytes, etype: int = 0x0800, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return MAC_B + MAC_A + tag + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, flags_frag: int = 0) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 7, flags_frag, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, ext: bytes = b"") -> bytes:
    first = 60 if ext else nxt                         # destination-options header first
    hdr = struct.pack("!IHBB", 6 << 28, len(ext) + len(payload), first, 64)
    hdr += socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return hdr + ext + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | flags, window, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def pcap_file(frames: list[bytes], linktype: int = 1, nano: bool = False, big: bool = False) -> bytes:
    e = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, fr in enumerate(frames):
        out += struct.pack(e + "IIII", 1_700_000_000 + i, 500_000_000 if nano else 500_000,
                           len(fr), len(fr)) + fr
    return out


def pcapng_file(frames: list[bytes], linktype: int = 1, tsresol: int | None = None) -> bytes:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = b""
    if tsresol is not None:
        opts = struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535) + opts)
    out = shb + idb
    divisor = 10 ** (tsresol or 6)
    for i, fr in enumerate(frames):
        ts = (1_700_000_000 + i) * divisor + divisor // 2
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(fr), len(fr)) + fr)
    return out


def write(tmp: str, name: str, data: bytes) -> str:
    path = os.path.join(tmp, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


SYN = eth(ipv4("10.0.0.5", "203.0.113.9", 6, tcp(40000, 443, 0x02)))


class TestContainers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pcap_little_big_and_nanosecond(self):
        for kw in ({}, {"big": True}, {"nano": True}):
            pkts = read_packets(write(self.tmp, "a.pcap", pcap_file([SYN, SYN], **kw)))
            self.assertEqual(len(pkts), 2, kw)
            self.assertAlmostEqual(pkts[1].ts, 1_700_000_001.5, places=5)
            self.assertEqual(pkts[0].fields["tcp.dstport"], 443)

    def test_pcapng_with_nanosecond_tsresol(self):
        pkts = read_packets(write(self.tmp, "a.pcapng", pcapng_file([SYN, SYN], tsresol=9)))
        self.assertEqual(len(pkts), 2)
        self.assertAlmostEqual(pkts[0].ts, 1_700_000_000.5, places=5)

    def test_gzip_compressed_capture(self):
        path = write(self.tmp, "a.pcap.gz", gzip.compress(pcap_file([SYN])))
        self.assertEqual(len(read_packets(path)), 1)

    def test_truncated_capture_ends_cleanly(self):
        data = pcap_file([SYN, SYN, SYN])
        pkts = read_packets(write(self.tmp, "t.pcap", data[:-10]))
        self.assertEqual(len(pkts), 3)                  # last frame partial, still yielded
        self.assertTrue(pkts[2].fields["frame.cap_len"] < len(SYN))

    def test_status_reports_a_clean_read(self):
        status: dict = {}
        read_packets(write(self.tmp, "c.pcapng", pcapng_file([SYN, SYN])), status=status)
        self.assertEqual(status, {"frames": 2, "problem": None})

    def test_status_reports_truncation(self):
        status: dict = {}
        read_packets(write(self.tmp, "t.pcap", pcap_file([SYN, SYN, SYN])[:-10]), status=status)
        self.assertEqual(status["frames"], 3)
        self.assertIn("truncated", status["problem"])

    def test_status_reports_a_corrupt_block_after_good_frames(self):
        data = bytearray(pcapng_file([SYN, SYN, SYN]))
        # Third EPB's total-length field -> absurd; the first two frames stay readable.
        epb_len = 12 + 20 + len(SYN) + (-len(SYN) % 4)
        third = len(data) - epb_len
        data[third + 4:third + 8] = struct.pack("<I", 0xFFFFFFF0)
        status: dict = {}
        pkts = read_packets(write(self.tmp, "x.pcapng", bytes(data)), status=status)
        self.assertEqual((len(pkts), status["frames"]), (2, 2))
        self.assertIn("corrupt block length", status["problem"])

    def test_status_reports_garbage_after_a_valid_magic(self):
        status: dict = {}
        pkts = read_packets(write(self.tmp, "g.pcapng", b"\x0a\x0d\x0d\x0a" + bytes(range(200))),
                            status=status)
        self.assertEqual(pkts, [])
        self.assertIn("corrupt section header", status["problem"])

    def test_status_reports_a_damaged_gzip_stream(self):
        blob = gzip.compress(pcap_file([SYN] * 50))
        status: dict = {}
        read_packets(write(self.tmp, "d.pcap.gz", blob[:len(blob) // 2]), status=status)
        self.assertIn("compressed stream", status["problem"])

    def test_status_marks_a_max_packets_limit(self):
        status: dict = {}
        pkts = read_packets(write(self.tmp, "m.pcap", pcap_file([SYN] * 5)), max_packets=2,
                            status=status)
        self.assertEqual((len(pkts), status.get("limited"), status.get("problem")), (2, True, None))

    def test_not_a_capture_raises_pcaperror(self):
        with self.assertRaises(PcapError):
            list(iter_frames(write(self.tmp, "x.pcap", b"hello world, not a capture")))

    def test_sniff_capture(self):
        self.assertEqual(sniff_capture(pcap_file([])[:4]), "pcap")
        self.assertEqual(sniff_capture(pcapng_file([])[:4]), "pcapng")
        self.assertIsNone(sniff_capture(b"<Events>"))


class TestLinkLayers(unittest.TestCase):
    def test_vlan_tagged(self):
        p = dissect(eth(ipv4("10.0.0.5", "10.0.0.9", 6, tcp(1, 22, 0x02)), vlan=30), 1)
        self.assertEqual((p.fields["vlan.id"], p.dst_port, p.proto), (30, 22, "tcp"))

    def test_raw_ip_and_linux_sll2(self):
        raw = ipv4("10.0.0.5", "10.0.0.9", 17, udp(5000, 6000, b"hi"))
        self.assertEqual(dissect(raw, 101).proto, "udp")
        sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, MAC_A + b"\x00\x00") + raw
        p = dissect(sll2, 276)
        self.assertEqual((p.proto, p.src_mac), ("udp", "02:00:00:00:00:01"))

    def test_bsd_null_loopback_either_byte_order(self):
        raw = ipv4("127.0.0.1", "127.0.0.1", 17, udp(1, 2, b""))
        self.assertEqual(dissect(struct.pack("<I", 2) + raw, 0).src_ip, "127.0.0.1")
        self.assertEqual(dissect(struct.pack(">I", 2) + raw, 0).src_ip, "127.0.0.1")

    def test_unknown_link_type_is_not_an_error(self):
        p = dissect(b"\x00" * 30, 9999)
        self.assertIn("Unsupported link-layer type", p.summary)


class TestDissectors(unittest.TestCase):
    def test_ethernet_padding_is_not_payload(self):
        frame = SYN + b"\x00" * (60 - len(SYN))
        p = dissect(frame, 1)
        self.assertEqual(p.fields["data.len"], 0)

    def test_ipv6_with_extension_header(self):
        ext = bytes([6, 0]) + b"\x00" * 6              # dest-options, next = TCP
        p = dissect(eth(ipv6("2001:db8::1", "2001:db8::2", 6, tcp(40000, 22, 0x02), ext), 0x86DD), 1)
        self.assertEqual((p.src_ip, p.dst_port, p.proto), ("2001:db8::1", 22, "tcp"))
        self.assertEqual(p.fields["ipv6.hlim"], 64)

    def test_later_ip_fragment_is_not_dissected_as_transport(self):
        p = dissect(eth(ipv4("10.0.0.5", "10.0.0.9", 17, b"X" * 40, flags_frag=5)), 1)
        self.assertEqual(p.proto, "ip")
        self.assertNotIn("udp.srcport", p.fields)

    def test_icmp_error_quotes_offending_udp_probe(self):
        quoted = ipv4("10.0.0.5", "10.0.0.9", 17, udp(42000, 161, b""))
        icmp = bytes([3, 3, 0, 0]) + b"\x00" * 4 + quoted
        p = dissect(eth(ipv4("10.0.0.9", "10.0.0.5", 1, icmp)), 1)
        self.assertEqual((p.fields["icmp.orig.udp.dstport"], p.fields["icmp.orig.ip.src"]),
                         (161, "10.0.0.5"))

    def test_dns_compression_and_answers(self):
        q = dns_name("www.example.org")
        body = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0) + q + struct.pack("!HH", 1, 1)
        cname = dns_name("edge.example.net")
        body += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname)) + cname
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("192.0.2.10")
        p = dissect(eth(ipv4("10.0.0.53", "10.0.0.20", 17, udp(53, 33333, body))), 1)
        f = p.fields
        self.assertEqual(f["dns.qry.name"], "www.example.org")
        self.assertEqual(f["dns.a"], "192.0.2.10")                 # the A record, not the alias
        self.assertEqual(f["dns.resp_all"], ["edge.example.net", "192.0.2.10"])
        self.assertEqual(f["dns.cname"], "edge.example.net")

    def test_dns_pointer_loop_does_not_hang(self):
        body = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
        p = dissect(eth(ipv4("10.0.0.5", "10.0.0.53", 17, udp(5000, 53, body))), 1)
        self.assertNotIn("dns.qry.name", p.fields)                  # rejected, not looped

    def test_http_request_fields(self):
        req = (b"POST /login HTTP/1.1\r\nHost: portal.example\r\nUser-Agent: curl/8\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=a&password=b")
        p = dissect(eth(ipv4("10.0.0.5", "10.0.0.9", 6, tcp(50000, 80, 0x18, req))), 1)
        f = p.fields
        self.assertEqual((f["http.request.method"], f["http.request.uri"], f["http.host"]),
                         ("POST", "/login", "portal.example"))
        self.assertEqual(f["http.request.full_uri"], "http://portal.example/login")
        self.assertEqual(f["http.file_data"], "user=a&password=b")
        self.assertNotIn("http.cookie", f)                         # absent header -> absent field

    def test_tls_sni(self):
        sni = b"secret.example.com"
        ext = struct.pack("!HH", 0, len(sni) + 5) + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni
        body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + \
            struct.pack("!H", len(ext)) + ext
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
        self.assertEqual(extract_sni(record), "secret.example.com")
        p = dissect(eth(ipv4("10.0.0.5", "203.0.113.9", 6, tcp(50000, 8443, 0x18, record))), 1)
        self.assertEqual(p.fields["tls.handshake.extensions_server_name"], "secret.example.com")

    def test_nbns_registration_carries_owner_address(self):
        enc = bytes([32]) + bytes(b for ch in b"LAPTOP-7".ljust(15) + b"\x00"
                                  for b in (0x41 + (ch >> 4), 0x41 + (ch & 0xF))) + b"\x00"
        body = struct.pack("!HHHHHH", 7, 0x2910, 1, 0, 0, 1) + enc + struct.pack("!HH", 0x20, 1)
        body += b"\xc0\x0c" + struct.pack("!HHIH", 0x20, 1, 300000, 6) + b"\x00\x00" + \
            socket.inet_aton("192.168.1.31")
        p = dissect(eth(ipv4("192.168.1.31", "192.168.1.255", 17, udp(137, 137, body))), 1)
        f = p.fields
        self.assertEqual((f["nbns.name"], f["nbns.opcode"], f["nbns.addr"]),
                         ("LAPTOP-7", 5, "192.168.1.31"))

    def test_kerberos_strict_as_req(self):
        def tlv(tag, content):
            ln = len(content)
            return bytes([tag]) + (bytes([ln]) if ln < 128 else b"\x81" + bytes([ln])) + content

        def gstr(s):
            return tlv(0x1B, s.encode())

        def principal(*names):
            return tlv(0x30, tlv(0xA0, tlv(0x02, b"\x01")) + tlv(0xA1, tlv(0x30, b"".join(gstr(n) for n in names))))
        body = tlv(0x30, tlv(0xA0, tlv(0x03, b"\x00\x40\x81\x00\x10"))
                   + tlv(0xA1, principal("alice")) + tlv(0xA2, gstr("CORP.EXAMPLE"))
                   + tlv(0xA3, principal("krbtgt", "CORP.EXAMPLE"))
                   + tlv(0xA8, tlv(0x30, tlv(0x02, b"\x12") + tlv(0x02, b"\x17"))))
        asreq = tlv(0x6A, tlv(0x30, tlv(0xA1, tlv(0x02, b"\x05")) + tlv(0xA2, tlv(0x02, b"\x0a"))
                              + tlv(0xA4, body)))
        f = dissect(eth(ipv4("10.0.0.5", "10.0.0.2", 17, udp(51000, 88, asreq))), 1).fields
        self.assertEqual((f["kerberos.CNameString"], f["kerberos.SNameString"], f["kerberos.realm"]),
                         ("alice", "krbtgt/CORP.EXAMPLE", "CORP.EXAMPLE"))
        self.assertEqual(f["kerberos.etype"], [18, 23])          # 23 = RC4: a roasting tell

    def test_random_garbage_never_raises(self):
        rng = random.Random(1)
        for _ in range(2000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 120)))
            for lt in (1, 101, 113, 276, 0):
                p = dissect(data, lt)
                self.assertIsInstance(p.summary, str)


class TestNetaddr(unittest.TestCase):
    def test_documentation_ranges_are_external(self):
        for ip in ("203.0.113.7", "198.51.100.9", "192.0.2.44"):
            self.assertFalse(netaddr.is_internal(ip))
            self.assertTrue(netaddr.is_public(ip))

    def test_internal_space_incl_mapped_and_zoned(self):
        for ip in ("10.1.2.3", "172.20.0.1", "192.168.0.9", "100.64.1.1", "fd00::1",
                   "::ffff:10.0.0.5", "[fe80::1%12]"):
            self.assertTrue(netaddr.is_internal(ip), ip)

    def test_not_public(self):
        for ip in ("0.0.0.0", "255.255.255.255", "224.0.0.251", "not-an-ip", "", None):
            self.assertFalse(netaddr.is_public(ip), ip)

    def test_in_networks(self):
        self.assertTrue(netaddr.in_networks("::ffff:10.9.9.9", ["10.0.0.0/8"]))
        self.assertFalse(netaddr.in_networks("10.9.9.9", ["fd00::/8", "bogus"]))


class TestWindows(unittest.TestCase):
    """The O(n) helpers must pick exactly the window the old O(n*w) loops did."""

    @staticmethod
    def _brute_densest(times, w):
        best, lo = (0, 0), 0
        for hi in range(len(times)):
            while times[hi] - times[lo] > w:
                lo += 1
            if hi + 1 - lo > best[1] - best[0]:
                best = (lo, hi + 1)
        return best

    @staticmethod
    def _brute_distinct(items, w):
        best, lo = [], 0
        for hi in range(len(items)):
            while items[hi][0] - items[lo][0] > w:
                lo += 1
            win = items[lo:hi + 1]
            if len({k for _, k in win}) > len({k for _, k in best}):
                best = win
        return best

    def test_equivalence_on_random_data(self):
        rng = random.Random(7)
        for _ in range(300):
            n = rng.randint(0, 60)
            times = sorted(rng.uniform(0, 100) for _ in range(n))
            items = [(t, rng.randint(0, 8)) for t in times]
            w = rng.choice([0, 1, 5, 20, 1000])
            self.assertEqual(densest(times, w), self._brute_densest(times, w))
            lo, hi = most_distinct(items, lambda x: x[0], lambda x: x[1], w)
            self.assertEqual(items[lo:hi], self._brute_distinct(items, w))


if __name__ == "__main__":
    unittest.main(verbosity=2)
