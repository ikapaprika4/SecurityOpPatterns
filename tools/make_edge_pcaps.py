"""
Edge-case captures for the native-vs-scapy differential test: VLAN/QinQ, IP
options, fragments, Ethernet padding, DNS compression/CNAME/AAAA/TXT/NXDOMAIN,
ICMP errors, NBNS, DHCP, a real Kerberos AS-REQ, odd HTTP header casing,
gratuitous ARP, IPv6, nanosecond pcap, Linux cooked (SLL) and raw-IP links.

    pip install scapy
    python tools/make_edge_pcaps.py OUTDIR
    python tools/dump_scapy_fields.py golden.json OUTDIR/*
    python tools/compare_pcap_backends.py golden.json OUTDIR/*
"""
import os
import sys

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Dot1Q, Ether, Raw,
                       CookedLinux, Padding, wrpcap, wrpcapng, PcapWriter, IPOption_RR)
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNSRRMX
from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse
import scapy.layers.kerberos as krb
from scapy.asn1.asn1 import ASN1_GENERAL_STRING, ASN1_INTEGER

out = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
os.makedirs(out, exist_ok=True)
T0 = 1_750_000_000.123456


def at(p, i):
    p.time = T0 + i * 0.5
    return p


eth = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")

pkts = []
# VLAN + QinQ tagged TCP SYN with options
pkts.append(eth() / Dot1Q(vlan=10) / IP(src="10.1.1.5", dst="10.1.1.9") /
            TCP(sport=40000, dport=445, flags="S", options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)]))
pkts.append(eth() / Dot1Q(vlan=100) / Dot1Q(vlan=20) / IP(src="10.1.1.5", dst="10.1.1.10") /
            TCP(sport=40001, dport=3389, flags="S"))
# IP with options (IHL > 5)
pkts.append(eth() / IP(src="10.2.2.2", dst="10.2.2.3", options=[IPOption_RR()]) /
            UDP(sport=5000, dport=6000) / Raw(b"hello"))
# First fragment and a later fragment
pkts.append(eth() / IP(src="10.3.3.3", dst="10.3.3.4", flags="MF", frag=0, id=77) /
            UDP(sport=1111, dport=2222) / Raw(b"A" * 40))
pkts.append(eth() / IP(src="10.3.3.3", dst="10.3.3.4", frag=6, id=77, proto=17) / Raw(b"B" * 24))
# Small TCP RST that a NIC would pad to 60 bytes (explicit padding)
pkts.append(eth() / IP(src="10.4.4.4", dst="10.4.4.5") / TCP(sport=80, dport=50000, flags="RA") /
            Raw(b"\x00" * 6))
# A bare SYN padded to the 60-byte Ethernet minimum (padding is NOT payload)
pkts.append(eth() / IP(src="10.4.4.6", dst="10.4.4.7") / TCP(sport=50001, dport=443, flags="S") /
            Padding(b"\x00" * 6))
# DNS response with compression, CNAME -> A, plus AAAA/TXT/MX responses
pkts.append(eth() / IP(src="10.0.0.53", dst="10.0.0.20") / UDP(sport=53, dport=33333) /
            DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.org", qtype="A"),
                an=[DNSRR(rrname="www.example.org", type="CNAME", ttl=60, rdata="edge.example.net"),
                    DNSRR(rrname="edge.example.net", type="A", ttl=30, rdata="192.0.2.10")]))
pkts.append(eth() / IP(src="10.0.0.53", dst="10.0.0.20") / UDP(sport=53, dport=33334) /
            DNS(id=0x1235, qr=1, qd=DNSQR(qname="v6.example.org", qtype="AAAA"),
                an=[DNSRR(rrname="v6.example.org", type="AAAA", ttl=300, rdata="2001:db8::10")]))
pkts.append(eth() / IP(src="10.0.0.53", dst="10.0.0.20") / UDP(sport=53, dport=33335) /
            DNS(id=0x1236, qr=1, qd=DNSQR(qname="txt.example.org", qtype="TXT"),
                an=[DNSRR(rrname="txt.example.org", type="TXT", ttl=300, rdata=[b"v=spf1 -all", b"x"])]))
pkts.append(eth() / IP(src="10.0.0.53", dst="10.0.0.20") / UDP(sport=53, dport=33336) /
            DNS(id=0x1237, qr=1, rcode=3, qd=DNSQR(qname="nope.example.org", qtype="A")))
# ICMP TTL-exceeded quoting a TCP segment
inner = IP(src="10.5.5.5", dst="198.51.100.9", ttl=1) / TCP(sport=45000, dport=443, flags="S")
pkts.append(eth() / IP(src="10.5.5.1", dst="10.5.5.5") / ICMP(type=11, code=0) / inner)
# NBNS positive query response
pkts.append(eth() / IP(src="10.6.6.6", dst="10.6.6.7") / UDP(sport=137, dport=137) /
            NBNSHeader(NAME_TRN_ID=1, RESPONSE=1, OPCODE=0, NM_FLAGS=0x40, ANCOUNT=1) /
            NBNSQueryResponse(RR_NAME="FILESRV01"))
# DHCP discover with vendor class + client id
pkts.append(Ether(src="02:00:00:00:00:77", dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex("020000000077") + b"\x00" * 10, xid=0x42) /
            DHCP(options=[("message-type", "discover"), ("hostname", b"LAPTOP-7"),
                          ("vendor_class_id", b"MSFT 5.0"), "end"]))
# A genuine AS-REQ
body = krb.KRB_KDC_REQ_BODY(
    kdcOptions="forwardable+renewable",
    cname=krb.PrincipalName(nameString=[ASN1_GENERAL_STRING(b"alice")], nameType=ASN1_INTEGER(1)),
    realm=ASN1_GENERAL_STRING(b"CORP.EXAMPLE"),
    sname=krb.PrincipalName(nameString=[ASN1_GENERAL_STRING(b"krbtgt"), ASN1_GENERAL_STRING(b"CORP.EXAMPLE")],
                            nameType=ASN1_INTEGER(2)),
    nonce=ASN1_INTEGER(12345), etype=[ASN1_INTEGER(18), ASN1_INTEGER(23)])
asreq = krb.Kerberos(root=krb.KRB_AS_REQ(reqBody=body))
pkts.append(eth() / IP(src="10.7.7.7", dst="10.7.7.1") / UDP(sport=51000, dport=88) / asreq)
# HTTP request with odd header casing and a response with Location
pkts.append(eth() / IP(src="10.8.8.8", dst="10.8.8.9") / TCP(sport=51111, dport=8080, flags="PA") /
            Raw(b"POST /api/v1/upload?x=1 HTTP/1.1\r\nhOsT: files.internal\r\nuser-AGENT: python-requests/2.31\r\n"
                b"Content-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nDATA"))
pkts.append(eth() / IP(src="10.8.8.9", dst="10.8.8.8") / TCP(sport=8080, dport=51111, flags="PA") /
            Raw(b"HTTP/1.1 302 Found\r\nLocation: /done\r\nServer: gunicorn\r\n\r\n"))
# ARP gratuitous request
pkts.append(Ether(src="02:00:00:00:00:99", dst="ff:ff:ff:ff:ff:ff") /
            ARP(op=1, hwsrc="02:00:00:00:00:99", psrc="10.9.9.9", pdst="10.9.9.9"))
# IPv6 (scapy-backed trafkit ignores IPv6; native must parse it without errors)
pkts.append(eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=40100, dport=22, flags="S"))
pkts.append(eth() / IPv6(src="2001:db8::1", dst="2001:db8::53") / UDP(sport=40200, dport=53) /
            DNS(id=9, qd=DNSQR(qname="ipv6-only.example", qtype="AAAA")))
pkts = [at(p, i) for i, p in enumerate(pkts)]
wrpcap(os.path.join(out, "edge_ether.pcap"), pkts)
wrpcapng(os.path.join(out, "edge_ether_real.pcapng"), pkts)

# nanosecond pcap
w = PcapWriter(os.path.join(out, "edge_nano.pcap"), nano=True)
for p in pkts[:5]:
    w.write(p)
w.close()

# Linux cooked capture
sll = [at(CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x02\x00\x00\x00\x00\x05\x00\x00", proto=0x0800) /
          IP(src="10.10.0.5", dst="10.10.0.6") / TCP(sport=33000, dport=21, flags="PA") / Raw(b"USER bob\r\n"), 1)]
wrpcap(os.path.join(out, "edge_sll.pcap"), sll)

# Raw IP link type
raw = [at(IP(src="10.11.0.1", dst="10.11.0.2") / UDP(sport=5353, dport=5353) /
          DNS(id=0, qr=0, qd=DNSQR(qname="printer.local", qtype="A")), 1)]
wrpcap(os.path.join(out, "edge_rawip.pcap"), raw, linktype=101)
print("edge captures written")
