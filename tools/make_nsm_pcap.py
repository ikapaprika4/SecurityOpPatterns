#!/usr/bin/env python3
"""
Build a synthetic MITM capture so the ARP/DNS/SSL-strip and ICMP detectors can
be validated without a lab. Mirrors the MITM room's chain:

    ARP poison (gateway) -> forged DNS answer -> TLS stripped -> creds in clear
    plus an ICMP tunnel from a second host.

Usage:  python tools/make_nsm_pcap.py [out.pcap]    (default: samples/nsmkit/mitm.pcap; needs scapy)
"""

from __future__ import annotations

import base64
import os
import sys

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw,
                       wrpcap)

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "nsmkit"), "mitm.pcap")

GW_IP, GW_MAC = "192.168.10.1", "02:aa:bb:cc:00:01"
VICTIM_IP, VICTIM_MAC = "192.168.10.10", "02:aa:bb:cc:00:10"
ATTACKER_IP, ATTACKER_MAC = "192.168.10.55", "02:fe:bb:cd:55:55"
SERVER_IP = "203.0.113.80"
RESOLVER = "8.8.8.8"
DOMAIN = "corp-login.acme-corp.local"

pkts = []
t = 1_700_000_000.0


def add(p, dt=0.25):
    global t
    p.time = t
    t += dt
    pkts.append(p)


# ---------------------------------------------------------- normal baseline
for i in range(6):
    add(Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, psrc=VICTIM_IP, hwsrc=VICTIM_MAC, pdst=GW_IP))
    add(Ether(src=GW_MAC, dst=VICTIM_MAC) /
        ARP(op=2, psrc=GW_IP, hwsrc=GW_MAC, pdst=VICTIM_IP, hwdst=VICTIM_MAC))

def client_hello(sni: str) -> bytes:
    """A minimal but structurally valid TLS 1.2 ClientHello carrying an SNI."""
    host = sni.encode()
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host      # name_type + name
    sni_ext_body = len(server_name).to_bytes(2, "big") + server_name  # ServerNameList
    sni_ext = b"\x00\x00" + len(sni_ext_body).to_bytes(2, "big") + sni_ext_body
    extensions = len(sni_ext).to_bytes(2, "big") + sni_ext

    body = (b"\x03\x03"                       # client_version TLS 1.2
            + b"\x11" * 32                    # random
            + b"\x00"                         # session_id length
            + b"\x00\x02\x00\x2f"             # cipher_suites
            + b"\x01\x00"                     # compression_methods
            + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


# legitimate TLS to the portal, so the site is known to speak HTTPS
for i in range(3):
    add(Ether(src=VICTIM_MAC, dst=GW_MAC) / IP(src=VICTIM_IP, dst=SERVER_IP) /
        TCP(sport=44000 + i, dport=443, flags="PA") / Raw(load=client_hello(DOMAIN)))

# ------------------------------------------------------ 1. ARP cache poisoning
for i in range(14):
    # attacker claims to be the gateway, unsolicited, to the victim
    add(Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) /
        ARP(op=2, psrc=GW_IP, hwsrc=ATTACKER_MAC, pdst=VICTIM_IP, hwdst=VICTIM_MAC), dt=1.0)
    # and gratuitous broadcasts to keep the poison fresh
    add(Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=2, psrc=GW_IP, hwsrc=ATTACKER_MAC, pdst=GW_IP, hwdst="ff:ff:ff:ff:ff:ff"), dt=1.0)

# ------------------------------------------------------ 2. DNS spoofing
for i in range(3):
    add(Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=VICTIM_IP, dst=RESOLVER) /
        UDP(sport=50000 + i, dport=53) /
        DNS(id=0x1000 + i, rd=1, qd=DNSQR(qname=DOMAIN)), dt=0.05)
    # legitimate answer
    add(Ether(src=GW_MAC, dst=VICTIM_MAC) / IP(src=RESOLVER, dst=VICTIM_IP) /
        UDP(sport=53, dport=50000 + i) /
        DNS(id=0x1000 + i, qr=1, aa=1, qd=DNSQR(qname=DOMAIN),
            an=DNSRR(rrname=DOMAIN, type="A", ttl=3600, rdata=SERVER_IP)), dt=0.4)
    # forged answer from the attacker, arriving in the same race window
    add(Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / IP(src=ATTACKER_IP, dst=VICTIM_IP) /
        UDP(sport=53, dport=50000 + i) /
        DNS(id=0x1000 + i, qr=1, aa=1, qd=DNSQR(qname=DOMAIN),
            an=DNSRR(rrname=DOMAIN, type="A", ttl=15, rdata=ATTACKER_IP)), dt=0.4)

# ------------------------------------------------------ 3. SSL stripping
get = (f"GET /login HTTP/1.1\r\nHost: {DOMAIN}\r\n"
       f"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n").encode()
add(Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=VICTIM_IP, dst=ATTACKER_IP) /
    TCP(sport=45001, dport=80, flags="PA") / Raw(load=get))

post_body = b"username=j.doe&password=Winter2025!&remember=1"
post = (f"POST /login HTTP/1.1\r\nHost: {DOMAIN}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)}\r\n\r\n").encode() + post_body
add(Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=VICTIM_IP, dst=ATTACKER_IP) /
    TCP(sport=45001, dport=80, flags="PA") / Raw(load=post))

for i in range(4):
    add(Ether(src=VICTIM_MAC, dst=ATTACKER_MAC) / IP(src=VICTIM_IP, dst=ATTACKER_IP) /
        TCP(sport=45002 + i, dport=80, flags="PA") /
        Raw(load=f"GET /portal/{i} HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode()))

# ------------------------------------------------------ 4. ICMP tunnelling
secret = b"BEGIN-EXFIL;employee_records.csv;ssn,dob,salary;" * 12
chunks = [secret[i:i + 180] for i in range(0, len(secret), 180)]
for i, chunk in enumerate(chunks * 3):
    payload = base64.b64encode(chunk)
    add(Ether(src="02:aa:bb:cc:00:20", dst=GW_MAC) /
        IP(src="192.168.10.20", dst="203.0.113.99") /
        ICMP(type=8, id=0x4141, seq=i) / Raw(load=payload), dt=1.5)

wrpcap(OUT, pkts)
print(f"Wrote {OUT} ({len(pkts)} packets)")
