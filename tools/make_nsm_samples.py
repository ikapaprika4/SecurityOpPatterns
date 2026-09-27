#!/usr/bin/env python3
"""
Generate a synthetic but realistic incident dataset so the toolkit can be run
and validated without a lab VM.

The scenario mirrors the perimeter-monitoring investigation end to end:
  1. external recon      203.0.113.10 scans the perimeter
  2. exposed service     SSH reachable from the internet
  3. VPN brute force     the same IP hammers svc_backup, then succeeds
  4. lateral movement    the assigned pool IP 10.8.0.66 sweeps 22/445/3389
  5. C2 beaconing        10.0.0.51 checks in to 203.0.113.10:4444 every 6h
  6. exfiltration        10.0.0.51 POSTs bulk data out; DNS tunnel to a burner domain

Usage:  python tools/make_nsm_samples.py [outdir]    (default: samples/nsmkit)
"""

from __future__ import annotations

import base64
import os
import random
import sys
from datetime import datetime, timedelta

random.seed(1337)

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "nsmkit")
os.makedirs(OUT, exist_ok=True)

START = datetime(2025, 8, 25, 0, 0, 0)
ATTACKER = "203.0.113.10"
BENIGN = ["198.51.100.92", "192.0.2.115", "203.0.113.100", "198.51.100.45"]
INTERNAL = ["10.0.0.20", "10.0.0.50", "10.0.0.51", "10.0.0.60", "10.0.0.70"]
DMZ_WEB = "10.0.0.50"
COMPROMISED = "10.0.0.51"
VPN_GW = "10.0.0.1"
VPN_ASSIGNED = "10.8.0.66"
C2_PORT = 4444
EXFIL_DOMAIN = "cdn-metrics-sync.example"

fw: list[tuple[datetime, str]] = []
ids: list[tuple[datetime, str]] = []
vpn: list[tuple[datetime, str]] = []
dns: list[tuple[datetime, str]] = []
http: list[tuple[datetime, str]] = []


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- background
for day in range(35):
    for _ in range(random.randint(20, 40)):
        t = START + timedelta(days=day, seconds=random.randint(0, 86399))
        src = random.choice(BENIGN)
        dst = random.choice(INTERNAL)
        port = random.choice([80, 443, 443, 443, 25, 53, 8080])
        fw.append((t, f"{ts(t)} ALLOW TCP {src}:{random.randint(49152, 65535)} -> {dst}:{port}"))
    # a little internal chatter
    for _ in range(random.randint(5, 12)):
        t = START + timedelta(days=day, seconds=random.randint(0, 86399))
        http.append((t, f'timestamp={t.strftime("%Y-%m-%dT%H:%M:%SZ")} '
                        f'src_ip={random.choice(INTERNAL)} dst_ip=93.184.216.34 method=GET '
                        f'domain=example.com uri=/index.html bytes_sent={random.randint(200, 900)} '
                        f'status=200 action=ALLOW'))
    for _ in range(random.randint(30, 60)):
        t = START + timedelta(days=day, seconds=random.randint(0, 86399))
        host = random.choice(["www.google.com", "outlook.office365.com", "update.microsoft.com",
                              "cdn.jsdelivr.net", "api.github.com"])
        dns.append((t, f'timestamp={t.strftime("%Y-%m-%dT%H:%M:%SZ")} '
                       f'src_ip={random.choice(INTERNAL)} dst_ip=8.8.8.8 query={host} '
                       f'qtype=A rcode=NOERROR action=ALLOW'))
    # normal VPN logins
    for user in random.sample(["alice", "bob", "jsmith", "mgarcia"], k=random.randint(1, 3)):
        t = START + timedelta(days=day, hours=random.randint(7, 19), minutes=random.randint(0, 59))
        vpn.append((t, f"{ts(t)} {random.choice(BENIGN)} {user} SUCCESS "
                       f"assigned_ip=10.8.0.{random.randint(10, 200)}"))

# ---------------------------------------------------- 1. external recon (day 2)
t0 = START + timedelta(days=2, hours=12, minutes=12)
scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433,
              3306, 3389, 5432, 5900, 8080, 8443]
for i, port in enumerate(scan_ports):
    t = t0 + timedelta(seconds=i * 3)
    fw.append((t, f"{ts(t)} BLOCK TCP {ATTACKER}:{50000 + i} -> {DMZ_WEB}:{port}"))
    if port in (22, 445, 3389):
        ids.append((t, f"{ts(t)} [**] [1:2000100:1] ET SCAN Possible SSH/SMB Scan [**] "
                       f"[Classification: Attempted Information Leak] [Priority: 2] {{TCP}} "
                       f"{ATTACKER}:{50000 + i} -> {DMZ_WEB}:{port}"))
# horizontal sweep for 445 across the estate
for i in range(20):
    t = t0 + timedelta(minutes=4, seconds=i * 2)
    host = f"10.0.0.{20 + i}"
    fw.append((t, f"{ts(t)} BLOCK TCP {ATTACKER}:{51000 + i} -> {host}:445"))

# ------------------------------------------- 2. exposed SSH (misconfiguration)
for i in range(6):
    t = START + timedelta(days=3, hours=21, minutes=i * 7)
    fw.append((t, f"{ts(t)} ALLOW TCP {ATTACKER}:{53000 + i} -> {DMZ_WEB}:22"))

# ------------------------------------------- 3. VPN brute force + success (d9)
bf = START + timedelta(days=9, hours=2, minutes=19)
for i in range(118):
    t = bf + timedelta(seconds=i * 10)
    vpn.append((t, f"{ts(t)} {ATTACKER} svc_backup FAIL"))
    fw.append((t, f"{ts(t)} ALLOW TCP {ATTACKER}:{31000 + i} -> {VPN_GW}:443"))
t_success = bf + timedelta(seconds=1190)
vpn.append((t_success, f"{ts(t_success)} {ATTACKER} svc_backup SUCCESS assigned_ip={VPN_ASSIGNED}"))
# password spray the following night
sp = START + timedelta(days=9, hours=23)
for i, user in enumerate(["admin", "root", "test", "guest", "backup", "operator",
                          "helpdesk", "sqladmin", "ftpuser", "webadmin"]):
    for k in range(2):
        t = sp + timedelta(seconds=i * 90 + k * 20)
        vpn.append((t, f"{ts(t)} {ATTACKER} {user} FAIL"))

# ---------------------------------------------------- 4. lateral movement (d11)
lm = START + timedelta(days=11, hours=6)
for i in range(40):
    t = lm + timedelta(minutes=i * 10)
    target = INTERNAL[i % len(INTERNAL)]
    port = [22, 445, 3389][i % 3]
    fw.append((t, f"{ts(t)} ALLOW TCP {VPN_ASSIGNED}:{2000 + i} -> {target}:{port}"))
    sig = {22: "ET SCAN Possible SSH Scan",
           445: "ET EXPLOIT Possible MS-SMB Lateral Movement",
           3389: "ET EXPLOIT Possible RDP Brute Force"}[port]
    ids.append((t, f"{ts(t)} [**] [1:{2000200 + i}:1] {sig} [**] "
                   f"[Classification: Attempted Unauthorized Access] [Priority: 1] {{TCP}} "
                   f"{VPN_ASSIGNED}:{2000 + i} -> {target}:{port}"))

# ------------------------------------------------------- 5. C2 beaconing (d17+)
c2_start = START + timedelta(days=17, hours=1)
for i in range(80):
    t = c2_start + timedelta(hours=6 * i / 2) + timedelta(seconds=random.randint(-30, 30))
    fw.append((t, f"{ts(t)} ALLOW TCP {COMPROMISED}:{30000 + i} -> {ATTACKER}:{C2_PORT}"))
    ids.append((t, f"{ts(t)} [**] [1:{2001000 + i}:1] ET TROJAN Possible C2 Beaconing [**] "
                   f"[Classification: A network Trojan was detected] [Priority: 1] {{TCP}} "
                   f"{COMPROMISED}:{30000 + i} -> {ATTACKER}:{C2_PORT}"))

# ------------------------------------------------- 6a. HTTP exfiltration (d24+)
ex = START + timedelta(days=24, hours=3)
for i in range(60):
    t = ex + timedelta(hours=4 * i)
    port = 8080 if i % 3 == 0 else 80
    size = random.randint(2_000_000, 9_000_000)
    fw.append((t, f"{ts(t)} ALLOW TCP {COMPROMISED}:{40000 + i} -> {ATTACKER}:{port}"))
    http.append((t, f'timestamp={t.strftime("%Y-%m-%dT%H:%M:%SZ")} src_ip={COMPROMISED} '
                    f'dst_ip={ATTACKER} method=POST domain=staging-backup.example '
                    f'uri=/upload/chunk{i}.bin bytes_sent={size} status=200 action=ALLOW'))
    ids.append((t, f"{ts(t)} [**] [1:{2002000 + i}:1] ET INFO Possible HTTP POST Large Upload [**] "
                   f"[Classification: Potential Data Exfiltration] [Priority: 2] {{TCP}} "
                   f"{COMPROMISED}:{40000 + i} -> {ATTACKER}:{port}"))

# ------------------------------------------------- 6b. DNS tunnelling (d26+)
secret = (b"CONFIDENTIAL:Q3-financials,customer-PII-export,domain-admin-hash-dump;" * 40)
chunks = [secret[i:i + 30] for i in range(0, len(secret), 30)]
dt0 = START + timedelta(days=26, hours=2)
for i, chunk in enumerate(chunks[:90]):
    t = dt0 + timedelta(seconds=i * 45)
    label = base64.b32encode(chunk).decode().rstrip("=")
    host = COMPROMISED if i % 3 else "10.0.0.60"
    qname = f"{label[:50]}.{i:04d}.{EXFIL_DOMAIN}"
    dns.append((t, f'timestamp={t.strftime("%Y-%m-%dT%H:%M:%SZ")} src_ip={host} '
                   f'dst_ip=203.0.113.53 query={qname} qtype=TXT rcode=NXDOMAIN action=ALLOW'))
    fw.append((t, f"{ts(t)} ALLOW UDP {host}:{random.randint(40000, 60000)} -> 203.0.113.53:53"))

# ------------------------------------------------- 7. web attacks on the DMZ
wa = START + timedelta(days=5, hours=9, minutes=14)
attacks = [
    ("GET /products.php?id=9' UNION SELECT null,version()--", "SQL Injection", 942100),
    ("GET /search.php?q=<script>alert('XSS')</script>", "XSS", 941100),
    ("GET /../../../../etc/passwd", "Directory Traversal", 930120),
    ("POST /admin/login.php", "Brute Force", 949110),
]
for i, (req, atype, rid) in enumerate(attacks * 3):
    t = wa + timedelta(seconds=i * 11)
    http.append((t, f'timestamp={t.strftime("%Y-%m-%dT%H:%M:%SZ")} src_ip=198.51.100.45 '
                    f'dst_ip={DMZ_WEB} action=BLOCK request="{req}" rule_id={rid} '
                    f'attack_type="{atype}" bytes_sent=0'))
    ids.append((t, f"{ts(t)} [**] [1:{2003000 + i}:1] ET WEB_SERVER Possible {atype} [**] "
                   f"[Classification: Web Application Attack] [Priority: 1] {{TCP}} "
                   f"198.51.100.45:{20000 + i} -> {DMZ_WEB}:80"))

# ---------------------------------------------------------------- write files
def write(name: str, rows: list[tuple[datetime, str]]) -> None:
    rows.sort(key=lambda r: r[0])
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(r[1] for r in rows) + "\n")
    print(f"  {path:<34} {len(rows):>6,} lines")


print(f"Writing sample dataset to {OUT}/")
write("firewall.log", fw)
write("ids_alerts.log", ids)
write("vpn_auth.log", vpn)
write("dns_logs.log", dns)
write("http_logs.log", http)
print(f"\nRun:  python -m nsmkit.cli analyze {OUT} -v")
