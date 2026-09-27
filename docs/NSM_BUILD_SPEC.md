# Network Security Monitoring — Detection Engineering Build Spec

**Purpose.** A complete, implementation-ready specification for building SOC analysis tooling
over network telemetry. Written to be handed directly to a code-generating model or a developer.
Every rule states its inputs, logic, thresholds, tuning knobs, false-positive sources, MITRE
ATT&CK mapping, and analyst action.

**Scope.** Perimeter monitoring, network discovery/scanning, credential attacks, lateral movement,
C2 beaconing, data exfiltration (DNS/HTTP/FTP/ICMP), man-in-the-middle (ARP/DNS spoofing, SSL
stripping), and IDS/IPS rule authoring with Snort.

**Companion implementation.** `nsmkit/` — a working Python reference implementation of everything
in this document. 22 detectors, 40 passing tests. See §12.

---

## Table of contents

1. [Domain model](#1-domain-model)
2. [Log source catalogue and grammars](#2-log-source-catalogue-and-grammars)
3. [Normalised event schema](#3-normalised-event-schema)
4. [Enrichment functions](#4-enrichment-functions)
5. [Detection rules](#5-detection-rules)
6. [Correlation and the pivot graph](#6-correlation-and-the-pivot-graph)
7. [False-positive management](#7-false-positive-management)
8. [Finding schema and reporting](#8-finding-schema-and-reporting)
9. [Snort / IDS rule authoring](#9-snort--ids-rule-authoring)
10. [Analyst query cookbook](#10-analyst-query-cookbook)
11. [Architecture for a production tool](#11-architecture-for-a-production-tool)
12. [Reference implementation](#12-reference-implementation)

---

## 1. Domain model

### 1.1 Asset classes and why each matters

| Asset | Role | Attacker interest | Primary telemetry |
|---|---|---|---|
| **Workstations / endpoints** | Daily user work | Most common initial foothold (phishing, malicious download) | EDR, Sysmon, Windows Event Log; network logs often show C2 first |
| **File / database servers** | Store the organisation's data | The objective: ransomware target, PII/financial exfil source | File audit (4663/4656), DB audit, SMB flows |
| **Application servers** (web, mail, VPN) | Externally facing services | High-value: internet-reachable, scanned constantly for vulns/weak config | Web/app logs, WAF, firewall, IDS |
| **Active Directory / auth servers** | Identity backbone | Privilege escalation, persistence, lateral movement; one domain admin = whole estate | 4624/4625/4768/4769, LDAP, Kerberos |
| **Routers / switches** | Traffic transport | Traffic interception (MITM), backdoor routes, covert channels | NetFlow/sFlow, syslog, config change audit |
| **Firewalls / perimeter devices** | Gatekeeper between trusted and untrusted | The first thing an attacker meets; its logs are the earliest attack indicator | Connection allow/deny logs |

### 1.2 The perimeter

The boundary between the trusted internal network and the untrusted internet. Components:
firewall, router/gateway, **DMZ** (buffer segment for public-facing servers), VPN/remote-access
gateway, and in modern estates cloud connections and virtual gateways.

Perimeter weakness leads to: exploitation of exposed services (RDP/SSH/SMB/MySQL), reconnaissance
and mapping, brute force against login services, and outbound exfiltration channels.

### 1.3 Two telemetry classes

| | **Host-centric** | **Network-centric** |
|---|---|---|
| Source | OS logs, application logs, AV/EDR/HIDS | Firewall, IDS/IPS, router flow, proxy, VPN |
| Answers | *What happened inside the room* | *Who entered and left the building* |
| Shows | Process creation, logons, file access, service starts | src/dst IP, ports, protocol, action, volume, timing |
| Best for | Impact, root cause, what the malware did | Recon, lateral movement, exfil, C2 |

**Neither is sufficient.** Every high-confidence conclusion in §5 comes from correlating both, or
from correlating two network sources (e.g. firewall ALLOW + IDS signature + VPN auth).

### 1.4 The three signal shapes

The compression of the whole discipline into three lines:

| Shape | Meaning |
|---|---|
| One source → **many destinations**, same port | **Horizontal scan** (service hunting) |
| One source → **one destination**, many ports | **Vertical scan** (host footprinting) / **brute force** (one service) |
| Traffic at **perfect, regular intervals** | **Malware beaconing** |

Add a fourth, from the exfiltration material:

| Shape | Meaning |
|---|---|
| **Sustained outbound volume** exceeding inbound to one external host | **Exfiltration** |

### 1.5 Direction determines severity

The same technical event carries a different severity depending on direction. This is the single
most important severity rule in the spec.

| Direction | Kill chain / ATT&CK phase | Severity | Response |
|---|---|---|---|
| **External → Internal** scan | Reconnaissance (TA0043) | Low | Block source IP at perimeter. Attacker may return from a new IP. |
| **Internal → Internal** scan | Discovery (TA0007) | **High** | Escalate, initiate IR, root-cause the source host. Blocking the IP is insufficient. |

Internal scanning means the attacker already has a foothold. Encode this as a first-class
condition, not an afterthought.

### 1.6 Kill chain ordering (for correlation and narrative)

```
Reconnaissance → Weaponization → Delivery → Exploitation → Initial Access →
Installation → Persistence → Credential Access → Discovery →
Lateral Movement → Collection → Command & Control → Exfiltration → Impact
```

MITM sits at **Exploitation** (it exploits the trust design of ARP/DNS) and **Installation**
(the inline position becomes a delivery mechanism for payloads injected into cleartext downloads).

---

## 2. Log source catalogue and grammars

Each entry gives the exact grammar, a regex, and the fields to extract. Anchor regexes at `^` and
capture named groups. All parsers must return `None` (not raise) on non-matching input, so a
format detector can score them against a sample.

### 2.1 Perimeter firewall (text)

```
2025-08-25 00:47:46 ALLOW TCP 203.0.113.100:62718 -> 10.0.0.50:443
2025-08-26 12:12:47 BLOCK TCP 203.0.113.10:64292 -> 10.0.0.50:21
```

```regex
^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+
(?P<action>ALLOW|BLOCK|DENY|DROP|REJECT|ACCEPT|PERMIT|PASS)\s+
(?P<proto>TCP|UDP|ICMP|GRE|ESP|IP)\s+
(?P<src>\S+?)\s*->\s*(?P<dst>\S+)(?:\s+bytes=(?P<bytes>\d+))?
```

Split `src`/`dst` on the **last** colon (IPv6-safe). Fields: timestamp, action, protocol,
src_ip, src_port, dst_ip, dst_port, bytes.

### 2.2 Snort / Suricata fast alert

Two variants must both parse. ISO timestamp with ports:

```
2025-08-25 00:12:53 [**] [1:2003272:1] ET POLICY Suspicious HTTP [**] [Classification: Suspicious Activity] [Priority: 3] {TCP} 198.51.100.92:20127 -> 10.0.0.20:22
```

Snort-native timestamp, quoted message, no ports:

```
07/24-10:46:52.401504  [**] [1:1000001:1] "Loopback Ping Detected" [**] [Priority: 0] {ICMP} 127.0.0.1 -> 127.0.0.1
```

```regex
^(?P<ts>\S+(?:[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?)\s+
\[\*\*\]\s*\[(?P<sid>[\d:]+)\]\s*(?P<msg>.*?)\s*\[\*\*\]
(?:\s*\[Classification:\s*(?P<cls>[^\]]*)\])?
(?:\s*\[Priority:\s*(?P<pri>\d+)\])?
(?:\s*\{(?P<proto>\w+)\})?
\s*(?P<src>\S+?)\s*->\s*(?P<dst>\S+)\s*$
```

`sid` is `gid:sid:rev`. Strip surrounding quotes from `msg`. Both classification and priority
are optional — a rule with no `classtype` emits neither.

**Priority semantics:** 1 = highest. Do not map priority directly to severity; combine with
direction (§1.5) and whether the traffic was blocked.

### 2.3 VPN authentication

Two variants:

```
2025-08-25 08:27:38 203.0.113.100 svc_backup SUCCESS assigned_ip=10.8.0.131
2025-09-03 02:19:00 203.0.113.10 svc_backup FAIL
```

```regex
^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+
(?P<ip>[0-9a-fA-F\.:]+)\s+(?P<user>\S+)\s+
(?P<result>SUCCESS|FAIL|FAILED|FAILURE|SUCCESS_AUTH|FAILED_AUTH|DENIED)
(?:\s+assigned_ip=(?P<assigned>[0-9a-fA-F\.:]+))?
```

Appliance style with a 5-tuple:

```
2025-09-22 10:12:11 FAILED_AUTH TCP 203.0.113.10:31245 -> 10.0.0.1:443 (user 'admin')
```

```regex
^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+
(?P<result>SUCCESS_AUTH|FAILED_AUTH)\s+(?P<proto>\w+)\s+
(?P<src>\S+?)\s*->\s*(?P<dst>\S+?)\s+\(user\s+'(?P<user>[^']*)'\)
```

> **`assigned_ip` is the most valuable field in the entire dataset.** It is the join key that
> turns a VPN compromise into a lateral-movement investigation. See §6.2.

### 2.4 WAF / key=value

```
timestamp=2025-09-22T09:14:46Z src_ip=203.0.113.9 action=BLOCK request="GET /search.php?q=<script>alert('XSS')</script>" rule_id=941100 attack_type="XSS"
```

```regex
(\w[\w\.\-]*)=("([^"]*)"|'([^']*)'|\S+)
```

Iterate all matches into a dict. Accept these key aliases:

| Canonical | Aliases |
|---|---|
| `src_ip` | `source_ip`, `client_ip`, `srcip` |
| `dst_ip` | `dest_ip`, `destination_ip`, `dstip` |
| `bytes_out` | `bytes_sent`, `bytes`, `sc_bytes` |
| `http_host` | `domain`, `host`, `hostname` |
| `signature` | `attack_type`, `msg`, `rule_name` |

Split `request` into method + URI when the first token is an uppercase HTTP verb.

### 2.5 Zeek `conn` via SIEM CSV export

Kibana exports the Zeek record as a quoted JSON blob inside a `message` column:

```csv
"@timestamp","source.ip","source.port","destination.ip","destination.port","rule.action",message,"event.dataset"
"Sep 7, 2025 @ 17:16:42.944","203.0.113.25",39120,"192.168.230.145",5922,"-","{""ts"":1757265402.944286,""id.orig_h"":""203.0.113.25"",""id.orig_p"":39120,""id.resp_h"":""192.168.230.145"",""id.resp_p"":5922,""proto"":""tcp"",""conn_state"":""S0"",""orig_pkts"":1,""orig_ip_bytes"":44,""resp_pkts"":0,""resp_ip_bytes"":0}","zeek.conn"
```

**Parse the CSV row, then merge the decoded `message` JSON into the row dict** — otherwise you
lose `conn_state`, byte counts and packet counts, which the volume and scan detectors need.

Zeek field mapping:

| Zeek | Canonical |
|---|---|
| `id.orig_h` / `id.orig_p` | src_ip / src_port |
| `id.resp_h` / `id.resp_p` | dst_ip / dst_port |
| `orig_ip_bytes` / `resp_ip_bytes` | bytes_out / bytes_in |
| `orig_pkts` | packets |
| `conn_state` | see below |

**`conn_state` is a scan oracle.** Learn these three:

| State | Meaning | Scan signal |
|---|---|---|
| `S0` | SYN sent, no reply | **Strong.** Filtered/dropped port. Bulk `S0` from one source = scan. |
| `REJ` | Connection rejected (RST) | **Strong.** Closed port answered. |
| `SF` | Normal establish + teardown | Benign — or an open port the scanner found. |
| `RSTO`/`RSTR` | Reset by originator/responder | Weak |
| `SH` | SYN followed by FIN, no SYN-ACK | Stealth scan indicator |

### 2.6 Suricata EVE JSON / generic JSON lines

Flatten nested `alert`, `dns`, `http`, `flow`, `tls` objects one level (`alert.signature` →
also expose as `signature`) before mapping. Field aliases:

```
src_ip     ← src_ip, source.ip, id.orig_h
dst_ip     ← dest_ip, destination.ip, id.resp_h
signature  ← alert.signature, signature, msg
sid        ← alert.signature_id, sid, rule_id
dns_query  ← dns.rrname, query
http_uri   ← http.url, uri, url
bytes_out  ← bytes_toserver, orig_ip_bytes, source.bytes
```

### 2.7 PCAP

Two backends; support both.

**scapy** (pure Python, full detail) — extract per layer:

| Layer | Fields |
|---|---|
| ARP | `op`, `psrc`, `hwsrc`, `pdst`, Ethernet `src`/`dst`; **gratuitous** = `op==2 and (psrc==pdst or eth.dst==ff:ff:ff:ff:ff:ff)` |
| ICMP | `type`, `code`, `len(payload)`, payload bytes (for entropy) |
| DNS | `qd.qname`, `qd.qtype`, `qr` (response flag), `an[0].rdata`, `an[0].ttl`, `rcode` |
| HTTP | request line (method, URI), `Host:` header, body after `\r\n\r\n` |
| FTP | first control-channel token: `USER`, `PASS`, `STOR`, `RETR`, `LIST`, `CWD`, `PASV` + argument |
| TLS | ClientHello SNI (see below) |

**SNI extraction** — walk the structure, do not pattern-match blindly:
```
record: type(1)=0x16  version(2)  length(2)
handshake: type(1)=0x01  length(3)
  client_version(2)  random(32)
  session_id_len(1) + session_id
  cipher_suites_len(2) + suites
  compression_len(1) + methods
  extensions_len(2)
    ext_type(2)==0x0000  ext_len(2)
      list_len(2)  name_type(1)==0x00  name_len(2)  name
```
Keep a byte-scan fallback for reassembled/truncated segments.

**tshark** (faster on large captures):

```bash
tshark -r capture.pcap -T fields -E separator=$'\x01' -E occurrence=f \
  -e frame.time_epoch -e frame.len -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
  -e eth.src -e eth.dst \
  -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 \
  -e arp.isgratuitous -e arp.duplicate-address-detected \
  -e dns.qry.name -e dns.qry.type -e dns.flags.response -e dns.a -e dns.resp.ttl \
  -e icmp.type -e data.len \
  -e http.request.method -e http.request.uri -e http.host -e http.response.code \
  -e ftp.request.command -e ftp.request.arg \
  -e tls.handshake.extensions_server_name
```

Use a non-printable separator (`\x01`) — commas and tabs appear inside URIs and query names.

### 2.8 Timestamp formats to support

```
%Y-%m-%d %H:%M:%S          firewall, VPN
%Y-%m-%dT%H:%M:%SZ         WAF, ISO
%Y-%m-%dT%H:%M:%S.%fZ      ISO with millis
%m/%d-%H:%M:%S.%f          Snort native (no year — infer from file or current year)
%b %d, %Y @ %H:%M:%S.%f    Kibana CSV export
%b %d %H:%M:%S             syslog (no year)
epoch seconds / millis     Zeek ts, frame.time_epoch (>1e11 ⇒ millis)
```

Try `datetime.fromisoformat` first (handles offsets), then the format list, then epoch.

---

## 3. Normalised event schema

Every parser emits this. Detectors never see raw text.

```python
@dataclass
class Event:
    # core
    timestamp: datetime
    kind: EventKind        # network_flow|ids_alert|auth|dns|http|ftp|icmp|arp|tls|other
    action: Action         # allow|block|drop|reset|success|failure|alert|unknown
    source_type: str       # "firewall" | "ids" | "vpn" | "waf" | "pcap" | ...
    raw: str               # original line — evidence in findings

    # 5-tuple
    src_ip, src_port, dst_ip, dst_port, protocol

    # volume
    bytes_out, bytes_in, packets, duration

    # identity
    user, assigned_ip

    # IDS
    signature, sid, classification, priority

    # application
    dns_query, dns_qtype, dns_rcode, dns_answer, dns_ttl, dns_is_response
    http_method, http_uri, http_host, http_status, user_agent
    ftp_command, ftp_arg

    # layer 2
    src_mac, dst_mac
    arp_opcode, arp_sender_ip, arp_sender_mac, arp_target_ip, arp_is_gratuitous
    icmp_type, icmp_payload_len

    extra: dict            # passthrough
```

### 3.1 Action normalisation table

Map vendor verbs to a closed enum in **one** place so onboarding a new appliance is a dict edit:

```
allow ← allow, allowed, accept, permit, pass, SF
block ← block, blocked, deny, denied, reject
drop  ← drop, dropped
success ← success, success_auth, accepted, ok
failure ← fail, failed, failure, failed_auth, invalid
alert ← alert
```

### 3.2 ⚠ IP classification — the trap

**Do not use `ipaddress.is_private`.** Python flags the RFC 5737 documentation ranges as private:

```
192.0.2.0/24     198.51.100.0/24     203.0.113.0/24
```

These are exactly the addresses that training material, sanitised exports and public IOC feeds
use for the **external attacker**. Using `is_private` inverts every direction check, every
severity decision, and silently disables all egress detection.

Define internal explicitly:

```python
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
           "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
           "::1/128", "fc00::/7", "fe80::/10")
```

Then derive:

```
src_is_internal, dst_is_internal
direction ∈ {inbound, outbound, internal, external, unknown}
```

Site-specific `home_nets` from config always wins over the default list.

---

## 4. Enrichment functions

### 4.1 Shannon entropy

```python
def shannon_entropy(s):
    counts = Counter(s); n = len(s)
    return -sum((c/n) * log2(c/n) for c in counts.values())
```

Calibration (bits per character):

| Content | Entropy |
|---|---|
| Repeated characters | < 1.0 |
| English words / normal hostnames | 3.0 – 3.6 |
| Base64 / base32 encoded data | **4.3 – 5.2** |
| Hex | ~4.0 |
| Compressed/encrypted bytes | 7.5 – 8.0 |

Threshold for DNS labels: **≥ 3.8**.

### 4.2 Encoding detection

```
hex     ^[0-9a-fA-F]{16,}$
base32  ^[A-Z2-7=]{16,}$      (all-uppercase check first)
base64  ^[A-Za-z0-9+/=_\-]{16,}$
```

Apply per DNS label, not to the whole qname.

### 4.3 Supporting lexical features (raise confidence, do not fire alone)

| Feature | Signal |
|---|---|
| `digit_ratio ≥ 0.25` | Machine-generated label |
| `longest_consonant_run ≥ 8` | Not a pronounceable word |
| `unique_subdomains / total_queries ≈ 1.0` | No DNS caching benefit — the point of a tunnel |

### 4.4 Registered-domain extraction

Group tunnelling subdomains under one key or per-domain counts are meaningless.
`a.b.c.evil.co.uk → evil.co.uk`. Handle multi-part public suffixes (`co.uk`, `com.au`, `co.jp`…);
use the real Public Suffix List in production.

### 4.5 Periodicity statistics

Given sorted timestamps for a channel, compute gaps, then:

```python
jitter_ratio  = stdev(gaps) / mean(gaps)      # coefficient of variation — sensitive
mad_ratio     = median(|g - median|) / median # robust to dropped beacons
dominant_period = median(gaps) if ≥70% of gaps within ±20% of it else None
size_cv       = stdev(bytes_out) / mean(bytes_out)
```

Calibration:

| jitter_ratio | Interpretation |
|---|---|
| ≈ 0.00 | Perfectly periodic — scripted beacon or cron |
| < 0.15 | Beaconing |
| < 0.35 | Jittered beacon (frameworks randomise ±20–30%) |
| > 0.60 | Human / bursty application traffic |

Use **both** `jitter_ratio` and `mad_ratio`: one long outage destroys the CV but not the MAD.
`size_cv ≤ 0.30` is independent confirmation — implants send near-identical check-ins.

### 4.6 Port semantics

```python
HIGH_RISK_PORTS  = {21,22,23,135,139,445,1433,3306,3389,5432,5900,6379,27017}
                   # exposure at the perimeter is itself a finding
SUSPICIOUS_PORTS = {4444,4445,1337,31337,8081,9001,9002,50050}
                   # default offensive-tooling listeners
LATERAL_PORTS    = {22,135,139,445,3389,5985,5986}
                   # carry lateral movement inside a LAN
```

---

## 5. Detection rules

Each rule: **inputs → grouping → logic → thresholds → severity → FP sources → ATT&CK → action.**

Implement every rule with a **sliding window** over the grouped, time-sorted events (advance a
left pointer until the window fits) and report the *best* window, not a fixed bucket. Fixed
buckets miss activity that straddles a boundary.

---

### NSM-SCAN-001 — Vertical port scan

| | |
|---|---|
| **Input** | firewall / flow / IDS events with `dst_port` |
| **Group by** | `(src_ip, dst_ip)` |
| **Logic** | In any window of `vertical_scan_window_s`, count distinct `dst_port` |
| **Threshold** | ≥ **10** distinct ports / 300 s (external source)<br>≥ **5** distinct ports (internal source — recon inside is quieter) |
| **Severity** | External source: `medium` if block-ratio ≥ 0.60, else `low`. Internal source: **`high`** |
| **Confidence** | `high` if block-ratio ≥ 0.60, else `medium` |
| **ATT&CK** | T1046 (Network Service Discovery); + T1595.001 if external |
| **Stage** | Reconnaissance (external) / Discovery (internal) |

**Block ratio is the primary discriminator.** A busy legitimate client hits many ports but is
*allowed*; a scanner is *denied*. Compute `blocked / total` in the window.

**FP sources:** vulnerability scanners (Nessus/Qualys/Tenable), asset-inventory tools, NMS
polling, load balancers health-checking. → allowlist by source IP.

**Action:** External — block at perimeter, verify no ALLOW entries exist for that source.
Internal — **escalate to IR and isolate the host**; blocking the IP is not a fix.

---

### NSM-SCAN-002 — Horizontal port scan

| | |
|---|---|
| **Group by** | `(src_ip, dst_port)` |
| **Logic** | Distinct `dst_ip` count in window |
| **Threshold** | ≥ **15** hosts / 300 s (external); ≥ **5** (internal) |
| **Severity** | `medium` external, **`high`** internal |
| **ATT&CK** | T1046, T1595.001 |

Horizontal scanning means the attacker has chosen a service and is hunting for anyone running it —
the WannaCry/SMB-445 pattern. **Escalate severity when the port is 445, 3389, 22, or 23**, since
a hit is directly exploitable.

**FP sources:** subnet discovery by monitoring tools, backup agents, SCCM/Intune.

---

### NSM-SCAN-003 — ICMP ping sweep

| | |
|---|---|
| **Input** | events with `protocol == icmp`, `icmp_type == 8` (echo request) or unspecified |
| **Group by** | `src_ip` |
| **Threshold** | ≥ **10** distinct `dst_ip` |
| **Severity** | `low` external, **`high`** internal |
| **ATT&CK** | T1018 (Remote System Discovery) |

Host discovery precedes port scanning. Often blocked at modern perimeters, which is itself why
its *presence* is notable. **FP:** monitoring systems, HA heartbeats.

---

### NSM-PERIM-001 — Internet-exposed high-risk service

| | |
|---|---|
| **Input** | firewall events, `action == ALLOW` |
| **Condition** | `src_ip` external **AND** `dst_ip` internal **AND** `dst_port ∈ HIGH_RISK_PORTS` |
| **Severity** | **`high`** |
| **Confidence** | `high` — it is a configuration fact, not an inference |
| **ATT&CK** | T1133 (External Remote Services), T1190 |

This is the misconfiguration attackers scan for. **One ALLOW is enough** — no threshold. It
should never require a volume trigger.

**Action:** remove the perimeter rule or move the service behind VPN/DMZ; review the host for
prior compromise (assume it was found before you found it).

---

### NSM-CRED-001 — Authentication brute force

| | |
|---|---|
| **Input** | auth events, `action == FAILURE` |
| **Group by** | `src_ip` |
| **Threshold** | ≥ **10** failures / 600 s |
| **Severity** | **`high`** |
| **Confidence** | `high` if ≤ 2 distinct users targeted, else `medium` |
| **ATT&CK** | T1110.001 (Password Guessing) |

Report attempts/minute and the targeted user list. A tight, regular cadence (low jitter on the
failure timestamps) indicates a script rather than a confused user.

**FP sources:** expired service-account passwords, a misconfigured mail client retrying, a user
with a stale cached credential on a phone. → check whether all failures share one user *and* one
source *and* began at a plausible password-change time.

**Always run NSM-CRED-003 next.** A brute force that ends in silence was defeated; one that ends
in SUCCESS is a breach.

---

### NSM-CRED-002 — Password spray

| | |
|---|---|
| **Group by** | `src_ip` |
| **Threshold** | ≥ **8** distinct users **AND** ≤ **3** attempts per user, within 3600 s |
| **Severity** | **`high`** |
| **Confidence** | `high` |
| **ATT&CK** | T1110.003 (Password Spraying) |

**The `max_per_user` ceiling is the definition, not an optimisation.** Spraying is shallow-and-wide
specifically to stay under account-lockout thresholds, so raw volume never trips a brute-force
rule. Deep-and-narrow activity must **not** be classified as a spray — assert this in tests.

**FP sources:** a directory-sync service with stale credentials for many accounts; a decommissioned
app still holding old creds.

---

### NSM-CRED-003 — Successful login after failure burst 🔴

| | |
|---|---|
| **Group by** | `src_ip`, then scan chronologically |
| **Logic** | For each `SUCCESS`, count preceding `FAILURE` events from the same source (same user where known) within 900 s |
| **Threshold** | ≥ **5** preceding failures |
| **Severity** | **`critical`** |
| **Confidence** | `high` |
| **ATT&CK** | T1110, T1078 (Valid Accounts) |

**This is the highest-value rule in the entire spec.** It converts "noise from the internet" into
"confirmed compromise" and it produces the `assigned_ip` pivot key.

Raise confidence further when the account is a service account (`svc_*`) — those should have a
narrow, fixed source set and effectively never fail authentication in bursts.

**Action:** treat as confirmed compromise. Disable the account, revoke sessions, and **pivot on
`assigned_ip`** (§6.2) to scope everything that followed.

---

### NSM-CRED-004 — Anomalous session pattern

| | |
|---|---|
| **Group by** | `user`, `action == SUCCESS` |
| **Threshold** | ≥ 3 distinct source IPs **OR** ≥ 3 off-hours sessions |
| **Severity** | `medium`; **`high`** for service accounts |
| **Confidence** | `low` — supporting signal only |
| **ATT&CK** | T1078 |

Low confidence by design: it exists to *raise the severity* of other findings on the same account,
not to alert alone. Where geo-IP is available, add impossible-travel (two logins from countries
further apart than travel time allows).

---

### NSM-C2-001 — C2 beaconing 🔴

| | |
|---|---|
| **Input** | flow / HTTP / DNS / IDS events, **internal source → external destination** |
| **Group by** | `(src_ip, dst_ip, dst_port)` |
| **Pre-filter** | de-duplicate identical timestamps (one connection logged by two sources) |
| **Minimum** | ≥ 8 events |
| **Logic** | `dominant_period` exists; `jitter_ratio ≤ 0.35` **OR** `mad_ratio ≤ 0.25`; `30 s ≤ period ≤ 86400 s` |

**Scoring** (severity: ≥7 `critical`, ≥5 `high`, else `medium`):

| Condition | Points |
|---|---|
| `jitter_ratio ≤ 0.10` | +3 |
| `jitter_ratio ≤ 0.35` | +2 |
| `mad_ratio ≤ 0.25` | +1 |
| `size_cv ≤ 0.30` (constant payload) | +2 |
| `dst_port ∈ SUSPICIOUS_PORTS` | +3 |
| ≥ 20 connections | +1 |
| IDS signature contains c2/trojan/beacon | +3 |

**ATT&CK:** T1071.001, T1573; + T1571 on a non-standard port.

**FP sources — the real problem with this rule.** Legitimate software beacons constantly:
software-update checks, NTP, telemetry/analytics SDKs, monitoring agents (Datadog, Nagios),
certificate OCSP/CRL, cloud-sync clients, RSS readers. Mitigate by:
1. Excluding destinations on a maintained allowlist of vendor/update domains.
2. Requiring a *supporting* signal for `high`+ (suspicious port, IDS hit, or constant size).
3. Baselining: a beacon to a destination *no other host in the estate contacts* is far more
   interesting than one 400 hosts share.

**Dedup rule:** a proxy export that omits `dst_port` produces a duplicate channel for a pair
already reported with a real port. Drop the port-less finding when a port-bearing one exists
for the same `(src_ip, dst_ip)`.

**Action:** contain the source host, block the destination, add to IOC list, pull EDR
process/network telemetry to identify the implant, and **check which other internal hosts talk
to the same destination**.

---

### NSM-C2-002 — Offensive-tooling port

| | |
|---|---|
| **Condition** | `dst_port ∈ SUSPICIOUS_PORTS` |
| **Severity** | `high` if outbound (internal→external), else `medium` |
| **ATT&CK** | T1571 (Non-Standard Port) |

4444 is the Metasploit default handler; 50050 is the Cobalt Strike team server. Neither has a
legitimate business use in most environments. Cheap rule, high value, near-zero FP rate — but do
confirm no internal application genuinely uses the port before deploying.

---

### NSM-EXFIL-001 — DNS tunnelling 🔴

| | |
|---|---|
| **Input** | DNS events with `dns_query` |
| **Group by** | `registered_domain(dns_query)` |
| **Pre-filter** | drop domains matching the allowlist (§7.2) |

**Feature extraction per domain:**

```
max_qname_len, mean_qname_len       length of the full query name
max_label_len                       longest single label
mean_entropy                        Shannon entropy over subdomain labels ≥8 chars
unique_subdomains                   distinct subdomain parts
encoded_labels                      labels matching base32/base64/hex
qtypes                              set of record types used
nxdomain_ratio                      NXDOMAIN answers / total
no_response_ratio                   queries with no answer / total
internal_hosts                      distinct src_ip querying this domain
mean_consonant_run, digit_ratio     lexical machine-generated signals
```

**Scoring** (fire at ≥ 5; severity ≥10 `critical`, ≥7 `high`, else `medium`):

| Condition | Points |
|---|---|
| `max_qname_len ≥ 60` | +2 |
| `max_label_len ≥ 30` | +2 |
| `mean_entropy ≥ 3.8` | **+3** |
| `queries ≥ 50` to one domain | +2 |
| `unique_subdomains ≥ 25` | +2 |
| `encoded_labels ≥ 3` | +2 |
| ≥3 queries use TXT/NULL/CNAME/MX/ANY | +1 |
| `nxdomain_ratio ≥ 0.50` (with ≥10 queries) | +2 |
| `no_response_ratio ≥ 0.80` | +1 |
| ≥2 internal hosts querying the same domain | +1 |
| `mean_consonant_run ≥ 8` | +1 |
| `digit_ratio ≥ 0.25` | +1 |

**ATT&CK:** T1071.004 (DNS), T1048.003 (Exfiltration Over Unencrypted Protocol).

Estimate volume exfiltrated: `sum(len(subdomain labels)) × 5 / 8` bytes (base32 packs 5 bits per
character).

**Never fire on a single feature.** Length alone matches CDN hostnames; entropy alone matches
hashed cache keys; volume alone matches a busy resolver. Requiring a score means the FP has to
look like a tunnel on several independent axes.

**FP sources:** CDNs with hashed hostnames (Akamai, CloudFront, Fastly), antivirus/reputation
lookup services (which genuinely encode file hashes into DNS — `*.sophosxl.net`,
`*.avts.mcafee.com`), DNS-based load balancing, `in-addr.arpa` reverse lookups, Office 365 and
Azure endpoint discovery.

**Action:** sinkhole/block the domain at the resolver; force all internal DNS through the
corporate resolver and alert on direct `:53` egress; investigate each querying host for the implant.

---

### NSM-EXFIL-002 — DNS to unapproved resolver

| | |
|---|---|
| **Condition** | internal src → external dst on port 53, dst ∉ `known_resolvers` |
| **Threshold** | ≥ 5 queries |
| **Severity** | `medium` |
| **ATT&CK** | T1071.004 |

A precursor rather than an attack: bypassing the corporate resolver defeats DNS logging and
filtering, and is a prerequisite for most DNS tunnelling. It also catches misconfigured hosts,
which is a useful hygiene outcome.

---

### NSM-EXFIL-003 — HTTP POST upload 🔴

| | |
|---|---|
| **Input** | HTTP events with `method == POST`, internal source |
| **Group by** | `(src_ip, http_host or dst_ip)` |
| **Baseline** | median `bytes_out` across **all** POSTs in the dataset |

**Trigger if any:** total ≥ `exfil_min_total_bytes` (50 MB); any single POST ≥
`http_post_large_bytes`; or ≥5 POSTs to one destination with the largest > 10× baseline.

**Scoring** (≥7 `critical`, ≥4 `high`, else `medium`):

| Condition | Points |
|---|---|
| total ≥ 50 MB | +3 |
| largest ≥ 2× the large-POST threshold | +2 |
| ≥ 5 POSTs to the destination | +1 |
| largest > 20× environment baseline | +2 |
| IDS signature mentions exfil / "POST large" | +3 |
| destination is external | +1 |

**ATT&CK:** T1041 (Exfiltration Over C2), T1048.003, T1567.002 (Exfil to Cloud Storage).

**Compute the baseline from the data, do not hardcode it.** A 600-byte POST is enormous in a lab
capture and trivial in production. The comparison that survives across environments is
*largest vs. this environment's median*.

**FP sources:** file-sharing (Dropbox/Drive/OneDrive/Box), CI/CD artefact pushes, backup agents,
log shippers, video-conference uploads, CRM/ERP bulk imports. → maintain
`upload_destination_allowlist`, and prefer *new/rare destination* over raw size.

---

### NSM-EXFIL-004 — Outbound volume anomaly

| | |
|---|---|
| **Group by** | `(src_ip, dst_ip)`, internal → external |
| **Threshold** | `bytes_out ≥ 50 MB` **AND** `bytes_out / bytes_in ≥ 5.0` |
| **Severity** | `high` |
| **ATT&CK** | T1041 |

Protocol-agnostic. Normal client traffic is download-heavy; a sustained inverted ratio to one
external host is the shape of a bulk transfer out — regardless of which protocol carries it.

**FP:** backup-to-cloud, offsite replication, video uploads. → allowlist by destination ASN/domain.

---

### NSM-EXFIL-005 — ICMP tunnelling

| | |
|---|---|
| **Group by** | `(src_ip, dst_ip)`, ICMP only |
| **Baseline** | a normal ping is 32–56 bytes payload (~74 bytes total frame) |
| **Threshold** | ≥3 packets with payload > **64 bytes**, or ≥20 ICMP packets total |

**Scoring** (fire at ≥4; ≥6 `high`, else `medium`):

| Condition | Points |
|---|---|
| max payload > 64 B | +3 |
| max payload > 256 B | +2 |
| ≥ 20 packets | +1 |
| destination external | +2 |
| mean payload entropy ≥ 4.5 (encoded data) | +3 |

**ATT&CK:** T1095 (Non-Application Layer Protocol), T1048.003.

The simplest exfil channel to detect — payload size alone nearly settles it. Also flag unusual
ICMP types (13/14 timestamp) and non-zero codes, which are used to dodge signatures.

**Action:** block ICMP egress to the internet; extract and decode the payloads from PCAP.

---

### NSM-EXFIL-006 — FTP upload

| | |
|---|---|
| **Input** | FTP control-channel events (port 21) |
| **Group by** | `(src_ip, dst_ip)` |
| **Extract** | `STOR` (upload) and `RETR` (download) filenames, `USER`/`PASS` values |
| **Sensitive extensions** | `.csv .xlsx .xls .pdf .doc .docx .sql .db .bak .zip .rar .7z .tar .gz .pst .key .pem` |

**Scoring** (≥7 `critical`, ≥5 `high`, else `medium`):

| Condition | Points |
|---|---|
| any `STOR` | +2 |
| any sensitive filename | +3 |
| external destination | +3 |
| generic account (`anonymous`, `guest`, `ftp`, `test`) | +2 |
| `PASS` observed (cleartext credential on the wire) | +1 |

**ATT&CK:** T1048.003.

FTP's cleartext control channel is an investigative gift: it yields the account used *and* the
exact filenames taken. Reconstruct transferred files from the PCAP data channel (Wireshark →
Follow TCP Stream, or File → Export Objects).

---

### NSM-WEB-001 — Web application attack

| | |
|---|---|
| **Input** | WAF/IDS events whose signature matches SQLi / XSS / traversal / command injection / LFI / RFI |
| **Group by** | `src_ip` |
| **Severity** | `high` if ≥2 distinct attack classes **or** any attack was **not** blocked; else `medium` |
| **ATT&CK** | T1190 (Exploit Public-Facing Application), T1059 |

Multiple distinct attack classes from one source means deliberate, tool-driven probing rather than
a stray scanner hit. **The critical field is `action`:** for any attack that was *not* blocked,
treat the target as potentially compromised and pull its application and OS logs.

---

### NSM-LAT-001 — Lateral movement 🔴

| | |
|---|---|
| **Condition** | source ∈ `home_nets ∪ vpn_pool_nets`, destination ∈ `home_nets`, `dst_port ∈ LATERAL_PORTS` |
| **Group by** | `src_ip` |
| **Threshold** | ≥ **3** distinct internal targets / 3600 s |

**Scoring** (≥8 `critical`, else `high`):

| Condition | Points |
|---|---|
| base | 2 |
| ≥2 distinct lateral ports (SSH+SMB+RDP mix) | +2 |
| source is a **VPN pool address** | **+3** |
| IDS exploit/lateral/brute/psexec signatures present | +3 |
| any connection ALLOWED | +2 |
| ≥5 targets | +1 |

**ATT&CK:** T1021.001 (RDP), T1021.002 (SMB), T1021.004 (SSH), T1210 (Exploitation of Remote Services).

The VPN-pool condition is what elevates this from "an admin is working" to "a remote-access
session is pivoting inward" — and it links straight back to NSM-CRED-003 through the account.

**FP sources:** jump boxes, admin workstations, config-management (Ansible/SCCM/Puppet), backup
agents, vulnerability scanners. → allowlist those sources; note a legitimate jump box usually
shows *one* protocol to *many* hosts consistently, while an attacker mixes protocols during a
short window.

**Action:** isolate the source. Pull Windows Security 4624/4625/4648 and Sysmon from each target
to confirm which sessions succeeded; reset credentials used on those hosts before reuse.

---

### NSM-LAT-002 — Internal exploit attempt

| | |
|---|---|
| **Condition** | IDS alert, signature contains "exploit" or classification contains "unauthorized", **both endpoints internal** |
| **Severity** | **`critical`** |
| **Confidence** | `high` |
| **ATT&CK** | T1210 |

No threshold — one alert is enough. An exploit attempt where both ends are inside the network is
definitionally post-compromise. This is no longer a perimeter problem.

---

### NSM-MITM-001 — ARP spoofing 🔴

| | |
|---|---|
| **Input** | ARP events, `arp_opcode == 2` (reply) |
| **Group by** | `arp_sender_ip` → set of `arp_sender_mac` |
| **Threshold** | ≥ **2** distinct MACs claiming one IP |
| **Severity** | **`critical`** if the IP is the gateway; else `high` |
| **Confidence** | `high` |
| **ATT&CK** | T1557.002 (ARP Cache Poisoning) |

**Attributing the impostor:** the MAC that claimed the IP **earliest and most consistently** is
the legitimate host; later, burstier claimants are suspects. Report both with reply counts and
let the analyst decide — never auto-blame.

ARP has no authentication; any host may assert "x is at y". That design gap is the entire
vulnerability, which is why detection is behavioural rather than protocol-level.

**FP sources:** HA failover (VRRP/HSRP/CARP legitimately move a virtual IP between MACs), DHCP
lease churn, a NIC replacement, virtualisation live-migration. → allowlist known VIPs and their
MAC pairs; require ≥3 alternations for HA-prone addresses.

**Action:** trace the suspect MAC to a switch port and isolate. Deploy **Dynamic ARP Inspection**
with DHCP snooping; add static ARP entries for the gateway on critical hosts. Assume all
cleartext traffic in the window was observed.

---

### NSM-MITM-002 — Gratuitous ARP flood

| | |
|---|---|
| **Input** | ARP events with `arp_is_gratuitous` |
| **Threshold** | ≥ **5** unsolicited replies / 60 s from one MAC |
| **Severity** | `high` |

A poisoned cache ages out, so the attacker must keep re-asserting. The *repetition rate* is the
tell. Gratuitous = `op == 2 AND (sender_ip == target_ip OR eth.dst == ff:ff:ff:ff:ff:ff)`.

---

### NSM-MITM-003 — DNS answer from unapproved responder 🔴

| | |
|---|---|
| **Input** | DNS responses (`dns_is_response == True`) |
| **Condition** | `src_ip ∉ known_resolvers` and not a configured internal resolver |
| **Severity** | **`critical`**, confidence `high` |
| **ATT&CK** | T1557, T1071.004 |

**The single most reliable DNS-spoofing indicator.** A reply from an address that is not a
configured resolver means someone else is answering for your network.

---

### NSM-MITM-004 — Conflicting DNS answers

| | |
|---|---|
| **Group by** | `dns_query` |
| **Condition** | ≥2 distinct `dns_answer` values, with two differing answers within `dns_spoof_race_window_s` (2 s) |
| **Severity** | `high`, confidence `high` |

The legitimate resolver and the forged responder both replying is the classic cache-poisoning
race. **FP:** round-robin/GeoDNS legitimately return different A records — hence the tight race
window rather than a plain "answers differ" test.

---

### NSM-MITM-005 — Suspiciously short DNS TTL

| | |
|---|---|
| **Condition** | `dns_ttl ≤ 60`, ≥3 such answers for one query |
| **Severity** | `medium`, confidence **`low`** |
| **ATT&CK** | T1557, T1568.001 (Fast Flux) |

Attackers use very low TTLs so the poisoned entry expires quickly and they can reassert control.
Legitimate low TTLs exist (failover, CDN steering), so this is a **supporting** indicator that
raises other findings' confidence — never a standalone alert.

---

### NSM-MITM-006 — SSL stripping / TLS downgrade 🔴

| | |
|---|---|
| **Step 1** | Build the set of hosts observed completing TLS (from SNI or `dst_port == 443`) |
| **Step 2** | Find HTTP requests (`dst_port ∈ {80, 8080}`) whose `Host` is in that set |
| **Severity** | **`critical`**, confidence `high` |
| **ATT&CK** | T1557, T1040 (Network Sniffing) |

The asymmetry *is* the definition: the attacker keeps HTTPS to the real server and relays plain
HTTP to the victim. A site never seen doing TLS is not a downgrade — assert this negative in tests.

Supporting indicators: HTTP 301/302 redirects that persistently send an HTTPS request to an HTTP
resource; TLS handshake failures or self-signed certificates for a known-good domain.

**Action:** enforce HSTS with preloading; find the relay host (the IP serving the HTTP) and
correlate with ARP/DNS spoofing findings; rotate every credential submitted during the window.

---

### NSM-MITM-007 — Credentials in cleartext

| | |
|---|---|
| **Condition** | HTTP `POST` over cleartext whose URI/body contains `password`, `passwd`, `pwd`, `user`, `username`, `login`, `token`, `session`, `auth` |
| **Severity** | **`critical`** |
| **ATT&CK** | T1040, T1552.001 |

**Three exclusions are mandatory or this rule is a false-positive engine:**
1. Skip events the WAF **blocked** — that is an inbound attack on you, not your user leaking.
2. Skip events carrying an attack signature/classification.
3. Require the **submitter to be internal** — an external POST to `/admin/login.php` is someone
   attacking you.

---

## 6. Correlation and the pivot graph

Individual findings are alerts. Correlated findings are an **incident**.

### 6.1 Entity-based clustering

Extract pivot entities from each finding: `src_ip`, `dst_ip`, `user`, `entity` (domain/MAC/port
label), plus selected `metrics` keys (`assigned_ip`, `domain`, `destination`, `targets`, `hosts`).
Union-find over shared entities produces incident clusters. Rank incidents by:

1. number of distinct kill-chain stages (a 5-stage chain beats a 20-alert single-stage cluster)
2. maximum severity
3. finding count

Title the incident `"{first_stage} → {last_stage}: {top_finding_title}"`.

### 6.2 The VPN pivot — implement this explicitly

The join no single-log rule can see, and the backbone of the perimeter investigation:

```
VPN log:      external_ip + user + SUCCESS  →  assigned_ip
                                                   │
Firewall log: src_ip == assigned_ip  ─────────────┘  →  internal targets, ports
IDS log:      src_ip == assigned_ip                  →  exploit signatures
```

For each successful auth with an `assigned_ip`, collect all non-auth events where
`src_ip == assigned_ip` and `login_time ≤ ts ≤ login_time + 7 days`, then report:

```json
{
  "user": "svc_backup",
  "external_ip": "203.0.113.10",
  "assigned_ip": "10.8.0.66",
  "login_time": "2025-09-03T02:38:50",
  "post_login_events": 80,
  "internal_targets": ["10.0.0.20", "10.0.0.50", "10.0.0.51", "10.0.0.60", "10.0.0.70"],
  "ports_touched": [22, 445, 3389],
  "ids_signatures": ["ET EXPLOIT Possible MS-SMB Lateral Movement", "..."],
  "suspicious": true
}
```

Mark `suspicious` when IDS signatures exist or target count ≥ `lateral_min_targets`.

### 6.3 Triage statistics (the `sort | uniq -c` pass)

Compute these before any detector — they are what an analyst looks at first and they orient the
whole investigation:

```
top_blocked_sources          who is probing us
top_allowed_sources          who got through
top_auth_failure_sources     who is guessing passwords
top_ids_signatures           what the IDS is most worried about
top_upload_pairs (by bytes)  what is leaving
by_action / by_source_type   sanity check on parsing coverage
```

### 6.4 Reference attack narrative

The chain the toolkit should reconstruct end to end:

```
1. Recon           203.0.113.10 → vertical scan of DMZ, horizontal 445 sweep   [BLOCK-heavy]
2. Exposure        SSH (22) reachable from the internet on the DMZ host        [ALLOW]
3. Credential      118 VPN failures for svc_backup → 1 SUCCESS                 [assigned 10.8.0.66]
4. Lateral         10.8.0.66 → 5 internal hosts on 22/445/3389                 [IDS: SMB exploit]
5. C2              10.0.0.51 → 203.0.113.10:4444 every ~6 h, jitter ~0%        [IDS: TROJAN beacon]
6. Exfiltration    10.0.0.51 → HTTP POST 304 MB out; DNS tunnel, base32, TXT   [IDS: POST large]
```

Every stage links to the next through one shared entity. That is what makes it an incident and
not six alerts.

---

## 7. False-positive management

Three complementary techniques, in the order the SOC material recommends:

1. **Allowlist** known internal and benign external scanners so no alert is raised.
2. **Threat-intelligence gating** — alert only on scanning from known-malicious sources.
3. **Threat intelligence as a severity multiplier, not a gate** (preferred) — keep generic
   behavioural rules firing, and let TI raise severity. Gating alone silently misses novel
   infrastructure.

### 7.1 Config-driven allowlists

```json
{
  "home_nets": ["10.0.0.0/8", "192.168.0.0/16"],
  "dmz_nets": ["10.0.0.48/29"],
  "vpn_pool_nets": ["10.8.0.0/16"],
  "known_resolvers": ["10.0.0.53", "8.8.8.8"],
  "gateway_ips": ["10.0.0.1"],
  "scanner_allowlist": ["10.0.0.240"],
  "external_scanner_allowlist": ["198.51.100.7"],
  "domain_allowlist": ["akamai.net", "cloudfront.net", "windowsupdate.com"],
  "upload_destination_allowlist": ["backup.corp.example"],
  "service_accounts": ["svc_backup", "svc_sql"],
  "business_hours": [8, 18]
}
```

**Every threshold in §5 belongs in this file, not in code.** Tuning an environment must be a
config edit.

### 7.2 Default domain allowlist (DNS rules)

High-entropy by design — these will trip a naive tunnelling rule:

```
in-addr.arpa, ip6.arpa, akamai.net, akamaiedge.net, cloudfront.net,
azure.com, windowsupdate.com, office365.com, trafficmanager.net,
amazonaws.com, googleusercontent.com, spotify.com, dropbox.com,
sophosxl.net, mcafee.com, avts.mcafee.com
```

### 7.3 Baselining

Where a static threshold cannot survive across environments, compute from the data:

| Rule | Baseline |
|---|---|
| HTTP exfil | median `bytes_out` across all POSTs in the window |
| Beaconing | how many hosts contact this destination (a solo destination is far more suspicious) |
| Auth | each account's usual source set and hours |
| Scanning | each source's normal port/host fan-out |

### 7.4 Confidence vs. severity

Keep these **orthogonal**:

- **Severity** = impact if true.
- **Confidence** = probability it is true.

A `critical`/`low-confidence` finding is worth surfacing (analyst decides); a `low`/`high-confidence`
one is worth suppressing in a busy queue. Collapsing them into a single number loses the
distinction that makes a queue triageable.

---

## 8. Finding schema and reporting

```python
@dataclass
class Finding:
    rule_id: str          # "NSM-EXFIL-001" — stable, greppable
    title: str            # one line, includes the key numbers
    severity: str         # info|low|medium|high|critical
    confidence: str       # low|medium|high
    description: str      # WHY this is suspicious, in analyst language
    first_seen, last_seen: datetime
    src_ip, dst_ip, user, entity: str | None
    mitre: list[str]      # ["T1071.004", "T1048.003"]
    kill_chain: str       # stage name from §1.6
    metrics: dict         # every number used in the decision — this is the audit trail
    evidence: list[str]   # raw log lines, capped at ~10
    recommendation: str   # what the analyst does next
```

**`metrics` is not optional.** A finding whose numbers are not reproducible cannot be tuned,
disputed, or trusted. Include every threshold input, not just the ones that fired.

**Write descriptions that teach.** "80 connections at a near-constant interval of 10799 s
(jitter 0.2%) — traffic at perfect, regular intervals is malware check-in, not human browsing"
is worth more to an L1 analyst than "beaconing detected".

Output formats to implement: **console** (colour-coded severity, one block per finding),
**JSON** (SIEM ingest), **Markdown** (ticket/report), **HTML** (self-contained, theme-aware,
severity tiles + incident chains).

---

## 9. Snort / IDS rule authoring

### 9.1 IDS vs IPS

| | IDS | IPS |
|---|---|---|
| Posture | Passive — detects and alerts | Active — detects and blocks |
| On match | Generates an alert; a human acts | Terminates/drops the connection |
| Placement | Out of band (SPAN/TAP) | Inline |
| Deployment types | HIDS, NIDS | HIPS, NIPS, WIPS, NBA (behaviour-based) |

Detection techniques: **signature-based** (known patterns; fast, blind to zero-days),
**behaviour/anomaly-based** (needs a clean training baseline; catches novel attacks; more FPs),
**policy-based** (compares against configuration and security policy), and **hybrid**.

> A behaviour-based system trained during an active breach learns the breach as normal. The
> training period is a security-critical window.

### 9.2 Snort modes

| Mode | Flags | Use |
|---|---|---|
| Sniffer | `-v` `-d` `-e` `-X` | Read/display packets; troubleshooting |
| Packet logger | `-l <dir>` `-K ASCII` | Log to disk for later forensics |
| NIDS/NIPS | `-c <config>` `-A <alertmode>` | Apply rules, alert or drop |
| PCAP read | `-r file` / `--pcap-list=""` / `--pcap-show` | Historical/forensic analysis |

Sniffer flags: `-v` verbose TCP/IP, `-d` payload, `-e` link-layer headers, `-X` full hex,
`-i` interface, `-q` quiet (suppress banner).

Logger: `-l` output dir (default `/var/log/snort`); default output is **binary/tcpdump**
(readable by Snort `-r`, tcpdump, Wireshark); `-K ASCII` writes human-readable per-host
directories but is **not** re-readable by Snort `-r`. `-n` limits packets processed.

> Snort needs root to sniff, so logs are root-owned. `sudo chown -R user dir` before analysis.

Alert modes (`-A`): `console` (fast style to screen), `cmg` (headers + hex/ASCII payload),
`fast` (timestamp, message, IPs/ports — file only), `full` (all detail — file only),
`none` (no alert file; still logs packets).

Other NIDS flags: `-T` test configuration, `-N` disable logging, `-D` daemon/background.

IPS mode: `-Q --daq afpacket -i eth0:eth1` (requires two interfaces). DAQ modules: `pcap`
(default/sniffer), `afpacket` (inline/IPS), `ipq`, `nfq`, `ipfw`, `dump`.

### 9.3 Rule structure

```
<action> <protocol> <src_ip> <src_port> <direction> <dst_ip> <dst_port> ( <options> )
```

```
alert icmp any any -> $HOME_NET any (msg:"Ping Detected"; sid:1000001; rev:1;)
```

**Actions:** `alert` (alert + log), `log`, `drop` (block + log), `reject` (block + log +
terminate session).

**Protocols (Snort 2):** only `ip`, `tcp`, `udp`, `icmp`. Application protocols are matched via
port + content (FTP = tcp port 21, not an `ftp` keyword).

**Direction:** `->` source-to-destination, `<>` bidirectional. **There is no `<-` operator.**

**IP/port syntax:**

```
192.168.1.56              single host
192.168.1.0/24            CIDR
[192.168.1.0/24, 10.1.1.0/24]   list
!192.168.1.0/24           negation
21                        single port
1:1024                    range
:1024                     0–1024
1025:                     1025 and above
[21,23]                   list
```

**SID ranges — mandatory:**

| Range | Owner |
|---|---|
| `< 100` | Reserved |
| `100 – 999,999` | Shipped with the build |
| `≥ 1,000,000` | **Locally authored** |

SIDs must be unique. `rev:` increments on every edit; Snort keeps no rule history, so version
control is on you.

### 9.4 Rule options

**General:** `msg` (alert text), `sid`, `rev`, `reference` (e.g. `reference:cve,CVE-2021-44228`),
`classtype`, `priority`.

**Payload:** `content:"GET"` (ASCII) or `content:"|47 45 54|"` (hex) — case-sensitive by default;
`nocase` disables it; `fast_pattern` selects which `content` drives the initial match (**required
when using multiple `content` options**); plus `depth`, `offset`, `distance`, `within`, `pcre`.

**Non-payload:** `flags:S` (TCP flags — F,S,R,P,A,U), `dsize:100<>300` / `dsize:>100`,
`id:` (IP ID field), `ttl:`, `sameip` (src == dst), `itype`/`icode` (ICMP).

**Rate limiting — essential for behavioural rules:**

```
threshold:type threshold, track by_src, count 20, seconds 60;   # alert every N in window
threshold:type limit,     track by_src, count 1,  seconds 300;  # at most 1 alert per window
detection_filter:track by_src, count 15, seconds 60;            # only alert after N events
```

### 9.5 Rule library

```snort
# --- Reconnaissance ---
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL ICMP sweep";
  itype:8; threshold:type threshold, track by_src, count 10, seconds 60;
  classtype:attempted-recon; sid:1000001; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Horizontal scan";
  flags:S; threshold:type threshold, track by_src, count 20, seconds 60;
  classtype:attempted-recon; sid:1000002; rev:1;)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Vertical scan";
  flags:S; detection_filter:track by_src, count 15, seconds 60;
  classtype:attempted-recon; sid:1000003; rev:1;)

# --- Exposed services ---
alert tcp $EXTERNAL_NET any -> $HOME_NET [22,23,445,3389,1433,3306] (
  msg:"LOCAL Inbound to high-risk management port"; flags:S;
  threshold:type limit, track by_src, count 1, seconds 300;
  classtype:attempted-admin; priority:1; sid:1000004; rev:1;)

# --- Credential access ---
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"LOCAL VPN brute force";
  flags:PA; threshold:type threshold, track by_src, count 10, seconds 60;
  classtype:attempted-user; sid:1000005; rev:1;)

# --- C2 ---
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"LOCAL Egress to Metasploit default port";
  flags:S; classtype:trojan-activity; priority:1; sid:1000006; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 50050 (msg:"LOCAL Cobalt Strike team server port";
  flags:S; classtype:trojan-activity; priority:1; sid:1000007; rev:1;)

# --- Exfiltration ---
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Oversized ICMP - possible tunnel";
  itype:8; dsize:>100; classtype:policy-violation; sid:1000008; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"LOCAL Oversized DNS query - possible tunnelling";
  dsize:>150; threshold:type threshold, track by_src, count 20, seconds 60;
  classtype:policy-violation; priority:2; sid:1000009; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"LOCAL FTP STOR to external host";
  content:"STOR"; nocase; depth:4; classtype:policy-violation; sid:1000010; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Large HTTP POST upload";
  content:"POST"; http_method; dsize:>10000;
  threshold:type threshold, track by_src, count 5, seconds 300;
  classtype:policy-violation; sid:1000011; rev:1;)

# --- IOC-pinned (generated from findings) ---
alert ip $HOME_NET any -> 203.0.113.10 any (msg:"LOCAL Known C2 destination";
  metadata:source nsmkit; classtype:trojan-activity; priority:1; sid:1000012; rev:1;)
```

**ARP/MITM cannot be expressed in Snort rules.** Use the preprocessor:

```
preprocessor arpspoof
preprocessor arpspoof_detect_host: 192.168.10.1 02:aa:bb:cc:00:01
```

(Snort 3: the `arp_spoof` inspector, configured with the authoritative host/MAC list.)

### 9.6 Configuration reference

| File | Purpose |
|---|---|
| `snort.conf` (Snort 2) / `snort.lua` (Snort 3) | Main configuration |
| `local.rules` | User-authored rules (`$RULE_PATH/local.rules`) |

Snort 3 has no fixed config path (source builds commonly use `/usr/local/etc/snort`); always
pass it with `-c`.

Key `snort.conf` sections:

- **Step 1 — network variables:** `HOME_NET` (what you protect), `EXTERNAL_NET`
  (`any` or `!$HOME_NET`), `RULE_PATH`, `SO_RULE_PATH`, `PREPROC_RULE_PATH`
- **Step 2 — decoder:** `config daq: afpacket`, `config daq_mode: inline`, `config logdir`
- **Step 6 — output plugins:** alert/log destinations (syslog, unified2, database)
- **Step 7 — ruleset:** `include $RULE_PATH/local.rules` (uncomment to activate; `#` comments)

Rule feeds: **Community** (free, GPLv2, no registration), **Registered** (free, registration,
subscriber rules on a 30-day delay), **Subscriber** (paid, updated twice weekly).

### 9.7 Operational discipline

- Validate before deploying: `snort -c /etc/snort/snort.conf -T`
- Build rules incrementally — add one option at a time so syntax errors are localisable
- Back up configuration before editing; never delete a working rule, comment it out
- Test in a lab against a representative PCAP before production
- Do not reinvent: modify an existing community rule where one nearly fits

---

## 10. Analyst query cookbook

### 10.1 Command line (the manual pass)

```bash
# Orientation
head -n 20 firewall.log
wc -l *.log

# Who is generating the most blocks? (the first question, always)
grep "BLOCK" firewall.log | cut -d' ' -f5 | cut -d: -f1 | sort | uniq -c | sort -rn | head

# Did that source ever get through?
grep "203.0.113.10" firewall.log | grep "ALLOW"

# Which ports did it probe?
grep "203.0.113.10" firewall.log | grep BLOCK | awk '{print $7}' | cut -d: -f2 | sort -n | uniq -c

# Auth failures by source
grep FAIL vpn_auth.log | awk '{print $3}' | sort | uniq -c | sort -rn

# The full story for one source: failures then success
grep "203.0.113.10" vpn_auth.log

# THE PIVOT — what did the assigned address do next?
grep "10.8.0.66" firewall.log | grep ALLOW | head -30
grep "10.8.0.66" ids_alerts.log | head -30

# IDS signature frequency
cut -d']' -f4 ids_alerts.log | sort | uniq -c | sort -rn | head -20

# Beaconing candidates: connections to one destination, look at the gaps
grep "203.0.113.10:4444" firewall.log | awk '{print $1, $2}'

# Exfil: outbound pairs by frequency
grep ALLOW firewall.log | awk '{print $5, $7}' | sed 's/:[0-9]*//g' | sort | uniq -c | sort -rn | head
```

### 10.2 Wireshark display filters

```
# --- ARP / MITM ---
arp                                              all ARP
arp.opcode == 1                                  requests (who-has)
arp.opcode == 2                                  replies (is-at)
arp.isgratuitous                                 unsolicited replies
arp.duplicate-address-detected || arp.duplicate-address-frame    conflicting bindings
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1            who claims the gateway
arp.opcode == 2 && _ws.col.info contains "192.168.10.1 is at"    same, via the info column

# --- DNS ---
dns
dns.flags.response == 0                          queries only
dns.flags.response == 1                          responses only
dns && frame.len > 70                            long queries — tunnelling candidate
dns && dns.qry.name contains "suspicious-domain"
dns.flags.response == 1 && ip.src != 8.8.8.8     answers NOT from the approved resolver ← spoofing
dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
dns.qry.type == 16                               TXT records
dns.resp.ttl < 60                                suspiciously short TTL

# --- HTTP ---
http
http.request.method == "POST"
http.request.method == "POST" && frame.len > 750    large uploads
http contains "password"
http.response.code == 302                        redirect (SSL-strip supporting signal)

# --- TLS / SSL stripping ---
tls || ssl
tls.handshake.type == 1                          ClientHello
tls.handshake.extensions_server_name == "corp-login.acme-corp.local"
http && ip.src == <victim> && ip.dst == <attacker>    cleartext after the strip

# --- ICMP ---
icmp
icmp.type == 8                                   echo requests
icmp.type == 8 && frame.len > 100                oversized — tunnelling
data.len > 64                                    payload larger than a normal ping

# --- FTP ---
ftp || ftp-data
ftp.request.command == "USER" || ftp.request.command == "PASS"
ftp contains "STOR"
ftp contains "csv"
ftp && frame.len > 90

# --- Scanning ---
tcp.flags.syn == 1 && tcp.flags.ack == 0         SYN scan
tcp.flags == 0x014                               RST-ACK (closed port replies)
```

Press **Ctrl+Alt+1** to switch to absolute time display. Right-click a packet → **Follow → TCP
Stream** to reconstruct a session; **File → Export Objects** to pull transferred files.

### 10.3 Splunk SPL

```spl
index=network_logs sourcetype=firewall action=BLOCK
| stats count dc(dest_port) as ports dc(dest_ip) as hosts by src_ip
| where ports > 10 OR hosts > 15
| sort -count

index=network_logs sourcetype=vpn_auth action=FAIL
| stats count dc(user) as users values(user) as user_list by src_ip
| where count > 10
| sort -count

index=data_exfil sourcetype=DNS_logs
| eval qlen=len(query)
| where qlen > 60
| stats count avg(qlen) as avg_len max(qlen) as max_len dc(query) as unique_q by domain
| where count > 50
| sort -count

index=data_exfil sourcetype=http_logs method=POST
| stats count avg(bytes_sent) max(bytes_sent) sum(bytes_sent) as total by src_ip, domain
| where total > 50000000
| sort -total

# Beaconing: streamstats on inter-arrival gaps
index=network_logs dest_ip=203.0.113.10
| sort 0 _time
| streamstats current=f last(_time) as prev by src_ip, dest_ip, dest_port
| eval gap = _time - prev
| stats count avg(gap) as mean_gap stdev(gap) as sd_gap by src_ip, dest_ip, dest_port
| eval jitter = sd_gap / mean_gap
| where count > 8 AND jitter < 0.35
| sort jitter
```

### 10.4 Elastic / Kibana

Data View → **Discover** → set **Search entire time range**. Add fields as columns with `+`;
use the magnifier controls on a value to filter for or out. Useful KQL:

```
source.ip: "203.0.113.10" and rule.action: "BLOCK"
destination.port: (22 or 23 or 445 or 3389) and not source.ip: 10.0.0.0/8
zeek.conn.conn_state: "S0"                     # SYN with no reply — scan
dns.question.name: *  and dns.question.type: "TXT"
```

---

## 11. Architecture for a production tool

```
   ┌──────────┐   ┌───────────┐   ┌────────┐   ┌─────────┐   ┌────────┐
   │ PARSERS  │──▶│ NORMALISE │──▶│ ENRICH │──▶│ DETECT  │──▶│ REPORT │
   └──────────┘   └───────────┘   └────────┘   └────┬────┘   └────────┘
    regex/CSV/      Event           entropy,        │  Finding    console
    JSON/pcap       schema          periodicity,    ▼             json/md/html
                                    geo, TI    ┌───────────┐
                                               │ CORRELATE │──▶ Incident
                                               └───────────┘
```

**Design rules that matter:**

1. **One normalised schema.** Detectors must never parse text. Adding a log source is a parser
   plus a registry entry, nothing else.
2. **Config-driven thresholds.** Every number from §5 in a JSON profile.
3. **Detector registry with a decorator.** `@register` on the class; the runner iterates.
   Adding a rule is one file, zero wiring.
4. **Isolate detector failures.** Wrap each `detector.run()` in try/except — one broken rule
   must not abort the analysis.
5. **Sliding windows, not fixed buckets.** Report the best window per group.
6. **Score, don't gate.** For the noisy domains (DNS tunnelling, beaconing, HTTP exfil), sum
   weighted features and threshold the score. Single-feature gates are how you get a rule that
   either misses everything or alerts on everything.
7. **Streaming path:** the same detectors run over a sliding window buffer (keep the last
   *N* hours of events in memory, re-run on each tick, de-duplicate findings by
   `(rule_id, src_ip, dst_ip, entity)`).
8. **Exit codes for CI/automation:** non-zero when any `high`/`critical` finding exists.

**Extension points to leave open:** threat-intel enrichment (IP/domain reputation → severity
multiplier), geo-IP (impossible travel), asset criticality (a finding on a domain controller
outranks the same finding on a print server), TLS JA3/JA4 fingerprinting, host-log correlation
(Sysmon 1/3/11, Windows 4624/4625/4648/4663), and ATT&CK Navigator layer export.

---

## 12. Reference implementation

```
nsmkit/
├── __init__.py       analyze() one-call pipeline; run_detectors()
├── models.py         Event, Finding, Action/EventKind enums, IP classification
├── parsers.py        firewall/IDS/VPN/kv/JSON/CSV grammars + format auto-detection
├── pcap.py           scapy and tshark backends; SNI extraction
├── enrich.py         entropy, encoding, domains, periodicity, port maps
├── config.py         every threshold and allowlist
├── correlate.py      entity clustering, VPN pivot, triage statistics
├── report.py         console / JSON / Markdown / HTML renderers
├── snortgen.py       findings → Snort rules
├── cli.py            analyze | parse | stats | pivot | rules | snort
└── detectors/
    ├── base.py         Detector ABC + @register
    ├── scanning.py     SCAN-001..003, PERIM-001
    ├── bruteforce.py   CRED-001..004
    ├── beaconing.py    C2-001..002
    ├── exfiltration.py EXFIL-001..006, WEB-001
    ├── lateral.py      LAT-001..002
    └── mitm.py         MITM-001..007
```

```bash
python make_samples.py samples          # synthetic incident dataset
python make_pcap.py samples/mitm.pcap   # synthetic MITM capture (needs scapy)
python tests/test_nsmkit.py             # 40 tests, positive AND negative cases

python -m nsmkit.cli analyze samples/ -v
python -m nsmkit.cli analyze samples/ -f html -o report.html
python -m nsmkit.cli analyze samples/ -f json -o findings.json
python -m nsmkit.cli snort findings.json > local.rules
python -m nsmkit.cli pivot samples/
python -m nsmkit.cli stats samples/
python -m nsmkit.cli rules --show-thresholds
```

```python
from nsmkit import analyze, Config

cfg = Config(home_nets=["10.0.0.0/8"], vpn_pool_nets=["10.8.0.0/16"],
             gateway_ips=["10.0.0.1"], known_resolvers=["10.0.0.53"])
r = analyze(["firewall.log", "ids_alerts.log", "vpn_auth.log"], cfg)

for f in r["findings"]:
    print(f.severity, f.rule_id, f.title)
for inc in r["incidents"]:
    print(inc.incident_id, " → ".join(inc.stages))
```

**Validation status:** all 22 detectors fire on the reference incident dataset and reconstruct
the full six-stage chain of §6.4; all 40 tests pass, including a negative case for every rule
that could plausibly over-fire.

---

## Appendix A — ATT&CK coverage

| Technique | ID | Rules |
|---|---|---|
| Active Scanning | T1595.001 | SCAN-001, SCAN-002 |
| Network Service Discovery | T1046 | SCAN-001, SCAN-002 |
| Remote System Discovery | T1018 | SCAN-003 |
| External Remote Services | T1133 | PERIM-001 |
| Exploit Public-Facing Application | T1190 | PERIM-001, WEB-001 |
| Brute Force: Password Guessing | T1110.001 | CRED-001 |
| Brute Force: Password Spraying | T1110.003 | CRED-002 |
| Valid Accounts | T1078 | CRED-003, CRED-004 |
| Remote Services: RDP / SMB / SSH | T1021.001/.002/.004 | LAT-001 |
| Exploitation of Remote Services | T1210 | LAT-001, LAT-002 |
| App Layer Protocol: Web | T1071.001 | C2-001 |
| App Layer Protocol: DNS | T1071.004 | EXFIL-001, EXFIL-002, MITM-003 |
| Non-Standard Port | T1571 | C2-002, C2-001 |
| Non-Application Layer Protocol | T1095 | EXFIL-005 |
| Encrypted Channel | T1573 | C2-001 |
| Exfiltration Over C2 Channel | T1041 | EXFIL-003, EXFIL-004 |
| Exfil Over Unencrypted Protocol | T1048.003 | EXFIL-001, EXFIL-005, EXFIL-006 |
| Exfil to Cloud Storage | T1567.002 | EXFIL-003 |
| Adversary-in-the-Middle | T1557 | MITM-003..007 |
| AiTM: ARP Cache Poisoning | T1557.002 | MITM-001, MITM-002 |
| Network Sniffing | T1040 | MITM-006, MITM-007 |
| Unsecured Credentials in Files | T1552.001 | MITM-007 |
| Dynamic Resolution: Fast Flux | T1568.001 | MITM-005 |

## Appendix B — Threshold quick reference

| Parameter | Default | Rules |
|---|---|---|
| `vertical_scan_min_ports` | 10 (external) / 5 (internal) | SCAN-001 |
| `horizontal_scan_min_hosts` | 15 (external) / 5 (internal) | SCAN-002 |
| `scan_block_ratio` | 0.60 | SCAN-001, SCAN-002 |
| `ping_sweep_min_hosts` | 10 | SCAN-003 |
| `bruteforce_min_failures` / window | 10 / 600 s | CRED-001 |
| `spray_min_users` / `spray_max_attempts_per_user` | 8 / 3 | CRED-002 |
| `success_after_failures` / window | 5 / 900 s | CRED-003 |
| `beacon_min_events` | 8 | C2-001 |
| `beacon_max_jitter` / `beacon_max_mad_ratio` | 0.35 / 0.25 | C2-001 |
| `beacon_min_period_s` / `max` | 30 s / 86400 s | C2-001 |
| `beacon_size_cv_max` | 0.30 | C2-001 |
| `dns_min_qname_len` / `dns_min_label_len` | 60 / 30 | EXFIL-001 |
| `dns_min_entropy` | 3.8 | EXFIL-001 |
| `dns_min_queries_per_domain` | 50 | EXFIL-001 |
| `dns_min_unique_subdomains` | 25 | EXFIL-001 |
| `dns_nxdomain_ratio` | 0.50 | EXFIL-001 |
| `exfil_min_total_bytes` / window | 50 MB / 3600 s | EXFIL-003, EXFIL-004 |
| `exfil_out_in_ratio` | 5.0 | EXFIL-004 |
| `icmp_payload_suspicious_bytes` | 64 | EXFIL-005 |
| `ftp_stor_min_transfers` | 3 | EXFIL-006 |
| `lateral_min_targets` / window | 3 / 3600 s | LAT-001 |
| `arp_min_conflicting_macs` | 2 | MITM-001 |
| `arp_gratuitous_burst` / window | 5 / 60 s | MITM-002 |
| `dns_spoof_ttl_max` | 60 s | MITM-005 |
| `dns_spoof_race_window_s` | 2.0 s | MITM-004 |
