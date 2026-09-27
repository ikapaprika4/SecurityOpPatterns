# trafkit — packet-native traffic analysis toolkit

Reads pcap/pcapng captures directly and reimplements the Wireshark +
NetworkMiner analyst workflow — display filters, Statistics overview, host
identification, scan/ARP/tunnelling/credential detection, ACL generation —
as a scriptable, testable library instead of a GUI you click through by
hand.

**`docs/TRAFFIC_ANALYSIS_BUILD_SPEC.md` is the implementation spec** —
packet field reference, the display-filter grammar, every detector's logic
and thresholds, host/OS fingerprinting methodology, and ten numbered
implementation traps found while building this (scapy link-type
registration timing, a port-80 HTTP auto-bind that silently breaks payload
extraction, ICMP error sub-packet classes, and more). Hand that file to a
coding model to build from, or read it as the reference; `trafkit/` is the
working implementation of it.

Companion to **nsmkit** (log-driven network security monitoring — firewall/
IDS/VPN/WAF text logs) and **phishkit** (email/phishing analysis). Where
nsmkit reads what a log line recorded, trafkit reads the packet itself.

## Install

Nothing to install: run from the `soc-workbench` folder (or `pip install -e .` there for the
`trafkit` command). Python 3.10+, no dependencies — captures are read by the native
`soccore.pcap` reader (pcap/pcapng, gzip, IPv4 + IPv6, VLAN/SLL/raw-IP links), which
replaced scapy as the default and reads about 28× faster. scapy is still supported as an
opt-in backend (`TRAFKIT_BACKEND=scapy`), kept for the field-by-field comparison in
`tools/compare_pcap_backends.py`. No tshark, no Wireshark install required.

## Quick start

```bash
python -m trafkit overview samples/trafkit/arp_spoof.pcapng
python -m trafkit analyze samples/trafkit/nmap_connect.pcapng -v
python -m trafkit filter samples/trafkit/nmap_syn.pcapng \
    'tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024'
python tools/make_traf_pcaps.py         # regenerate the 13 synthetic captures (needs scapy)
```

A truncated or damaged capture is read up to the damage and reported on
stderr ("warning: the capture is damaged ...") rather than silently
analysed as if it were complete.

## Commands

| Command | Purpose |
|---|---|
| `trafkit overview <pcap>` | Quick triage: summary, protocol hierarchy, top hosts, resolved addresses |
| `trafkit hosts <pcap>` | Host inventory: IP/MAC, OS guess, open ports, traffic volume |
| `trafkit filter <pcap> <expr>` | Apply a Wireshark-style display filter |
| `trafkit analyze <pcap>` | Run every detector, report (`-f console\|json\|markdown\|html`) |
| `trafkit dns <pcap>` / `http <pcap>` | Protocol statistics |
| `trafkit creds <pcap>` | Extract cleartext credentials (FTP, HTTP Basic/form) |
| `trafkit files <pcap>` | Extracted file metadata (name/type/endpoints — see scope note below) |
| `trafkit identify <pcap>` | DHCP/NBNS/Kerberos host & user identification |
| `trafkit keywords <pcap> <words...>` | Keyword search across every text field |
| `trafkit acl <pcap> --target iptables\|cisco_ios\|pf\|netsh` | Generate firewall ACL rules from findings |
| `trafkit rules` | List every detection rule |

Exit code is 1 when any finding reaches high/critical severity.

## What it detects

**Scanning** — TCP Connect vs. SYN scan fingerprinting (by completed
handshake + window size), horizontal host sweeps, UDP scans (via ICMP
port-unreachable).

**ARP / MITM** — conflicting IP-to-MAC claims (spoofing), ARP request
floods, and the MITM relay pattern itself: traffic addressed at the link
layer to a spoofing host while still IP-addressed to the real target.

**Host identification** — DHCP hostname claims correctly attributed to the
*assigned* IP (not the `0.0.0.0` the DISCOVER was sent from), NBNS names,
Kerberos principal/realm extraction (with a schema-free fallback when full
ASN.1 dissection isn't available), DHCP starvation and NAK-burst signals.

**Tunnelling** — oversized ICMP echo payloads, DNS queries scored on
length/entropy/encoding-likelihood/digit-density rather than any single
signal.

**Cleartext protocols** — FTP brute force and password spray (kept as
distinct patterns on purpose — one password against many accounts evades a
per-account lockout that many-passwords-one-account would trip),
credential harvesting (FTP, HTTP Basic-Auth, form POSTs).

**HTTP** — known scanner/audit-tool user agents, user-agent inconsistency,
the Log4Shell JNDI exploitation pattern across four request/response
fields.

**TLS** — ClientHello/ServerHello + SNI extraction, and a full handshake
riding on a port nobody expects TLS on (a common way to hide a C2 channel).

## The display filter engine

Wireshark syntax, not a lookalike: `==`/`!=`/`>`/`<`/`>=`/`<=` and their
English spellings (`eq`/`ne`/`gt`/`lt`/`ge`/`le`), `and`/`or`/`not` and
`&&`/`||`/`!`, `contains`, `matches` (regex), `in {80 443 8080}`,
`upper()`/`lower()`/`string()`, bare presence tests (`tcp`, `http.request`),
CIDR membership (`ip.addr == 10.10.10.0/24`), and the direction-blind
aliases (`ip.addr`, `tcp.port`, `udp.port`) that match either endpoint —
including that alias's well-known `!=` quirk, kept faithful to real
Wireshark rather than "fixed" away. See §3 of the build spec for the full
grammar.

## Extending

**A new detector** — subclass `Detector` in the relevant `detectors/*.py`
module, decorate with `@register`, return `Finding` objects from `.run()`.
Give it a rule ID in the existing scheme, evidence that names the
*offending* host under a key ACL generation already recognises (`src`,
`prober`, or `client` — see `aclgen.py`), and a recommendation.

**A new packet field** — add extraction logic to the relevant dissector in
`soccore/pcap.py` (the native reader; the scapy backend's `_apply_*`
functions in `pcapread.py` only matter for the comparison tool), using the
Wireshark field name so the filter engine and any detector can read it with
no further plumbing.

**A new ACL target** — add a branch to `aclgen.generate_acl()` and the name
to `SUPPORTED_TARGETS`.

## Tests

```bash
python tests/test_trafkit.py     # or, for every toolkit at once: python run_tests.py
```

65 tests: filter DSL, field extraction per protocol, host inventory/OS
fingerprinting, statistics, one positive case per detector rule, a shared
clean-baseline capture that must trigger **zero** findings across every
detector at once, credential/file/keyword extraction, and ACL generation
(including an explicit "never generates a rule blocking the victim" check).

## Three things worth knowing

**File extraction is metadata, not recovered bytes.** trafkit works
packet-by-packet rather than doing full TCP stream reassembly, so `files`
tells you a transfer happened and what it claimed to be — not the
reassembled file NetworkMiner would carve to disk. Real byte-for-byte
carving needs a stream reassembler, a project of its own.

**A user agent is not authentication.** `HTTP-UA-01` matching a known
scanner string is a lead, not a verdict — it's trivially forged, and the
finding's own recommendation text says so.

**ACL generation only ever names the attacker, never the victim** — and
for ARP/MITM findings that only identify the attacker by MAC address (no
IP worth blocking), it correctly generates nothing at all. That's a real
limit of IP-based ACLs against link-layer spoofing, not a bug.
