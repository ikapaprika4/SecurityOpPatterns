# trafkit — Packet-Native Traffic Analysis: Build Specification

Companion spec to `NSM_BUILD_SPEC.md` (log-driven network security monitoring)
and `PHISHING_BUILD_SPEC.md` (email/phishing analysis). Where nsmkit reads
firewall/IDS/VPN/WAF log lines, trafkit reads the packets themselves,
reimplementing the analyst workflow taught across TryHackMe's Network Traffic
Analysis, Wireshark (Basics / Packet Operations / Traffic Analysis), and
NetworkMiner rooms as a scriptable, testable Python library instead of a GUI
you click through by hand. Hand this file to a coding model to build from, or
read it as the reference; `trafkit/` is the working implementation of it.

This spec assumes the reader already has `NSM_BUILD_SPEC.md` — it does not
re-derive shared concepts (severity/confidence axes, the sliding-window
aggregation pattern, config-driven thresholds, the Detector/`@register`
pattern) except where trafkit's packet-native model changes them.

---

## 1. Why a separate toolkit, not an nsmkit extension

nsmkit's `Event` model is deliberately protocol-agnostic and log-shaped: one
row per interesting event, built from whatever a log line or a coarse pcap
summary happened to record. That is the right shape for firewall/IDS/VPN
exports, where the *log format itself* already threw away most of the
packet.

The material in this batch is the opposite case: it is entirely about what
you can see *only* by having the packet — TCP flags and window size (to tell
a Connect scan from a SYN scan), the encapsulated original packet inside an
ICMP error, ARP's link-layer addressing, DHCP/NBNS/Kerberos option fields,
raw HTTP/FTP bytes, a TLS ClientHello's extension list. Cramming all of that
into `Event`'s flat, log-oriented fields would either lose information or
turn `Event` into two schemas wearing one name. trafkit instead keeps one
record per packet (`PacketRecord`) with a flat, **Wireshark-named** field
dict — `ip.src`, `tcp.flags.syn`, `http.request.method` — so a display
filter typed into Wireshark's own filter bar and a detector's field access
use exactly the same vocabulary. That equivalence is the toolkit's spine:
build it first, and every detector, every statistic, and the `filter` CLI
command all read from the same dict.

---

## 2. The PacketRecord field schema

`trafkit/models.py::PacketRecord` holds:

```
frame_number: int         # 1-indexed, matches Wireshark's "No." column
ts: float                 # unix epoch seconds
length: int                # frame length in bytes
fields: dict[str, Any]     # flat, dot-namespaced -- see below
summary: str                # scapy's one-line packet summary
src_mac, dst_mac: str | None
src_ip, dst_ip: str | None
proto: str | None          # "tcp" | "udp" | "icmp" | "arp" | "ip" | None
src_port, dst_port: int | None
```

`src_mac/dst_mac/src_ip/dst_ip/proto/src_port/dst_port` are promoted copies
of the hottest fields — every detector needs them, and indexing a Python
attribute is faster than a dict lookup by string key done thousands of
times per run. They are *always* mirrored into `fields` too, so the filter
engine never has to know about the promotion.

### 2.1 Field reference (everything pcapread.py can produce)

| Namespace | Fields | Source |
|---|---|---|
| `frame.*` | `number`, `time_epoch`, `len` | every packet |
| `eth.*` | `src`, `dst` | Ethernet header |
| `arp.*` | `opcode`, `src.proto_ipv4`, `dst.proto_ipv4`, `src.hw_mac`, `dst.hw_mac`, `duplicate-address-detected` | ARP |
| `ip.*` | `src`, `dst`, `ttl`, `proto`, `flags`, `frag`, `len` | IPv4 header |
| `icmp.*` | `type`, `code`, `orig.ip.src`, `orig.ip.dst`, `orig.udp.srcport`, `orig.udp.dstport`, `orig.tcp.srcport`, `orig.tcp.dstport` | ICMP; `orig.*` only present on an error message (type 3/11/12) and comes from the **encapsulated original packet** |
| `tcp.*` | `srcport`, `dstport`, `port` (alias, see §3.3), `flags` (raw int), `flags.{fin,syn,reset,push,ack,urg}` (0/1), `window_size`, `seq`, `ack` | TCP header |
| `udp.*` | `srcport`, `dstport`, `port` (alias) | UDP header |
| `data.len` | payload length *after* the transport header | TCP/UDP/ICMP |
| `dns.*` | `flags.response`, `qry.name`, `qry.name.len`, `qry.type`, `qry.type.name`, `rcode`, `a` (first answer), `resp.ttl`, `resp_all` (list) | DNS over UDP/53 |
| `dhcp.*` | `hw.mac_addr`, `yiaddr`, `option.dhcp` (message type int), `option.hostname`, `option.requested_ip_address`, `option.domain_name`, `option.ip_address_lease_time`, `option.message`, `option.client_id` | BOOTP/DHCP |
| `nbns.name` | the queried NetBIOS name | NBNS |
| `kerberos.*` | `pvno`, `realm`, `CNameString`, `SNameString`, `hostname` (fallback path only) | see §6 |
| `ftp.request.{command,arg}`, `ftp.response.{code,arg}` | FTP control channel (port 21) | raw-text parse |
| `http.request`, `http.request.{method,uri,full_uri}`, `http.host`, `http.user_agent`, `http.authorization`, `http.cookie`, `http.file_data` | HTTP request | `scapy.layers.http.HTTP` parse of the TCP payload |
| `http.response`, `http.response.code`, `http.server`, `http.content_type`, `http.content_disposition` | HTTP response | same |
| `tls.handshake.type`, `tls.record.content_type`, `tls.handshake.extensions_server_name` | TLS record/handshake header + SNI | manual TLS record walk, **not port-gated** (see §7) |

Any field not applicable to a given packet is simply absent from `fields` —
detectors and filters treat a missing key as "doesn't match", never as an
error (`FieldRef.eval` returns `None` on a miss; `Compare`/`Contains`/
`Matches` all short-circuit to `False` on `None`, mirroring how a real
Wireshark display filter silently excludes a packet that doesn't have the
field at all rather than erroring).

---

## 3. The display filter engine (`filters.py`)

### 3.1 Grammar

```
expr       := or_expr
or_expr    := and_expr (("or" | "||") and_expr)*
and_expr   := not_expr (("and" | "&&") not_expr)*
not_expr   := ("not" | "!") not_expr | primary
primary    := "(" expr ")" | comparison
comparison := value (OP | keyword_op | "in" | "contains" | "matches") value_or_set
            | value                                    # bare presence test
OP         := "==" | "!=" | ">" | "<" | ">=" | "<="
keyword_op := "eq" | "ne" | "gt" | "lt" | "ge" | "le"   # -> OP
value      := STRING | IPV4[/CIDR] | HEX | NUMBER | fieldref | func "(" value ")"
func       := "upper" | "lower" | "string"
value_or_set := value | "{" value ("," | " ")* value* "}"
```

A bare field reference with no operator (`tcp`, `http.request`,
`arp.opcode`) is a **presence test**: true if that exact field, or anything
nested under it (`name + "."`), exists in the packet's field dict. This is
what lets `tcp` mean "this is a TCP packet" and `http.request` mean "this
packet is an HTTP request" without a separate boolean field for every
protocol.

### 3.2 Tokenizer notes

- Numbers with dots that look like `N.N.N.N` (optionally `/N`) tokenize as
  `IPV4`, not `NUMBER` — otherwise `ip.src == 10.0.0.5` fails to tokenize
  past the first octet. This must be tried **before** the plain `NUMBER`
  pattern in the alternation.
- `!` must not consume the `!` in `!=` — use a negative lookahead
  (`!(?!=)`) and keep the `OP` alternative (which matches `!=` as one unit)
  earlier in the alternation than the logic-symbol alternative.
- Hex literals (`0xFA`) are supported for `ip.ttl >= 0xFA`-style filters,
  matching Wireshark's own hex/decimal interchangeability.

### 3.3 Direction-blind field aliases

Wireshark's `ip.addr`, `eth.addr`, `tcp.port`, `udp.port` match either
direction — `tcp.port == 443` matches a packet whether 443 is the source or
destination port. pcapread.py stores direction-aware fields only
(`ip.src`/`ip.dst`, `tcp.srcport`/`tcp.dstport`) because direction is what
every detector actually needs (a scanner's *source* vs. a scanned host's
*destination* are never interchangeable). The alias is resolved at
**filter-evaluation time** instead: `_FIELD_ALIASES` maps the alias name to
its two underlying fields, and `Compare`/`Contains`/`Matches`/`InSet` all OR
the comparison across every candidate value:

```python
_FIELD_ALIASES = {
    "ip.addr": ("ip.src", "ip.dst"),
    "eth.addr": ("eth.src", "eth.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
}
```

One consequence, inherited faithfully from real Wireshark and *not* a bug:
`ip.addr != X` means "**either** endpoint is not X", which is true for
almost every packet where the two endpoints differ — exactly the
inconsistency the room's own material calls out ("Usage of `!=value` is
deprecated... using `!(value)` is suggested for more consistent results").
Do not special-case this away; it is the documented, real behavior.

`ip.addr == 10.10.10.0/24` performs subnet membership via
`ipaddress.ip_network`, not string equality — detected by the right-hand
literal containing `/`.

### 3.4 Error handling

A malformed expression raises `FilterSyntaxError` at parse time (surfaced to
the CLI as exit code 2 with a message, never a stack trace). A well-formed
expression evaluated against a packet that lacks the referenced field
returns `False`, never raises — `evaluate()` wraps `Node.eval()` in a
broad `except Exception: return False` specifically so one packet type's
irrelevant field access can't aboard the whole filter pass (a regex field
that only applies to HTTP packets shouldn't crash on a DNS packet).

---

## 4. PCAP ingestion (`pcapread.py`) — three landmines already defused

Everything below was found by writing the synthetic sample generator and
watching the pipeline silently produce wrong or empty results, then working
backward to the cause. Re-introducing any of these breaks a real capture,
not just the sample.

### 4.1 Import `scapy.all` *before* opening the file, not lazily

`scapy.utils.PcapReader` resolves a file's link-layer type (e.g.
`LINKTYPE_ETHERNET`) to a dissector class **once, at open time**, using a
registration table that only exists after `scapy.all` (or at least the
relevant layer modules) has been imported into the process. If the first
thing that imports scapy layers is a function called *while iterating* the
reader (e.g. `_extract()`'s local `from scapy.all import ...`), every frame
in that file comes back as an undissected `scapy.packet.Raw` blob — no
`Ether`, no `IP`, nothing — and every downstream field extraction silently
returns nothing, no exception raised. The fix is one import, ordered
correctly:

```python
def read_pcap(path: str) -> list[PacketRecord]:
    import scapy.all  # noqa: F401 -- must run before PcapReader(path) opens the file
    from scapy.utils import PcapReader
    ...
```

This is invisible in a REPL session where you already `import scapy.all`
for something else first — it only reproduces in a clean subprocess, which
is exactly how the test suite (and any real invocation of `trafkit analyze`
from a shell) runs. Test for it explicitly if you can (spawn a subprocess
with nothing else imported and confirm `ip.src` is populated), and at
minimum never remove the eager import.

### 4.2 Get the transport payload from `.payload`, not `pkt[Raw]`

`from scapy.layers.http import HTTP` has a side effect: importing it binds
the `HTTP` dissector to TCP port 80 (`bind_layers(TCP, HTTP, ...)`) for the
rest of the process. The **first** port-80 packet processed before that
import runs is dissected as plain `TCP / Raw` (payload reachable via
`pkt[Raw].load`); **every packet after that import** is dissected as
`TCP / HTTP / ...` instead, and `pkt.haslayer(Raw)` silently returns
`False` because the bytes were consumed into HTTP fields, not left as a
generic Raw layer. Code that special-cases `pkt[Raw].load` for the payload
works on the first HTTP packet in a run and silently returns nothing for
every one after it — the exact shape of bug that a single-packet smoke test
will never catch.

The fix: use the *previous layer's own `.payload`* attribute, which scapy
keeps correct regardless of how much further dissection happened to that
payload:

```python
tcp_payload = bytes(tcp.payload)   # not bytes(pkt[Raw].load)
udp_payload = bytes(udp.payload)
```

This generalizes to any future contrib layer that auto-binds to a port
trafkit also cares about — it's immune to the whole class of bug, not just
the HTTP instance of it.

### 4.3 ICMP error payloads dissect as `IPerror`/`TCPerror`/`UDPerror`

An ICMP destination-unreachable (type 3) encapsulates the original packet
that triggered it — that's how a UDP scan's closed-port response gets
attributed back to the port that was probed. Scapy dissects that
encapsulated packet using **distinct error-variant classes**
(`scapy.layers.inet.IPerror`, `TCPerror`, `UDPerror`), not the normal
`IP`/`TCP`/`UDP` classes — `icmp.payload.haslayer(IP)` is `False` even
though the bytes are structurally an IP header. Use the `*error` classes:

```python
from scapy.layers.inet import IPerror, TCPerror, UDPerror
if icmp.haslayer(IPerror):
    orig_dst_port = icmp[UDPerror].dport if icmp.haslayer(UDPerror) else None
```

### 4.4 Kerberos: real ASN.1 first, generic TLV scan as fallback

Real Kerberos messages are BER/DER-encoded per RFC 4120, and scapy ships an
ASN.1 dissector for them (`scapy.layers.kerberos`). Try it first — on a real
capture from a real KDC it will produce fully-qualified fields
(`reqBody.cname.nameString`, `reqBody.realm`, `reqBody.sname.nameString`).
It is *not* guaranteed to round-trip cleanly for hand-constructed test
fixtures in every scapy version (optional-field / SEQUENCE-OF encoding
edge cases have been observed), so trafkit never depends on it working:

```python
try:
    pkt_krb = krb.KRB_AS_REQ(payload)
    ...  # use pkt_krb.reqBody.cname / .realm / .sname
except Exception:
    strings = _ber_general_strings(payload)   # fallback below
```

The fallback (`_ber_general_strings`) is a generic BER TLV walk that finds
every ASN.1 GeneralString/PrintableString primitive (tag `0x1B`/`0x13`/
`0x1A`) in the payload using nothing but that primitive's own length byte —
no schema awareness at all. It reliably recovers the realm (the string
containing a `.`) and every principal-name component, which is genuinely
sufficient for the room's own investigative technique: distinguish a
hostname from a username purely by whether the string ends in `$`
("filter the `$` value... hostnames end with `$`, usernames don't"). Treat
this as string-hunting, not RFC-4120 parsing — document it as such rather
than pretending it's a full dissector, and keep both the scapy-dissected
`kerberos.CNameString` and the fallback's separate `kerberos.hostname`
field, because a `$`-suffixed cname (a machine account authenticating as
itself) and a `$`-suffixed value recovered by the fallback scanner are not
guaranteed to land in the same field name — `identify_hosts_and_users()`
in `detectors/hostid.py` checks both.

### 4.5 TLS extraction must not be port-gated

`_apply_tls` is deliberately called on *every* TCP payload, not only on
port 443/8443 — a TLS record's own header (`0x16 0x03 0x0X` — handshake
content type + a `TLSv1.x` version byte) is specific enough to identify it
without relying on the port. This is what makes `TLS-PORT-01` (a handshake
completed on a port nobody expects TLS on) detectable at all: gating the
extraction on "expected" TLS ports would make the detector built to catch
*unexpected* ports permanently blind to its own reason for existing.

---

## 5. Nmap scan fingerprinting (`detectors/scanning.py`)

Three independent scan shapes, matching Wireshark: Traffic Analysis task 2:

| Scan type | `nmap` flag | Wire signature |
|---|---|---|
| TCP Connect | `-sT` | Full 3-way handshake completes; **window size > 1024** on the initial SYN (a real OS socket layer is behind it, expecting to receive data) |
| TCP SYN | `-sS` | Half-open — SYN, then RST on SYN,ACK (never ACKs); **window size ≤ 1024** (crafted directly, no real socket) |
| UDP | `-sU` | No response from open ports; **ICMP type 3 code 3** (port unreachable) from closed ones, encapsulating the original UDP probe |

`SCAN-NMAP-01` groups SYN-only (no-ACK) packets by `(src, dst)`, slides a
window (`vertical_scan_window_seconds`, default 60s), and fires when the
distinct destination-port count in the best window reaches
`vertical_scan_min_ports` (15). It classifies Connect-vs-SYN by majority
vote on window size across the probes in that window, not a single sample —
a mixed capture (some retransmits, some probes losing their window in
transit) still classifies correctly by whichever style dominates.

`SCAN-NMAP-02` (horizontal / host sweep) groups the same SYN packets by
`(src, dst_port)` instead — one port, many destination IPs — and fires past
`horizontal_scan_min_hosts` (10).

`SCAN-NMAP-03` (UDP) groups ICMP-unreachable responses by
`(prober, scanned_host)`, recovering the prober's identity from the
encapsulated original packet's source IP (§4.3), and fires past
`udp_scan_min_unreachables` (8) distinct closed ports.

All three use the same sliding-window helper (`_slide`): advance a left
pointer until the window duration is satisfied, track the largest qualifying
run — identical in shape to nsmkit's scan detectors, because it's the same
problem (bound a burst of related events to a time window without a fixed
bucket boundary splitting one real burst into two under-threshold halves).

---

## 6. ARP spoofing, flooding, and MITM relay (`detectors/arp.py`)

`ARP-SPOOF-01` tracks, per claimed IP, every `(timestamp, mac, frame)` from
an ARP **reply/announcement** (opcode 2 — a request only asks, it doesn't
assert ownership). A sliding window over that per-IP list that contains
`{≥ 2}` distinct MACs is a conflict: two hosts claiming the same address is
definitionally a spoof (there is no legitimate reason for it outside HA
failover, which uses a shared virtual MAC, not two real ones flapping).

`ARP-SPOOF-02` (MITM relay) is the room's own walkthrough turned into code:
once a MAC is known to be spoofing (flagged by -01), any packet whose
**link-layer destination** is that MAC while its **IP-layer destination**
is a different host entirely proves traffic is being funneled through the
attacker before reaching its real target — the room's own example is the
victim's HTTP session, still IP-addressed to the real web server, but
Ethernet-addressed to the poisoner. This is the highest-confidence finding
in the file because it's not inference from ARP alone — it's direct
evidence of interception.

`ARP-FLOOD-01` counts, per source MAC, how many distinct target IPs it
ARP-requested inside a window — `arp_flood_min_targets` (20) in
`arp_flood_window_seconds` (30). This is a discovery sweep, not
necessarily a spoof by itself, but is the room's documented precursor
signal to one.

---

## 7. Tunnelling (`detectors/tunneling.py`)

**ICMP** (`TUNNEL-ICMP-01`): group echo request/reply (`type` 0 or 8) with
`data.len` over `icmp_tunnel_payload_len_floor` (64 bytes — a stock ping is
32–64B) by the **unordered** `{src, dst}` pair (echo is inherently
bidirectional; grouping directionally would report one tunnel as two mirror
findings). Fire once `icmp_tunnel_min_packets` (20) oversized packets land
in one window.

**DNS** (`TUNNEL-DNS-01`): a small point-based score per query name, not a
single gate (same philosophy nsmkit's DNS tunnel detector uses, and for the
same reason — a name that's merely long isn't automatically a tunnel, but
long *and* high-entropy *and* base32/64/hex-shaped *and* digit-heavy
together is):

```
+5  matches a known tool string ("dnscat", "dns2tcp", "iodine", "dnscat2")
+1  subdomain length >= dns_tunnel_qname_len_floor (40)
+2  subdomain looks base16/32/64-encoded (enrich.looks_encoded)
+1  subdomain Shannon entropy >= 3.5 bits/char
+1  subdomain digit ratio > 0.4
```

Queries scoring ≥ 2 are "suspicious"; the detector fires once a source
accumulates `dns_tunnel_min_queries` (15) suspicious queries in
`dns_tunnel_window_seconds` (120s). `!mdns`-equivalent noise (multicast/
local-link chatter) never enters this path because it isn't a unicast query
carrying a real qname in the samples used to build this; a production
deployment should add an explicit local-domain allowlist the same way
nsmkit's DNS detectors do.

---

## 8. Cleartext credentials & brute force (`detectors/cleartext.py`)

FTP USER/PASS pairing is stream-ordered per `(client, server)`: walk
packets in timestamp order, remember the most recent `USER` argument, and
attribute the next `PASS` to it — this is the same "pair the request with
the response/predecessor on the same conversation" pattern the room's own
manual walkthrough uses (`ftp.request.command == "PASS"` alongside the
preceding `USER`).

- **Brute force** (`FTP-BRUTE-01`): count `530` (login incorrect) responses
  per `(client, server)` in a window; fire past `bruteforce_min_failures`
  (5). A single `230` (success) anywhere in the capture is not itself
  suppressive — the recommendation text explicitly tells the analyst to
  check for one, because a successful login *after* a run of failures is
  the highest-value single fact in the whole finding.
- **Password spray** (`FTP-BRUTE-02`): group by `(server, password)` and
  count *distinct usernames* that password was tried against; fire past
  `spray_min_targets` (5). This is deliberately the transposed axis from
  brute force — many passwords/one account vs. one password/many
  accounts — because spraying exists specifically to dodge a per-account
  lockout threshold, and a detector keyed only on failure *count* per
  account would miss it by design.

`extract_credentials()` (used by `extract.py` and the `creds` CLI command)
additionally recovers HTTP Basic-Auth (base64-decoded) and simple
`username=&password=`-style form POST bodies — cleartext by construction,
so no further inference is needed, only extraction.

---

## 9. HTTP anomalies (`detectors/http.py`)

`HTTP-UA-01` matches the `User-Agent` header against a configurable list of
known audit/scanner tool signatures (`sqlmap`, `nmap`, `wfuzz`, `nikto`,
`nessus`, `acunetix`, `havij`, `gobuster`, `dirbuster` by default). The
room's own caution is baked into the recommendation text, not silently
assumed: *"Never treat the user agent as authoritative on its own — it's
trivially forged."*

`HTTP-LOG4J-01` (Log4Shell / CVE-2021-44228) scans four fields — User-Agent,
request URI, Host, and the response/request body — for the JNDI lookup
pattern:

```
\$\{jndi:(ldap|rmi|dns|ldaps|iiop|nis|nds)://
```

plus a literal `Exploit.class` substring match, mirroring the room's own
two low-hanging-fruit filters
(`(ip contains "jndi") or (ip contains "Exploit")`). A confirmed hit is
`severity=critical` unconditionally — this is exploitation-attempt
evidence, not an anomaly requiring corroboration.

---

## 10. Host inventory & OS fingerprinting (`hosts.py`)

`build_hosts()` produces the NetworkMiner "Hosts" tab equivalent: per-IP
MAC set, hostname set, a rough OS guess, inferred open ports, and
sent/received traffic counters.

**Open port inference**: a `SYN,ACK` response means the *destination* of
the original SYN — i.e. whoever sent the SYN,ACK — has that source port
open. No separate service-banner step needed.

**OS fingerprint**: bucketed by the *client's initial SYN* TTL (before any
reply could have altered the analyst's read of it), the same signal
NetworkMiner's own backends (Satori, p0f) use:

| TTL ≤ | Bucket |
|---|---|
| 34 | Windows (old, TTL~32) |
| 66 | Linux / Unix / macOS (TTL~64) |
| 130 | Windows (TTL~128) |
| 256 | Network device / Solaris / some Unix (TTL~255) |

Window size (`64240`/`5840`/`29200` → Linux-ish, `65535`/`8192` → Windows/
macOS/BSD-ish) only ever *raises confidence* when it agrees with the TTL
bucket; it never overrides the TTL bucket, because window size is far
noisier across OS versions, TCP stack tuning, and middlebox rewriting.
`os_confidence` stays `"low"` unless both signals agree — treat the whole
field as a triage hint, not evidence, and never build an enforcement
decision on it alone.

**DHCP hostname attribution**: a DHCP DISCOVER/REQUEST is sent from
`0.0.0.0` (the client has no address yet) — naively attaching
`dhcp.option.hostname` to the packet's own source IP puts every claimed
hostname on a useless `"0.0.0.0"` host record. `build_hosts()` does a small
pre-pass instead: build `mac -> hostname` from every DISCOVER/REQUEST and
`mac -> assigned_ip` from every ACK's `yiaddr`, then attach the hostname to
the *assigned* IP. (`identify_hosts_and_users()` in `detectors/hostid.py`,
which drives the `identify` CLI command, is a simpler raw listing by design
and does not do this correlation — it's meant as a diagnostic dump of what
was seen, not the polished inventory.)

`resolved_addresses()` (the NetworkMiner/Wireshark "Resolved Addresses"
view) maps every A-record answer's IP back to every query name that
resolved to it, straight from `dns.a` + `dns.qry.name`.

---

## 11. Statistics (`statistics.py`)

Direct port of the Wireshark Statistics menu items this material covers:

- `protocol_hierarchy()` — packet counts per transport, plus the
  application-layer protocols trafkit was able to identify layered on top
  (`tcp.http`, `tcp.ftp`, `tcp.tls`, `udp.dns`, `udp.dhcp`, `udp.nbns`,
  `udp.kerberos`).
- `endpoints()` — per-address packet/byte totals, sorted by volume
  descending (the "who's talking the most" triage question).
- `dns_stats()` — query/response counts, unique query-name count, NXDOMAIN
  count, top-10 queried names, qtype breakdown.
- `http_stats()` — request/response counts, method/status-code breakdowns,
  top hosts, top user agents.
- `capture_summary()` — packet count, total bytes, wall-clock duration,
  protocol hierarchy — what `trafkit overview` leads with, deliberately
  before a single detector has run, matching the room's own "Statistics
  first, then filter down to the event of interest" workflow.

---

## 12. Artifact extraction (`extract.py`) — and its honest scope line

`extract_files()`, `search_keywords()`, and the re-exported
`extract_credentials()`/`resolved_addresses()` are the NetworkMiner
Files/Keywords/Credentials/Resolved-Addresses tabs.

**File extraction is metadata-only, not byte recovery**, and that is a
deliberate scope boundary, not an oversight: trafkit processes packets
individually (§2) rather than doing full TCP stream reassembly. A
`Content-Disposition: attachment` response yields filename/content-type/
endpoints/frame-number — enough to know *that* a file crossed the wire and
what it claimed to be — but not the reassembled bytes NetworkMiner would
carve to disk. Real byte-for-byte carving needs a stream reassembler, which
is a project of its own; `phish attachments --extract` in the sibling
toolkit *does* do full reconstruction, but only because MIME attachments
arrive base64-encoded in one contiguous blob inside a single message, not
scattered across an arbitrary number of TCP segments. Document this
boundary explicitly to anyone extending trafkit rather than letting someone
assume `files` recovers a usable file.

`search_keywords()` is a case-insensitive substring scan across every
text-shaped field trafkit extracts (HTTP URI/host/UA/body, FTP args, DNS
query names, Kerberos realm/CNameString, NBNS/DHCP hostnames) — "reload the
case after changing keywords" in NetworkMiner is just calling this again
with a new list here.

---

## 13. Firewall ACL generation (`aclgen.py`)

Mirrors Wireshark's own "Tools → Firewall ACL Rules" feature and its
supported target list: Netfilter/iptables, Cisco IOS (extended ACL),
`pf`, and Windows Firewall (`netsh`). Two rules this module enforces on
itself:

1. **Deny-only, never allow.** Every generated rule blocks a specific
   host; nothing here can accidentally open a hole if pasted into a device
   without careful review.
2. **Only the offending host, never the victim.** `_implicated_ips()`
   pulls IPs from a fixed, deliberately narrow set of evidence keys —
   `src`, `prober`, `client` — that consistently name *who initiated* the
   bad traffic across every detector. Keys like `dst`, `scanned`,
   `server`, `victims`, `hosts_probed`, `targets_probed` all name the
   *target* instead, and were excluded on purpose after an early version
   scanned every evidence value indiscriminately and would have generated
   a rule blocking a *scanned* host right alongside the actual scanner.
   ARP/MITM findings that only ever identify the attacker by MAC address
   (no IP of their own worth blocking) correctly produce **no** IP rule —
   that's a real limitation of IP-based ACLs against link-layer spoofing,
   not a bug to work around.

---

## 14. Architecture

```
trafkit/
  models.py            PacketRecord, Host, Conversation, Finding, Credential,
                        Artifact, AnalysisResult
  config.py             every threshold, one dataclass, JSON-serialisable
  filters.py             Wireshark display-filter tokenizer/parser/evaluator
  pcapread.py            scapy-based ingestion -> list[PacketRecord]
  enrich.py               shannon_entropy / looks_encoded / digit_ratio
  hosts.py                 host inventory, OS fingerprint, conversations,
                            resolved addresses
  statistics.py             protocol hierarchy, endpoints, DNS/HTTP stats
  extract.py                 credentials (re-export) + files + keywords
  aclgen.py                  firewall ACL rule generation
  detectors/
    base.py                  Detector ABC, @register, REGISTRY, run_detectors
    scanning.py                Nmap Connect/SYN/UDP + horizontal sweep
    arp.py                     ARP spoof/flood + MITM relay
    hostid.py                  DHCP starvation/NAK anomalies + identity table
    tunneling.py                ICMP + DNS tunnelling
    cleartext.py                 FTP brute force/spray + credential harvest
    http.py                      scanner UA, UA inconsistency, Log4Shell
    tls.py                       TLS-on-unexpected-port
  report.py                       console/JSON/Markdown/HTML rendering
  cli.py                           overview|hosts|filter|analyze|dns|http|
                                    creds|files|identify|keywords|acl|rules
```

`trafkit.analyze(path, cfg=None) -> AnalysisResult` is the top-level API:
read the pcap, build hosts/conversations once (shared via
`AnalysisContext` so every detector reuses them instead of recomputing),
run every registered detector inside the isolation wrapper (`run_detectors`
— one detector's exception becomes an `info`-severity finding describing
the failure, never a crashed run), sort findings by severity, return.

---

## 15. Testing

`make_pcaps.py` builds one small, hand-crafted `.pcapng` per scenario under
`samples/` (scapy synthetic packets, not real capture data) — one file per
detector's positive case, plus `clean_baseline.pcapng`: ordinary TCP
handshakes, resolved DNS lookups, one normal HTTP exchange, and one
normal-sized ping, which must trigger **zero** findings across every
detector at once. That file is the single most valuable regression test in
the suite — it's what a threshold tuned too aggressively in any one
detector breaks first.

`tests/test_trafkit.py` (57 tests) covers: the filter DSL (equality,
aliases, CIDR, numeric/hex, `contains`/`matches`/`in`, functions, presence,
logic, syntax errors), enrichment primitives, field extraction per
protocol, host inventory and OS fingerprinting, conversations/statistics,
one positive case per detector rule plus the shared clean-baseline
negative, credential/file/keyword extraction, and ACL generation
(including the "never blocks the victim" check).

---

## Appendix A — TCP flags quick reference

| Bit | Name | Hex |
|---|---|---|
| FIN | 0x01 | connection close |
| SYN | 0x02 | connection start |
| RST | 0x04 | reset |
| PSH | 0x08 | push buffered data |
| ACK | 0x10 | acknowledgment valid |
| URG | 0x20 | urgent pointer valid |

`tcp.flags == 2` (decimal) is SYN-only; `tcp.flags == 18` is SYN,ACK;
`tcp.flags == 20` is RST,ACK.

## Appendix B — DNS query type codes trafkit recognises

`1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 33=SRV, 255=ANY`

## Appendix C — MITRE ATT&CK mapping

| Rule | Technique |
|---|---|
| SCAN-NMAP-01/02/03 | T1046 Network Service Discovery |
| ARP-SPOOF-01/02 | T1557.002 ARP Cache Poisoning |
| ARP-FLOOD-01 | T1046 Network Service Discovery |
| DHCP-ANOM-01 | T1557 Adversary-in-the-Middle |
| TUNNEL-ICMP-01 | T1095 Non-Application Layer Protocol |
| TUNNEL-DNS-01 | T1071.004 Application Layer Protocol: DNS |
| FTP-BRUTE-01 | T1110.001 Brute Force: Password Guessing |
| FTP-BRUTE-02 | T1110.003 Brute Force: Password Spraying |
| HTTP-UA-01 | T1595.002 Active Scanning: Vulnerability Scanning |
| HTTP-LOG4J-01 | T1190 Exploit Public-Facing Application |
| TLS-PORT-01 | T1571 Non-Standard Port |

## Appendix D — Implementation traps (summary)

1. Import `scapy.all` before constructing `PcapReader`, at the top of
   `read_pcap()` — not lazily inside a per-packet extraction function — or
   every frame comes back as undissected `Raw` with no error raised (§4.1).
2. Read TCP/UDP payload via `bytes(layer.payload)`, never `pkt[Raw].load`
   — any scapy contrib import that auto-binds a dissector to a port (HTTP
   on 80 is the one that bit this build) makes `pkt.haslayer(Raw)` silently
   go `False` for every later packet on that port (§4.2).
3. ICMP error payloads are `IPerror`/`TCPerror`/`UDPerror`, not `IP`/`TCP`/
   `UDP` — `icmp.payload.haslayer(IP)` is `False` even on a structurally
   valid encapsulated IP header (§4.3).
4. Don't gate TLS record detection behind "expected" ports — the detector
   whose entire purpose is catching TLS on an *unexpected* port needs to
   see it there in the first place (§4.5).
5. Kerberos: try scapy's real ASN.1 dissector, fall back to a schema-free
   BER TLV string scan, and keep the `$`-suffix hostname/username split
   consistent between whichever path actually populated the fields (§4.4).
6. ARP conflict detection requires opcode 2 (reply/announcement) only —
   an opcode-1 request only *asks* who has an address, it never asserts
   ownership, so counting requests toward a conflict would flag every
   normal ARP resolution as spoofing.
7. Group bidirectional protocols (ICMP echo, any conversation-shaped
   traffic) by the **unordered** endpoint pair, not `(src, dst)` — grouping
   directionally reports one real channel as two mirror-image findings.
8. `ip.addr`/`tcp.port`-style filter aliases must OR across both
   underlying direction-specific fields at evaluation time; storing a
   duplicated non-directional copy at extraction time loses the
   directional fields every detector actually needs.
9. ACL generation must read evidence by a fixed attacker-identifying key
   whitelist (`src`/`prober`/`client`), never scan every evidence value
   indiscriminately — several detectors legitimately carry the *victim's*
   IP in evidence too, and blocking it would be actively harmful advice.
10. Test with a dedicated clean/negative-baseline capture that must
    produce **zero** findings across the whole detector set, not just a
    positive case per rule — it is the fastest way to catch a threshold
    that's drifted too aggressive during later tuning.
