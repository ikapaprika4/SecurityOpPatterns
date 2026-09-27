# What changed from the original four toolkits

The four toolkits started as separate projects (`phishkit`, `evtxkit`,
`nsmkit`, `trafkit`). Here they are fixed, extended and joined under one
front end. The detection logic, rule IDs, weights and thresholds are the
originals' unless listed below, and every original test still runs (now 303
tests in total, `python run_tests.py`).

## New

* **SOC Workbench** (`socworkbench/`): one window for all four kits. Drop
  files, folders or `.zip` archives; each file is recognised by its content
  (not its extension), sent to the right kit, and comes back as a *case*:
  a verdict, findings with evidence and ATT&CK IDs, indicators marked
  block-worthy or context-only, the kit's own detail tables, and exports
  (HTML report, JSON, IOC CSV, blocklist, MISP/STIX, firewall ACLs,
  Snort/Suricata rules). Emails are one case each, Windows logs are merged
  per host, network logs are merged into one case, and every capture is
  analysed by trafkit *and* nsmkit's flow detectors from a single parse.
* **`soccore/`**, code the kits now share instead of each carrying its own:
  * `pcap.py`: a dependency-free pcap/pcapng reader and dissector. It
    replaces scapy as the default for trafkit and nsmkit.
  * `netaddr.py`: one address classifier. RFC 5737 documentation ranges
    count as *external*, and IPv4-mapped IPv6 is handled.
  * `windows.py`: O(n) sliding windows.
* `python -m phishkit|nsmkit|evtxkit|trafkit ...` works (added
  `__main__.py`), next to the original `python -m <kit>.cli ...`.
* `run_tests.py` runs every suite in its own interpreter. There is a new
  `tests/test_workbench.py` (routing, grouping, zip/folder expansion,
  damaged input, exports, and the HTTP server's token, Host and path
  checks) and `tests/test_soccore.py`.
* `tools/`: the sample generators, plus a differential test that checks
  the native packet reader field-by-field against the original scapy code.

## Nothing to install any more

| Was needed | Now |
|---|---|
| `scapy` for every PCAP (trafkit, nsmkit) | native reader, standard library only; about 28× faster (200,000 packets: 6.3 s vs 176.9 s, measured on one Windows PC); reads IPv6, which the scapy path ignored |
| `extract-msg` for Outlook `.msg` | native OLE2/CFB + MAPI reader: transport headers, bodies, attachments |
| `python-evtx` for `.evtx` | on Windows, read through the built-in `wevtutil` (python-evtx only off Windows) |

scapy remains an opt-in backend (`TRAFKIT_BACKEND=scapy`) so the two can
be compared: `tools/dump_scapy_fields.py` + `tools/compare_pcap_backends.py`
report **0 mismatches over 485 packets in 19 captures** (the 13 trafkit
samples, the nsmkit MITM capture, and 5 edge-case captures from
`tools/make_edge_pcaps.py`: VLAN/QinQ, SLL, raw IP, nanosecond pcap, IP
options, fragments, padding, DNS compression, a real Kerberos AS-REQ, IPv6).

## Bugs fixed

### phishkit
* **An `.mbox` was parsed as a single message.** It is now one result per message.
* **A plain `.eml` saved with a `.msg` name was read as an empty
  message** (it failed as "not an OLE2 file"), so a BEC wire-fraud email
  came back as mere *spam*. Files are now routed by content.
* **Blocklists contained shared infrastructure.** `gmail.com` and
  `outlook.com` (webmail sender domains), `help.netflix.com` (the real brand
  link a phish includes as a decoy), link shorteners and the mail
  provider's own servers appeared as block-worthy. They are now *context*
  indicators, shown but never exported to a blocklist. The attacker's own
  addresses, links and hashes still are, and the BEC **Reply-To** address,
  where the replies actually go, was added.
* **A Reply-To pointing at a different free-webmail account** (a "CEO" on
  gmail.com asking for replies to another gmail.com mailbox, the classic
  BEC setup) counted as "same organisation" and scored 3 instead of 22.
  Two mailboxes at a free provider are two people, so it is now scored high.
* **Microsoft Safe Links**: the real destination behind the wrapper is now
  an indicator. The wrapper URL is context.
* Input with no email headers at all is flagged as "not an email" instead
  of being scored as spam.

### evtxkit
* **Event 4688 PIDs were inverted**: the new process was given the parent's
  PID, which broke the process tree for Security-log sources.
* **Process detectors only read Sysmon.** Hosts with only the Security log
  (4688) produced no execution, discovery or C2 findings. They now read
  both.
* **Event IDs were not checked against their channel**, so System event 1
  counted as a Sysmon process creation. Identity is now channel-aware.
* **Logon ID `0x0`** matched unrelated sessions. It is now ignored for correlation.
* **PowerShell-history events showed 1970 as their time.** They are now
  shown as untimed.
* New detections: security or event log cleared (1102/104), encoded
  PowerShell (`-enc` payloads are decoded and searched), and suspicious
  PowerShell script blocks (4104): critical on one marker of named
  offensive tooling, medium on three or more individually common
  techniques together. A single common technique doesn't fire.
* More inputs: Event Viewer / `wevtutil` XML, evtx_dump,
  Winlogbeat/ECS, EvtxECmd and flat JSON, and several files at once. A
  `Get-WinEvent` positional-JSON export is explained instead of silently
  misread.

### nsmkit
* **`correlate()` crashed** with `TypeError` when a stage mixed findings
  with and without a timestamp (it compared a `datetime` to `""`).
* **Resolvers and gateways were used as correlation keys.** Every host
  talks to them, so unrelated findings merged into one incident. They are
  no longer used as join keys.
* **PCAP timestamps were converted to the analysing PC's local time** while every
  log parser uses UTC. Captures and logs then disagreed by the UTC offset,
  which breaks time-window correlation. They are now UTC.
* One crashing detector could abort a library run. Detectors are now
  isolated (reported as `NSM-ERR-001`).
* The CLI config was a shared, mutable object. Each run now gets its own.
* **Quadratic sliding windows** in scan, brute-force and lateral-movement
  detection are now O(n): identical findings on the 4,018-event sample set,
  about 2× faster.
* IPv6: IPv4-mapped addresses are classified correctly, and ULA and
  link-local addresses count as home networks.

### trafkit
* **The generated Cisco ACL ended with an implicit deny.** Applied to an
  interface, it would have blocked *all* traffic. It now ends in
  `permit ip any any` with explanatory comments. IPv6 attackers get
  `ip6tables` rules.
* **HTTP findings were one per packet.** They are now aggregated per
  source, destination and tool.
* **Obfuscated Log4Shell** (`${${lower:j}ndi:...}`) was missed. It is now
  deobfuscated before matching.
* **NBNS names were attributed to the host that asked**, not the host that
  owns the name. They are now attributed to the owner.
* **DHCP hostnames were filed under `0.0.0.0`.** They now go under the
  address the server assigned.
* **CNAME chains resolved to the alias.** Only the first answer was used,
  often the CNAME itself. Every A record is now kept, and each address is
  attributed to the name that was actually looked up.
* **DNS-tunnel false positives** on reverse lookups (`in-addr.arpa`,
  `ip6.arpa`) and CDN names are now suppressed by a configurable
  allowlist.
* TLS "unusual port" no longer fires on standard TLS services (DoT 853,
  SIP-TLS 5061, APNs 5223, FCM 5228, MQTT 8883, 9443).
* Broadcast and multicast MACs are no longer attributed to hosts, and the
  OS guess also uses the IPv6 hop limit.
* **A truncated or damaged capture was analysed silently as if complete.**
  A corrupt one even came back *clean*. The reader now says where and why
  it stopped. The CLI warns on stderr, the workbench adds a note to the
  case, and a capture with no readable packets is an error, never "clean".
* Sliding windows (scan, ARP, tunnelling, cleartext) are now O(n).

### Samples
* The original capture generator used a bare scapy `Ether()`, which stamps
  **the generating PC's real network-card MAC** into every sample. The
  samples now use RFC 7042 documentation MACs (`00:00:5e:00:53:xx`).
* Samples named `.pcapng` really are pcapng now (scapy's `wrpcap` had
  written classic pcap under that name).
* **No real third party is named as an attacker.** The samples had used
  made-up names on real domains: Gmail and Outlook addresses for the BEC
  "attacker", registrable `.com`/`.net` names for C2 and tunnelling, and a
  real-format bit.ly link. The blocklist exports would have listed them as
  block-worthy, although someone could own them. Attacker infrastructure now uses the
  reserved `.example` TLD. Values that must sit on a real service for a
  rule to fire are demo names: the Gmail addresses contain `_`, which Gmail
  doesn't allow, so they can't exist. Verdicts, scores and rules are
  unchanged.
* An email-address example taken from course material now uses
  `example.com`.
* New samples: an Outlook `.msg`, a multi-message `.mbox`, a Security-only
  Windows host (no Sysmon), a cleared-log XML export, and PowerShell script
  blocks.

## Native reader vs the scapy path: intentional differences

Where they differ, the native value follows Wireshark and the scapy path
was incomplete:

* `dns.a` is the first **A** record (scapy-trafkit stored the first answer
  of any type, e.g. a CNAME). Every answer is kept (`dns.a_all`,
  `dns.resp_all`); scapy-trafkit kept only the first.
* Kerberos: a genuine RFC 4120 message is parsed structurally. The scapy
  path's fallback string scan merged the service name into the client name.
* Payload lengths are bounded by the IP/UDP length fields, so Ethernet
  padding is no longer counted as data.
* IPv6 and Linux cooked (SLL) frames are dissected (the scapy path skipped them).
* `http.request.full_uri` is `http://host/path`, as in Wireshark (the scapy
  path gave the path only).
* Additive fields the scapy path never produced: `dns.id`, `dns.cname`,
  `dns.aaaa`, `ip.id`, `ip.flags.df`, `tcp.len`, `vlan.id`, `kerberos.etype`,
  `nbns.name`, `data.data` and more.
