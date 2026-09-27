# nsmkit — Network Security Monitoring analysis toolkit

Parses firewall, IDS, VPN, WAF, DNS, HTTP and PCAP telemetry into one normalised event stream,
runs 22 detectors over it, correlates the findings into incidents, and reports.

**`docs/NSM_BUILD_SPEC.md` is the detection-engineering specification** — log grammars,
every rule's logic and thresholds, false-positive sources, ATT&CK mapping, Snort reference, and
the Wireshark/Splunk/CLI query cookbook. Hand that file to a coding model to build from, or read
it as the reference; `nsmkit/` is the working implementation of it.

## Install

Nothing to install: run from the `soc-workbench` folder (or `pip install -e .` there for the
`nsm` command). Python 3.10+, no dependencies — PCAPs are read by the built-in native reader
(`soccore.pcap`); scapy and tshark remain available as optional alternative backends.

## Quick start

```bash
python -m nsmkit analyze samples/nsmkit/ -v
python -m nsmkit analyze samples/nsmkit/ -f html -o report.html

python tools/make_nsm_samples.py        # regenerate the synthetic incident dataset
python tools/make_nsm_pcap.py           # regenerate samples/nsmkit/mitm.pcap (needs scapy)
```

## Commands

| Command | Purpose |
|---|---|
| `nsm analyze <files\|dirs>` | Run all detectors, correlate, report (`-f console\|json\|markdown\|html`) |
| `nsm parse <file>` | Normalise one log to JSONL — use this to debug parsing |
| `nsm stats <files>` | Triage statistics: top blocked sources, auth failures, IDS signatures, upload pairs |
| `nsm pivot <files>` | VPN account → assigned IP → what it did next |
| `nsm rules [--show-thresholds]` | List detectors and the active configuration |
| `nsm snort findings.json` | Generate Snort/Suricata rules from findings |

Useful flags: `-c site.json` (config), `--only beaconing,dns_tunnel` (subset),
`--min-severity high`, `-o out.html`. Exit code is 1 when any high/critical finding exists,
so it drops into CI.

## Configuration

Every threshold and allowlist lives in a JSON profile — tuning is a config edit, not a code edit.

```json
{
  "home_nets": ["10.0.0.0/8", "192.168.0.0/16"],
  "vpn_pool_nets": ["10.8.0.0/16"],
  "known_resolvers": ["10.0.0.53"],
  "gateway_ips": ["10.0.0.1"],
  "scanner_allowlist": ["10.0.0.240"],
  "domain_allowlist": ["akamai.net", "cloudfront.net"],
  "beacon_max_jitter": 0.35,
  "dns_min_entropy": 3.8,
  "exfil_min_total_bytes": 52428800
}
```

`python -m nsmkit.cli rules --show-thresholds` prints the full set with current values.

## Detectors

| ID | Detector | Detects |
|---|---|---|
| NSM-SCAN-001 | `vertical_scan` | One source, many ports on one host |
| NSM-SCAN-002 | `horizontal_scan` | One source, one port across many hosts |
| NSM-SCAN-003 | `ping_sweep` | ICMP host discovery |
| NSM-PERIM-001 | `exposed_service` | High-risk ports reachable from the internet |
| NSM-CRED-001 | `brute_force` | Authentication failure floods |
| NSM-CRED-002 | `password_spray` | Few attempts across many accounts |
| NSM-CRED-003 | `success_after_failures` | Login success following a failure burst |
| NSM-CRED-004 | `anomalous_vpn` | Unusual source/hour patterns per account |
| NSM-C2-001 | `beaconing` | Periodic outbound check-ins (jitter + MAD + payload-size analysis) |
| NSM-C2-002 | `suspicious_port` | 4444, 50050 and other tooling defaults |
| NSM-EXFIL-001 | `dns_tunnel` | Encoded data in DNS labels (11-feature score) |
| NSM-EXFIL-002 | `dns_direct_egress` | Resolution bypassing the corporate resolver |
| NSM-EXFIL-003 | `http_exfil` | Large POST uploads, baselined against the environment |
| NSM-EXFIL-004 | `volume_exfil` | Outbound volume and upload/download imbalance |
| NSM-EXFIL-005 | `icmp_exfil` | Oversized ICMP payloads |
| NSM-EXFIL-006 | `ftp_exfil` | STOR uploads, sensitive filenames, cleartext creds |
| NSM-WEB-001 | `waf_attack` | SQLi, XSS, traversal, command injection |
| NSM-LAT-001 | `lateral_movement` | Internal fan-out on 22/445/3389 |
| NSM-LAT-002 | `internal_exploit` | Exploit signatures with both endpoints internal |
| NSM-MITM-001/002 | `arp_spoof` | Conflicting IP↔MAC bindings, gratuitous ARP floods |
| NSM-MITM-003/004/005 | `dns_spoof` | Rogue responder, conflicting answers, short TTLs |
| NSM-MITM-006/007 | `ssl_strip` | TLS downgrade, credentials in cleartext |

## Adding a log source

```python
# nsmkit/parsers.py
def parse_myvendor(line: str) -> Event | None:
    m = MY_RE.match(line)
    if not m:
        return None                 # never raise — the detector scores parsers on a sample
    return Event(timestamp=parse_timestamp(m["ts"]), kind=EventKind.NETWORK_FLOW,
                 action=normalise_action(m["action"]), source_type="myvendor",
                 src_ip=m["src"], dst_ip=m["dst"], dst_port=int(m["dport"]), raw=line)

PARSERS["myvendor"] = parse_myvendor
```

Detectors need no changes — they only see `Event`.

## Adding a detector

```python
# nsmkit/detectors/mine.py
from .base import Detector, register
from ..models import Finding

@register
class MyDetector(Detector):
    name = "my_detector"
    rule_prefix = "NSM-CUSTOM"
    description = "What it finds."

    def run(self, events):
        cfg = self.cfg                      # thresholds from config
        findings = []
        # ... group, window, decide ...
        return findings
```

Import it in `detectors/__init__.py`. The `@register` decorator wires it into every run.

## Tests

```bash
python tests/test_nsmkit.py     # or, for every toolkit at once: python run_tests.py
```

46 tests: parser grammars, enrichment maths, a positive case for every detector, and a **negative
case for every rule that could plausibly over-fire** (a busy client is not a scan; deep-and-narrow
is not a spray; normal browsing is not a DNS tunnel; an HTTP-only site is not a downgrade).

## One gotcha worth knowing

`ipaddress.is_private` flags the RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) as private — and those are exactly the addresses sanitised
logs use for the **external attacker**. Using it inverts every direction check and silently
disables all egress detection. `nsmkit` classifies internal addresses explicitly; if you write
your own tooling, do the same. Spec §3.2.
