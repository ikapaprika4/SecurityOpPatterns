"""
Verification suite. Run with:  python -m pytest tests/ -q
(or plain `python tests/test_nsmkit.py` -- it works without pytest too.)

Covers parsing correctness, each detector's positive case, each detector's
negative case (so a rule that fires on everything fails here), and correlation.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nsmkit import Config, run_detectors                      # noqa: E402
from nsmkit.correlate import correlate, summarise, vpn_pivots  # noqa: E402
from nsmkit.enrich import (dominant_period, jitter_ratio, looks_encoded,       # noqa: E402
                           registered_domain, shannon_entropy, subdomain_part)
from nsmkit.models import Action, Event, EventKind             # noqa: E402
from nsmkit.parsers import (detect_parser, parse_firewall, parse_ids_alert,    # noqa: E402
                            parse_kv, parse_timestamp, parse_vpn_auth)

T0 = datetime(2025, 9, 1, 0, 0, 0)
CFG = Config(home_nets=["10.0.0.0/8"], vpn_pool_nets=["10.8.0.0/16"],
             known_resolvers=["8.8.8.8"], gateway_ips=["10.0.0.1"])


def _ids(findings):
    return {f.rule_id for f in findings}


# ==========================================================================
# Parsing
# ==========================================================================

def test_parse_firewall():
    ev = parse_firewall("2025-08-25 00:47:46 ALLOW TCP 203.0.113.100:62718 -> 10.0.0.50:443")
    assert ev is not None
    assert ev.src_ip == "203.0.113.100" and ev.src_port == 62718
    assert ev.dst_ip == "10.0.0.50" and ev.dst_port == 443
    assert ev.action is Action.ALLOW and ev.protocol == "tcp"
    assert ev.direction == "inbound"

    ev = parse_firewall("2025-08-26 12:12:47 BLOCK TCP 203.0.113.10:64292 -> 10.0.0.50:21")
    assert ev.action is Action.BLOCK and ev.dst_port == 21


def test_parse_ids_alert():
    line = ("2025-08-25 00:12:53 [**] [1:2003272:1] ET POLICY Suspicious HTTP [**] "
            "[Classification: Suspicious Activity] [Priority: 3] {TCP} "
            "198.51.100.92:20127 -> 10.0.0.20:22")
    ev = parse_ids_alert(line)
    assert ev is not None
    assert ev.sid == "1:2003272:1"
    assert ev.signature == "ET POLICY Suspicious HTTP"
    assert ev.classification == "Suspicious Activity"
    assert ev.priority == 3
    assert ev.dst_port == 22
    assert ev.kind is EventKind.IDS_ALERT


def test_parse_snort_native_no_ports():
    line = ('07/24-10:46:52.401504  [**] [1:1000001:1] "Loopback Ping Detected" [**] '
            '[Priority: 0] {ICMP} 127.0.0.1 -> 127.0.0.1')
    ev = parse_ids_alert(line)
    assert ev is not None
    assert ev.signature == "Loopback Ping Detected"
    assert ev.protocol == "icmp" and ev.src_port is None


def test_parse_vpn_both_styles():
    ev = parse_vpn_auth("2025-08-25 08:27:38 203.0.113.100 svc_backup SUCCESS assigned_ip=10.8.0.131")
    assert ev.user == "svc_backup" and ev.action is Action.SUCCESS
    assert ev.assigned_ip == "10.8.0.131"

    ev = parse_vpn_auth("2025-09-03 02:19:00 203.0.113.10 svc_backup FAIL")
    assert ev.action is Action.FAILURE and ev.assigned_ip is None

    ev = parse_vpn_auth("2025-09-22 10:12:11 FAILED_AUTH TCP 1.2.3.4:31245 -> 10.0.0.1:443 (user 'admin')")
    assert ev.user == "admin" and ev.action is Action.FAILURE and ev.dst_port == 443


def test_parse_waf_kv():
    line = ('timestamp=2025-09-22T09:14:46Z src_ip=203.0.113.9 action=BLOCK '
            'request="GET /search.php?q=<script>alert(1)</script>" rule_id=941100 attack_type="XSS"')
    ev = parse_kv(line)
    assert ev.action is Action.BLOCK and ev.signature == "XSS"
    assert ev.http_method == "GET" and ev.sid == "941100"


def test_timestamp_formats():
    assert parse_timestamp("2025-08-25 00:47:46").year == 2025
    assert parse_timestamp("2025-09-22T09:14:44Z").hour == 9
    assert parse_timestamp("Sep 7, 2025 @ 17:16:42.944").minute == 16
    assert parse_timestamp("1757265402.944286").year >= 2025
    assert parse_timestamp("not a time") is None


def test_parser_autodetect():
    fw = ["2025-08-25 00:47:46 ALLOW TCP 1.2.3.4:1 -> 10.0.0.1:80"] * 5
    assert detect_parser(fw)[0] == "firewall"
    vpn = ["2025-08-25 08:27:38 1.2.3.4 alice SUCCESS assigned_ip=10.8.0.1"] * 5
    assert detect_parser(vpn)[0] == "vpn"


# ==========================================================================
# Enrichment maths
# ==========================================================================

def test_entropy_and_encoding():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("MFRGGZDFMZTWQ2LKNNWG23TP") > 3.5
    assert looks_encoded("MFRGGZDFMZTWQ2LKNNWG23TP") in ("base32", "base64")
    assert looks_encoded("deadbeefdeadbeefdead") == "hex"
    assert looks_encoded("www") is None


def test_domain_helpers():
    assert registered_domain("a.b.evil.co.uk") == "evil.co.uk"
    assert registered_domain("data.tunnel.example.com") == "example.com"
    assert subdomain_part("data.tunnel.example.com") == "data.tunnel"


def test_periodicity():
    perfect = [60.0] * 10
    assert jitter_ratio(perfect) == 0.0
    assert dominant_period(perfect) == 60.0
    bursty = [1, 900, 3, 2, 1200, 5, 2]
    assert jitter_ratio(bursty) > 0.8
    jittered = [60, 66, 55, 62, 58, 64, 57]     # +/-10% jitter
    assert jitter_ratio(jittered) < 0.15


# ==========================================================================
# Detector positives
# ==========================================================================

def _fw(t, src, sport, dst, dport, action=Action.ALLOW):
    return Event(timestamp=t, kind=EventKind.NETWORK_FLOW, action=action,
                 source_type="firewall", src_ip=src, src_port=sport,
                 dst_ip=dst, dst_port=dport, protocol="tcp",
                 raw=f"{t} {action.value} TCP {src}:{sport} -> {dst}:{dport}")


def test_vertical_scan_positive():
    evs = [_fw(T0 + timedelta(seconds=i * 2), "203.0.113.10", 50000 + i,
               "10.0.0.50", p, Action.BLOCK)
           for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445])]
    assert "NSM-SCAN-001" in _ids(run_detectors(evs, CFG, ["vertical_scan"]))


def test_vertical_scan_negative_busy_client():
    # A legitimate client hitting a handful of allowed ports must not trip it.
    evs = [_fw(T0 + timedelta(seconds=i * 30), "198.51.100.9", 40000 + i,
               "10.0.0.50", p) for i, p in enumerate([80, 443, 443, 80])]
    assert not run_detectors(evs, CFG, ["vertical_scan"])


def test_horizontal_scan_positive():
    evs = [_fw(T0 + timedelta(seconds=i * 2), "203.0.113.10", 51000 + i,
               f"10.0.0.{20 + i}", 445, Action.BLOCK) for i in range(20)]
    assert "NSM-SCAN-002" in _ids(run_detectors(evs, CFG, ["horizontal_scan"]))


def test_exposed_service_positive():
    evs = [_fw(T0 + timedelta(minutes=i), "203.0.113.10", 53000 + i, "10.0.0.50", 22)
           for i in range(4)]
    assert "NSM-PERIM-001" in _ids(run_detectors(evs, CFG, ["exposed_service"]))


def test_exposed_service_negative_https():
    evs = [_fw(T0 + timedelta(minutes=i), "203.0.113.10", 53000 + i, "10.0.0.50", 443)
           for i in range(20)]
    assert not run_detectors(evs, CFG, ["exposed_service"])


def _auth(t, src, user, action, assigned=None):
    return Event(timestamp=t, kind=EventKind.AUTH, action=action, source_type="vpn",
                 src_ip=src, user=user, assigned_ip=assigned,
                 raw=f"{t} {src} {user} {action.value}")


def test_bruteforce_positive():
    evs = [_auth(T0 + timedelta(seconds=i * 10), "203.0.113.10", "svc_backup", Action.FAILURE)
           for i in range(30)]
    assert "NSM-CRED-001" in _ids(run_detectors(evs, CFG, ["brute_force"]))


def test_bruteforce_negative_typos():
    evs = [_auth(T0 + timedelta(minutes=i * 20), "10.0.0.9", "alice", Action.FAILURE)
           for i in range(4)]
    assert not run_detectors(evs, CFG, ["brute_force"])


def test_password_spray_positive():
    users = [f"user{i}" for i in range(12)]
    evs = [_auth(T0 + timedelta(seconds=i * 60), "203.0.113.10", u, Action.FAILURE)
           for i, u in enumerate(users)]
    assert "NSM-CRED-002" in _ids(run_detectors(evs, CFG, ["password_spray"]))


def test_password_spray_negative_is_bruteforce():
    # Deep-and-narrow must NOT be classified as a spray.
    evs = [_auth(T0 + timedelta(seconds=i * 10), "203.0.113.10", "admin", Action.FAILURE)
           for i in range(40)]
    assert "NSM-CRED-002" not in _ids(run_detectors(evs, CFG, ["password_spray"]))


def test_success_after_failures_positive():
    evs = [_auth(T0 + timedelta(seconds=i * 10), "203.0.113.10", "svc_backup", Action.FAILURE)
           for i in range(20)]
    evs.append(_auth(T0 + timedelta(seconds=210), "203.0.113.10", "svc_backup",
                     Action.SUCCESS, assigned="10.8.0.66"))
    fs = run_detectors(evs, CFG, ["success_after_failures"])
    assert "NSM-CRED-003" in _ids(fs)
    assert fs[0].metrics["assigned_ip"] == "10.8.0.66"


def test_beacon_positive():
    evs = [_fw(T0 + timedelta(seconds=i * 300), "10.0.0.51", 30000 + i,
               "203.0.113.10", 4444) for i in range(24)]
    fs = run_detectors(evs, CFG, ["beaconing"])
    assert "NSM-C2-001" in _ids(fs)
    assert abs(fs[0].metrics["period_seconds"] - 300) < 1


def test_beacon_negative_bursty():
    offsets = [0, 3, 5, 900, 903, 1400, 3000, 3002, 3005, 9000, 9100, 20000]
    evs = [_fw(T0 + timedelta(seconds=o), "10.0.0.51", 30000 + i, "203.0.113.10", 443)
           for i, o in enumerate(offsets)]
    assert not run_detectors(evs, CFG, ["beaconing"])


def _dns(t, src, qname, qtype="A", rcode="NOERROR"):
    return Event(timestamp=t, kind=EventKind.DNS, source_type="dns", src_ip=src,
                 dst_ip="8.8.8.8", dst_port=53, dns_query=qname, dns_qtype=qtype,
                 dns_rcode=rcode, raw=f"{t} {src} {qname}")


def test_dns_tunnel_positive():
    import base64
    payload = b"SENSITIVE-DATA-BLOCK-" * 40
    chunks = [payload[i:i + 30] for i in range(0, len(payload), 30)]
    evs = [_dns(T0 + timedelta(seconds=i * 5), "10.0.0.51",
                f"{base64.b32encode(c).decode().rstrip('=')}.{i:03d}.evil-tunnel.net",
                "TXT", "NXDOMAIN")
           for i, c in enumerate(chunks[:60])]
    fs = run_detectors(evs, CFG, ["dns_tunnel"])
    assert "NSM-EXFIL-001" in _ids(fs)
    assert fs[0].metrics["domain"] == "evil-tunnel.net"


def test_dns_tunnel_negative_normal_browsing():
    hosts = ["www.google.com", "outlook.office365.com", "cdn.jsdelivr.net",
             "api.github.com", "www.bbc.co.uk"]
    evs = [_dns(T0 + timedelta(seconds=i * 7), "10.0.0.51", hosts[i % len(hosts)])
           for i in range(200)]
    assert not run_detectors(evs, CFG, ["dns_tunnel"])


def test_dns_tunnel_negative_allowlisted_cdn():
    # High-entropy but allowlisted -- must be suppressed.
    evs = [_dns(T0 + timedelta(seconds=i * 3), "10.0.0.51",
                f"a{i}b7f3e9d2c8a1f6e4b0d5c9.dscx4nzcgy.cloudfront.net")
           for i in range(120)]
    assert not run_detectors(evs, CFG, ["dns_tunnel"])


def test_http_exfil_positive():
    evs = [Event(timestamp=T0 + timedelta(hours=i), kind=EventKind.HTTP,
                 action=Action.ALLOW, source_type="proxy", src_ip="10.0.0.51",
                 dst_ip="203.0.113.10", http_method="POST", http_host="drop.example",
                 http_uri=f"/u/{i}", bytes_out=8_000_000, raw="post")
           for i in range(12)]
    assert "NSM-EXFIL-003" in _ids(run_detectors(evs, CFG, ["http_exfil"]))


def test_http_exfil_negative_small_forms():
    evs = [Event(timestamp=T0 + timedelta(hours=i), kind=EventKind.HTTP,
                 action=Action.ALLOW, source_type="proxy", src_ip="10.0.0.51",
                 dst_ip="93.184.216.34", http_method="POST", http_host="intranet.example",
                 http_uri="/form", bytes_out=420, raw="post")
           for i in range(30)]
    assert not run_detectors(evs, CFG, ["http_exfil"])


def test_icmp_exfil_positive():
    evs = [Event(timestamp=T0 + timedelta(seconds=i * 2), kind=EventKind.ICMP,
                 source_type="pcap", src_ip="10.0.0.20", dst_ip="203.0.113.99",
                 protocol="icmp", icmp_type=8, icmp_payload_len=240, raw="icmp")
           for i in range(30)]
    assert "NSM-EXFIL-005" in _ids(run_detectors(evs, CFG, ["icmp_exfil"]))


def test_icmp_exfil_negative_normal_ping():
    evs = [Event(timestamp=T0 + timedelta(seconds=i), kind=EventKind.ICMP,
                 source_type="pcap", src_ip="10.0.0.20", dst_ip="10.0.0.1",
                 protocol="icmp", icmp_type=8, icmp_payload_len=32, raw="ping")
           for i in range(60)]
    assert not run_detectors(evs, CFG, ["icmp_exfil"])


def test_lateral_movement_positive():
    evs = []
    for i in range(15):
        evs.append(_fw(T0 + timedelta(minutes=i * 2), "10.8.0.66", 2000 + i,
                       f"10.0.0.{20 + (i % 5)}", [22, 445, 3389][i % 3]))
    assert "NSM-LAT-001" in _ids(run_detectors(evs, CFG, ["lateral_movement"]))


def test_lateral_movement_negative_admin_jumpbox_single_target():
    evs = [_fw(T0 + timedelta(minutes=i), "10.0.0.9", 2000 + i, "10.0.0.20", 22)
           for i in range(30)]
    assert not run_detectors(evs, CFG, ["lateral_movement"])


def _arp(t, sender_ip, sender_mac, op=2, gratuitous=False):
    return Event(timestamp=t, kind=EventKind.ARP, source_type="pcap",
                 src_ip=sender_ip, arp_opcode=op, arp_sender_ip=sender_ip,
                 arp_sender_mac=sender_mac, arp_is_gratuitous=gratuitous,
                 src_mac=sender_mac, raw=f"{sender_ip} is at {sender_mac}")


def test_arp_spoof_positive():
    evs = [_arp(T0 + timedelta(seconds=i), "10.0.0.1", "02:aa:bb:cc:00:01") for i in range(5)]
    evs += [_arp(T0 + timedelta(seconds=10 + i), "10.0.0.1", "02:fe:bb:cd:55:55",
                 gratuitous=True) for i in range(10)]
    fs = run_detectors(evs, CFG, ["arp_spoof"])
    assert "NSM-MITM-001" in _ids(fs)
    assert any(f.severity == "critical" for f in fs)   # gateway => critical


def test_arp_spoof_negative_single_binding():
    evs = [_arp(T0 + timedelta(seconds=i), "10.0.0.1", "02:aa:bb:cc:00:01") for i in range(30)]
    assert not run_detectors(evs, CFG, ["arp_spoof"])


def test_dns_spoof_positive():
    evs = []
    for i in range(3):
        evs.append(Event(timestamp=T0 + timedelta(seconds=i * 10), kind=EventKind.DNS,
                         source_type="pcap", src_ip="8.8.8.8", dst_ip="10.0.0.10",
                         dns_query="portal.corp.local", dns_answer="203.0.113.80",
                         dns_ttl=3600, dns_is_response=True, raw="legit"))
        evs.append(Event(timestamp=T0 + timedelta(seconds=i * 10 + 1), kind=EventKind.DNS,
                         source_type="pcap", src_ip="10.0.0.55", dst_ip="10.0.0.10",
                         dns_query="portal.corp.local", dns_answer="10.0.0.55",
                         dns_ttl=15, dns_is_response=True, raw="forged"))
    fs = _ids(run_detectors(evs, CFG, ["dns_spoof"]))
    assert {"NSM-MITM-003", "NSM-MITM-004", "NSM-MITM-005"} <= fs


def test_ssl_strip_positive():
    evs = [Event(timestamp=T0, kind=EventKind.TLS, source_type="pcap",
                 src_ip="10.0.0.10", dst_ip="203.0.113.80", dst_port=443,
                 http_host="portal.corp.local", raw="tls")]
    evs += [Event(timestamp=T0 + timedelta(seconds=i + 1), kind=EventKind.HTTP,
                  source_type="pcap", src_ip="10.0.0.10", dst_ip="10.0.0.55",
                  dst_port=80, http_host="portal.corp.local", http_method="GET",
                  http_uri="/login", raw="http") for i in range(4)]
    assert "NSM-MITM-006" in _ids(run_detectors(evs, CFG, ["ssl_strip"]))


def test_ssl_strip_negative_http_only_site():
    # A site never seen doing TLS is not a downgrade.
    evs = [Event(timestamp=T0 + timedelta(seconds=i), kind=EventKind.HTTP,
                 source_type="pcap", src_ip="10.0.0.10", dst_ip="203.0.113.80",
                 dst_port=80, http_host="legacy-intranet.local", http_method="GET",
                 http_uri="/", raw="http") for i in range(20)]
    assert "NSM-MITM-006" not in _ids(run_detectors(evs, CFG, ["ssl_strip"]))


# ==========================================================================
# Correlation
# ==========================================================================

def test_vpn_pivot_links_account_to_internal_activity():
    evs = [_auth(T0, "203.0.113.10", "svc_backup", Action.SUCCESS, assigned="10.8.0.66")]
    evs += [_fw(T0 + timedelta(minutes=i + 1), "10.8.0.66", 2000 + i,
                f"10.0.0.{20 + i}", 445) for i in range(5)]
    pivots = vpn_pivots(evs, CFG)
    assert len(pivots) == 1
    assert pivots[0]["user"] == "svc_backup"
    assert pivots[0]["assigned_ip"] == "10.8.0.66"
    assert pivots[0]["target_count"] == 5
    assert pivots[0]["suspicious"] is True


def test_correlation_chains_stages():
    evs = []
    evs += [_fw(T0 + timedelta(seconds=i * 2), "203.0.113.10", 50000 + i, "10.0.0.50",
                p, Action.BLOCK)
            for i, p in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445])]
    evs += [_auth(T0 + timedelta(minutes=10, seconds=i * 10), "203.0.113.10",
                  "svc_backup", Action.FAILURE) for i in range(20)]
    evs.append(_auth(T0 + timedelta(minutes=14), "203.0.113.10", "svc_backup",
                     Action.SUCCESS, assigned="10.8.0.66"))
    evs += [_fw(T0 + timedelta(hours=1, minutes=i * 2), "10.8.0.66", 2000 + i,
                f"10.0.0.{20 + (i % 5)}", [22, 445, 3389][i % 3]) for i in range(15)]

    findings = run_detectors(evs, CFG)
    incidents = correlate(findings)
    assert incidents, "expected at least one incident"
    top = incidents[0]
    assert len(top.stages) >= 3, f"expected a multi-stage chain, got {top.stages}"
    assert "203.0.113.10" in top.entities and "10.8.0.66" in top.entities


def test_summarise_shape():
    evs = [_fw(T0 + timedelta(seconds=i), "203.0.113.10", 1000 + i, "10.0.0.50", 22,
               Action.BLOCK) for i in range(10)]
    s = summarise(evs, CFG)
    assert s["event_count"] == 10
    assert s["top_blocked_sources"][0]["key"] == "203.0.113.10"
    assert s["top_blocked_sources"][0]["count"] == 10


def test_no_findings_on_empty_input():
    assert run_detectors([], CFG) == []
    assert summarise([], CFG)["event_count"] == 0


# ==========================================================================
# Regressions fixed in the workbench refactor
# ==========================================================================

def test_correlate_handles_findings_without_first_seen():
    from nsmkit.models import Finding
    a = Finding(rule_id="X-1", title="a", severity="high", confidence="high", description="",
                src_ip="203.0.113.5", kill_chain="Reconnaissance", first_seen=T0)
    b = Finding(rule_id="X-2", title="b", severity="low", confidence="low", description="",
                src_ip="203.0.113.5", kill_chain="Reconnaissance")
    incidents = correlate([a, b])                     # raised TypeError before
    assert len(incidents) == 1 and [f.rule_id for f in incidents[0].findings] == ["X-1", "X-2"]


def test_resolver_is_not_a_correlation_hub():
    from nsmkit.models import Finding
    cfg = Config(known_resolvers=["10.0.0.53"])
    a = Finding(rule_id="A", title="a", severity="high", confidence="high", description="",
                src_ip="10.0.0.20", dst_ip="10.0.0.53")
    b = Finding(rule_id="B", title="b", severity="high", confidence="high", description="",
                src_ip="10.0.0.99", dst_ip="10.0.0.53")
    assert len(correlate([a, b], cfg)) == 2           # sharing the resolver is not a link


def test_cli_does_not_mutate_default_config():
    from nsmkit.cli import _load_config
    from nsmkit.config import DEFAULT_CONFIG
    cfg = _load_config(None)
    cfg.min_severity = "critical"
    assert DEFAULT_CONFIG.min_severity == "info"


def test_ipv4_mapped_addresses_classified():
    from nsmkit.enrich import in_networks, is_private_ip
    assert is_private_ip("::ffff:10.1.2.3")
    assert in_networks("::ffff:10.1.2.3", ["10.0.0.0/8"])
    assert not is_private_ip("::ffff:203.0.113.5")


def test_library_run_isolates_a_broken_detector():
    from nsmkit.detectors.base import REGISTRY, Detector

    class Boom(Detector):
        name = "boom"

        def run(self, events):
            raise RuntimeError("boom")

    REGISTRY.append(Boom)
    try:
        findings = run_detectors([])
    finally:
        REGISTRY.remove(Boom)
    assert any(f.rule_id == "NSM-ERR-001" for f in findings)


def test_native_pcap_backend_reads_mitm_sample():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    from nsmkit.pcap import read_pcap
    events = read_pcap(os.path.join(root, "samples", "nsmkit", "mitm.pcap"))
    assert len(events) == 70
    ids = {f.rule_id for f in run_detectors(events)}
    for rule in ("NSM-MITM-001", "NSM-MITM-003", "NSM-MITM-006", "NSM-EXFIL-005"):
        assert rule in ids, rule


# ==========================================================================
# Runner (works without pytest)
# ==========================================================================

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
