"""
Tunable thresholds and environment context.

Every number a detector uses lives here, so tuning an environment is a config
edit rather than a code edit. Load a site profile with
``Config.from_json("site.json")``; unspecified keys keep the defaults below.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Config:
    # ---------------- environment ----------------
    home_nets: list[str] = field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "fc00::/7", "fe80::/10",          # IPv6 unique-local + link-local (captures now carry IPv6)
    ])
    dmz_nets: list[str] = field(default_factory=list)
    vpn_pool_nets: list[str] = field(default_factory=lambda: ["10.8.0.0/16"])
    known_resolvers: list[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4", "1.1.1.1"])
    gateway_ips: list[str] = field(default_factory=list)

    # ---------------- allowlists (false-positive suppression) ----------------
    scanner_allowlist: list[str] = field(default_factory=list)      # internal vuln scanners
    external_scanner_allowlist: list[str] = field(default_factory=list)  # Shodan, Censys...
    domain_allowlist: list[str] = field(default_factory=lambda: [
        # High-volume, high-entropy-by-design domains that otherwise trip DNS rules.
        "in-addr.arpa", "ip6.arpa", "akamai.net", "akamaiedge.net", "cloudfront.net",
        "azure.com", "windowsupdate.com", "office365.com", "spotify.com",
        "trafficmanager.net", "amazonaws.com", "googleusercontent.com",
        "dropbox.com", "sophosxl.net", "mcafee.com", "avts.mcafee.com",
    ])
    upload_destination_allowlist: list[str] = field(default_factory=list)
    service_accounts: list[str] = field(default_factory=list)       # expected to auth often
    business_hours: tuple[int, int] = (8, 18)                        # local hours, inclusive-exclusive

    # ---------------- scanning ----------------
    vertical_scan_min_ports: int = 10        # distinct dst ports on one dst IP
    vertical_scan_window_s: int = 300
    horizontal_scan_min_hosts: int = 15      # distinct dst IPs on one dst port
    horizontal_scan_window_s: int = 300
    scan_block_ratio: float = 0.60           # >=60% blocked => probing, not client traffic
    ping_sweep_min_hosts: int = 10
    internal_scan_min_ports: int = 5         # internal recon is quieter; lower bar
    internal_scan_min_hosts: int = 5

    # ---------------- brute force / credential access ----------------
    bruteforce_min_failures: int = 10        # failures from one src to one service
    bruteforce_window_s: int = 600
    spray_min_users: int = 8                 # distinct users failed from one src
    spray_max_attempts_per_user: int = 3     # low-and-slow signature of spraying
    spray_window_s: int = 3600
    success_after_failures: int = 5          # failures preceding a success => likely crack
    success_after_window_s: int = 900
    impossible_travel_min_countries: int = 2

    # ---------------- beaconing ----------------
    beacon_min_events: int = 8
    beacon_max_jitter: float = 0.35          # coefficient of variation
    beacon_max_mad_ratio: float = 0.25
    beacon_min_period_s: float = 30.0        # below this it is chatty app traffic
    beacon_max_period_s: float = 86400.0
    beacon_size_cv_max: float = 0.30         # near-constant payload size raises confidence

    # ---------------- DNS exfiltration ----------------
    dns_min_qname_len: int = 60
    dns_min_label_len: int = 30
    dns_min_entropy: float = 3.8
    dns_min_queries_per_domain: int = 50
    dns_min_unique_subdomains: int = 25
    dns_nxdomain_ratio: float = 0.50
    dns_suspicious_qtypes: list[str] = field(default_factory=lambda: ["TXT", "NULL", "CNAME", "MX", "ANY"])
    dns_min_hosts_for_campaign: int = 2      # same domain queried by N+ internal hosts

    # ---------------- volume-based exfiltration ----------------
    exfil_min_total_bytes: int = 50 * 1024 * 1024    # per src->dst pair, per window
    exfil_window_s: int = 3600
    exfil_out_in_ratio: float = 5.0                  # upload/download imbalance
    http_post_large_bytes: int = 600                 # matches the lab dataset; raise in prod
    http_min_posts_to_new_domain: int = 5
    icmp_payload_suspicious_bytes: int = 64          # normal ping payload is 32-56B
    icmp_min_packets: int = 20
    ftp_stor_min_transfers: int = 3

    # ---------------- lateral movement ----------------
    lateral_min_targets: int = 3             # internal hosts touched on lateral ports
    lateral_window_s: int = 3600

    # ---------------- MITM ----------------
    arp_min_conflicting_macs: int = 2        # distinct MACs claiming one IP
    arp_gratuitous_burst: int = 5            # unsolicited replies in the window
    arp_window_s: int = 60
    dns_spoof_ttl_max: int = 60              # attacker TTLs are deliberately short
    dns_spoof_race_window_s: float = 2.0     # two answers to one query within this gap

    # ---------------- reporting ----------------
    max_evidence_lines: int = 10
    min_severity: str = "info"

    # ---------------- helpers ----------------
    @classmethod
    def from_json(cls, path: str) -> "Config":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        cfg = cls()
        for key, value in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg

    def to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_CONFIG = Config()
