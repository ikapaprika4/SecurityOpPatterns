"""Every threshold a detector uses, in one place -- tuning is a config edit,
never a code edit (same rule as nsmkit/phishkit)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class Config:
    # --- Nmap scan fingerprinting ---------------------------------------
    # TCP Connect scans finish the 3-way handshake and carry a "real" window
    # size (>1024, since the OS's socket layer is behind the SYN, expecting
    # to receive real application data). SYN scans are crafted directly by
    # the scanner and typically ship a small/static window.
    scan_connect_window_floor: int = 1024
    # A source touching this many distinct destination ports on one host
    # inside the window below is a vertical (port) scan.
    vertical_scan_min_ports: int = 15
    vertical_scan_window_seconds: int = 60
    # A source touching this many distinct hosts on one port is a horizontal
    # (host-sweep) scan.
    horizontal_scan_min_hosts: int = 10
    horizontal_scan_window_seconds: int = 60
    udp_scan_min_unreachables: int = 8
    udp_scan_window_seconds: int = 60

    # --- ARP spoofing / flooding ----------------------------------------
    # >1 MAC claiming the same IP inside the window is a spoofing signal.
    arp_conflict_window_seconds: int = 120
    # A single MAC issuing this many ARP *requests* against distinct target
    # IPs inside the window looks like a sweep / flood, not organic traffic.
    arp_flood_min_targets: int = 20
    arp_flood_window_seconds: int = 30

    # --- ICMP / DNS tunnelling -------------------------------------------
    icmp_tunnel_payload_len_floor: int = 64      # a stock ping is ~32-64B
    icmp_tunnel_min_packets: int = 20
    icmp_tunnel_window_seconds: int = 120
    dns_tunnel_qname_len_floor: int = 40
    dns_tunnel_min_queries: int = 15
    dns_tunnel_window_seconds: int = 120
    # Names that are long / digit-heavy by design. Reverse lookups matter most:
    # an IPv6 PTR name is 72 characters of hex nibbles, and a burst of them
    # (Windows and Wireshark both resolve addresses) looked exactly like a tunnel.
    dns_tunnel_allowlist: tuple = (
        "in-addr.arpa", "ip6.arpa", "akamai.net", "akamaiedge.net", "akamaized.net",
        "cloudfront.net", "trafficmanager.net", "azureedge.net", "windowsupdate.com",
        "googleusercontent.com", "gvt1.com", "gvt2.com", "amazonaws.com", "fastly.net",
        "edgekey.net", "edgesuite.net", "sophosxl.net", "mcafee.com", "spamhaus.org",
        "local", "_tcp.local", "_udp.local",
    )

    # --- FTP / HTTP brute force & credential hunting ----------------------
    bruteforce_min_failures: int = 5
    bruteforce_window_seconds: int = 120
    spray_min_targets: int = 5
    spray_max_per_target: int = 3
    spray_window_seconds: int = 300

    # --- HTTP anomalies ----------------------------------------------------
    scanner_user_agents: tuple = ("sqlmap", "nmap", "wfuzz", "nikto", "nessus",
                                   "acunetix", "havij", "gobuster", "dirbuster")

    # --- ACL generation -----------------------------------------------------
    acl_default_action: str = "deny"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=list)

    @classmethod
    def from_json(cls, text: str) -> "Config":
        data = json.loads(text)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
