"""
Data-exfiltration detectors across the four channels the material covers
(DNS, HTTP, FTP, ICMP) plus generic volume analysis.

The unifying question for every rule here is: is an internal host pushing more
data outward than its role justifies, over a channel chosen for its ability to
cross the perimeter unexamined?
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Sequence

from ..enrich import (consonant_run, digit_ratio, human_bytes, in_networks,
                      longest_label, looks_encoded, registered_domain,
                      shannon_entropy, subdomain_part)
from ..models import Action, Event, EventKind, Finding
from .base import Detector, register


# ==========================================================================
# DNS tunnelling
# ==========================================================================

@register
class DNSTunnelDetector(Detector):
    name = "dns_tunnel"
    rule_prefix = "NSM-EXFIL"
    description = "Data encoded into DNS subdomain labels or TXT records."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        dns_events = [e for e in events
                      if (e.kind == EventKind.DNS or e.dns_query) and e.dns_query]
        if not dns_events:
            return []

        by_domain: dict[str, list[Event]] = defaultdict(list)
        for ev in dns_events:
            reg = registered_domain(ev.dns_query)
            if not reg:
                continue
            if any(reg == d or reg.endswith("." + d) for d in cfg.domain_allowlist):
                continue
            by_domain[reg].append(ev)

        findings: list[Finding] = []
        for domain, evs in by_domain.items():
            evs.sort(key=lambda e: e.timestamp)
            queries = [e.dns_query for e in evs if e.dns_query]
            subs = [subdomain_part(q) for q in queries]
            subs = [s for s in subs if s]

            # ---- feature extraction ----
            qname_lens = [len(q) for q in queries]
            max_len = max(qname_lens) if qname_lens else 0
            mean_len = statistics.fmean(qname_lens) if qname_lens else 0
            max_label = max((longest_label(q) for q in queries), default=0)
            entropies = [shannon_entropy(s.replace(".", "")) for s in subs if len(s) >= 8]
            mean_entropy = statistics.fmean(entropies) if entropies else 0.0
            unique_subs = len(set(subs))
            encoded_hits = sum(1 for s in subs
                               for label in s.split(".")
                               if looks_encoded(label))
            qtypes = [(e.dns_qtype or "").upper() for e in evs if e.dns_qtype]
            odd_qtypes = sum(1 for q in qtypes if q in cfg.dns_suspicious_qtypes)
            nx = sum(1 for e in evs if (e.dns_rcode or "").upper() in ("NXDOMAIN", "3"))
            responses = sum(1 for e in evs if e.dns_is_response)
            no_response_ratio = 1.0 - (responses / len(evs)) if evs else 0.0
            hosts = sorted({e.src_ip for e in evs if e.src_ip})
            long_runs = statistics.fmean([consonant_run(s) for s in subs]) if subs else 0
            digits = statistics.fmean([digit_ratio(s) for s in subs]) if subs else 0

            # ---- scoring ----
            score, reasons = 0, []
            if max_len >= cfg.dns_min_qname_len:
                score += 2; reasons.append(f"max qname length {max_len} chars")
            if max_label >= cfg.dns_min_label_len:
                score += 2; reasons.append(f"longest single label {max_label} chars")
            if mean_entropy >= cfg.dns_min_entropy:
                score += 3; reasons.append(f"mean subdomain entropy {mean_entropy:.2f} bits/char")
            if len(evs) >= cfg.dns_min_queries_per_domain:
                score += 2; reasons.append(f"{len(evs)} queries to one domain")
            if unique_subs >= cfg.dns_min_unique_subdomains:
                score += 2; reasons.append(f"{unique_subs} unique subdomains (no caching benefit)")
            if encoded_hits >= 3:
                score += 2; reasons.append(f"{encoded_hits} labels match base32/base64/hex")
            if odd_qtypes >= 3:
                score += 1; reasons.append(f"{odd_qtypes} queries used {sorted(set(qtypes))} record types")
            if len(evs) >= 10 and nx / len(evs) >= cfg.dns_nxdomain_ratio:
                score += 2; reasons.append(f"NXDOMAIN ratio {nx / len(evs):.0%}")
            if len(evs) >= 10 and no_response_ratio >= 0.8:
                score += 1; reasons.append("queries largely unanswered (exfil-by-query)")
            if len(hosts) >= cfg.dns_min_hosts_for_campaign:
                score += 1; reasons.append(f"{len(hosts)} internal hosts querying the same domain")
            if long_runs >= 8:
                score += 1; reasons.append(f"mean consonant run {long_runs:.1f} (machine-generated labels)")
            if digits >= 0.25:
                score += 1; reasons.append(f"digit ratio {digits:.0%}")

            if score < 5:
                continue

            severity = "critical" if score >= 10 else "high" if score >= 7 else "medium"
            # Rough capacity estimate: usable encoded bytes per query x query count.
            est_bytes = int(sum(len(s.replace(".", "")) for s in subs) * 5 / 8)

            f = Finding(
                rule_id="NSM-EXFIL-001",
                title=f"DNS tunnelling to {domain} ({len(evs)} queries, score {score})",
                severity=severity,
                confidence="high" if score >= 8 else "medium",
                description=(
                    f"Queries to {domain} carry the fingerprints of an encoded covert channel: "
                    + "; ".join(reasons) + ". DNS is allowed outbound almost everywhere, which is "
                    "precisely why it is used to smuggle data past the proxy and firewall."
                ),
                entity=domain,
                src_ip=hosts[0] if len(hosts) == 1 else None,
                mitre=["T1071.004", "T1048.003"],
                kill_chain="Exfiltration",
                metrics={
                    "domain": domain, "queries": len(evs),
                    "unique_subdomains": unique_subs,
                    "max_qname_len": max_len, "mean_qname_len": round(mean_len, 1),
                    "max_label_len": max_label,
                    "mean_entropy": round(mean_entropy, 3),
                    "encoded_labels": encoded_hits,
                    "nxdomain_ratio": round(nx / len(evs), 3) if evs else 0,
                    "qtypes": sorted(set(qtypes))[:10],
                    "internal_hosts": hosts[:20],
                    "estimated_bytes_exfiltrated": est_bytes,
                    "score": score,
                },
                recommendation=(
                    f"Sinkhole or block {domain} at the resolver. Force all internal DNS through the "
                    "corporate resolver and alert on direct :53 egress. Investigate each querying host "
                    "for the implant driving the tunnel."
                ),
            )
            findings.append(self._attach(f, evs))
        return findings


@register
class DNSDirectEgressDetector(Detector):
    name = "dns_direct_egress"
    rule_prefix = "NSM-EXFIL"
    description = "Internal hosts resolving against unapproved external resolvers."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            if ev.dst_port != 53 and ev.kind != EventKind.DNS:
                continue
            if not (ev.src_ip and ev.dst_ip):
                continue
            if not in_networks(ev.src_ip, cfg.home_nets):
                continue
            if in_networks(ev.dst_ip, cfg.home_nets):
                continue
            if ev.dst_ip in cfg.known_resolvers:
                continue
            groups[(ev.src_ip, ev.dst_ip)].append(ev)

        findings = []
        for (src, dst), evs in groups.items():
            if len(evs) < 5:
                continue
            f = Finding(
                rule_id="NSM-EXFIL-002",
                title=f"DNS to unapproved resolver: {src} -> {dst}",
                severity="medium",
                confidence="medium",
                description=(
                    f"{src} sent {len(evs)} DNS queries directly to {dst}, which is not in the approved "
                    f"resolver list {cfg.known_resolvers}. Bypassing the corporate resolver defeats DNS "
                    "logging and filtering, and is a prerequisite for most DNS tunnelling."
                ),
                src_ip=src, dst_ip=dst,
                mitre=["T1071.004"],
                kill_chain="Command & Control",
                metrics={"queries": len(evs), "resolver": dst},
                recommendation="Block outbound 53/udp+tcp except from the corporate resolvers.",
            )
            findings.append(self._attach(f, sorted(evs, key=lambda e: e.timestamp)))
        return findings


# ==========================================================================
# HTTP / volume exfiltration
# ==========================================================================

@register
class HTTPExfilDetector(Detector):
    name = "http_exfil"
    rule_prefix = "NSM-EXFIL"
    description = "Large or repeated HTTP POST uploads to external destinations."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        posts = [e for e in events
                 if (e.http_method or "").upper() == "POST"
                 and e.src_ip and in_networks(e.src_ip, cfg.home_nets)]
        if not posts:
            return []

        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in posts:
            dest = ev.http_host or ev.dst_ip or "unknown"
            if dest in cfg.upload_destination_allowlist:
                continue
            groups[(ev.src_ip, dest)].append(ev)

        # Environment baseline: what a "normal" POST looks like here.
        all_sizes = [e.bytes_out for e in posts if e.bytes_out > 0]
        baseline = statistics.median(all_sizes) if all_sizes else 0

        findings = []
        for (src, dest), evs in groups.items():
            evs.sort(key=lambda e: e.timestamp)
            total = sum(e.bytes_out for e in evs)
            largest = max((e.bytes_out for e in evs), default=0)
            big = [e for e in evs if e.bytes_out >= cfg.http_post_large_bytes]

            triggered = (
                total >= cfg.exfil_min_total_bytes
                or len(big) >= 1
                or (len(evs) >= cfg.http_min_posts_to_new_domain and baseline and largest > 10 * baseline)
            )
            if not triggered:
                continue

            score = 0
            if total >= cfg.exfil_min_total_bytes:
                score += 3
            if largest >= cfg.http_post_large_bytes * 2:
                score += 2
            if len(evs) >= cfg.http_min_posts_to_new_domain:
                score += 1
            if baseline and largest > 20 * baseline:
                score += 2
            if any("exfil" in (e.signature or "").lower()
                   or "post large" in (e.signature or "").lower() for e in evs):
                score += 3
            if not in_networks(dest, cfg.home_nets) and dest.count(".") >= 1:
                score += 1

            severity = "critical" if score >= 7 else "high" if score >= 4 else "medium"
            f = Finding(
                rule_id="NSM-EXFIL-003",
                title=f"HTTP upload to {dest}: {human_bytes(total)} from {src}",
                severity=severity,
                confidence="high" if score >= 6 else "medium",
                description=(
                    f"{src} issued {len(evs)} POST requests to {dest} totalling {human_bytes(total)} "
                    f"(largest single request {human_bytes(largest)}; environment median POST "
                    f"{human_bytes(baseline)}). Bulk data in POST bodies to an unusual destination is the "
                    "most common exfiltration path because it blends into ordinary web traffic."
                ),
                src_ip=src, entity=dest,
                mitre=["T1041", "T1048.003", "T1567.002"],
                kill_chain="Exfiltration",
                metrics={"posts": len(evs), "total_bytes": total,
                         "largest_bytes": largest, "baseline_median_bytes": baseline,
                         "destination": dest,
                         "uris": sorted({e.http_uri for e in evs if e.http_uri})[:10],
                         "score": score},
                recommendation=(
                    f"Block {dest} at the proxy, capture full PCAP for the session, and determine what "
                    "was uploaded. Check the source host for staging artefacts (recent archives)."
                ),
            )
            findings.append(self._attach(f, evs))
        return findings


@register
class VolumeExfilDetector(Detector):
    name = "volume_exfil"
    rule_prefix = "NSM-EXFIL"
    description = "Protocol-agnostic outbound volume and upload/download imbalance."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        pairs: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            if not (ev.src_ip and ev.dst_ip):
                continue
            if not in_networks(ev.src_ip, cfg.home_nets):
                continue
            if in_networks(ev.dst_ip, cfg.home_nets):
                continue
            if ev.bytes_out or ev.bytes_in:
                pairs[(ev.src_ip, ev.dst_ip)].append(ev)

        findings = []
        for (src, dst), evs in pairs.items():
            evs.sort(key=lambda e: e.timestamp)
            out = sum(e.bytes_out for e in evs)
            inn = sum(e.bytes_in for e in evs)
            if out < cfg.exfil_min_total_bytes:
                continue
            ratio = out / inn if inn else float("inf")
            if ratio < cfg.exfil_out_in_ratio:
                continue

            f = Finding(
                rule_id="NSM-EXFIL-004",
                title=f"Outbound volume anomaly: {src} -> {dst} ({human_bytes(out)} up)",
                severity="high",
                confidence="medium",
                description=(
                    f"{src} uploaded {human_bytes(out)} to {dst} while downloading only "
                    f"{human_bytes(inn)} (ratio {ratio:.1f}:1) across {len(evs)} flows. Normal client "
                    "traffic is download-heavy; a sustained inverted ratio to one external host is the "
                    "shape of a bulk transfer out."
                ),
                src_ip=src, dst_ip=dst,
                mitre=["T1041"],
                kill_chain="Exfiltration",
                metrics={"bytes_out": out, "bytes_in": inn,
                         "ratio": round(ratio, 2) if inn else None,
                         "flows": len(evs),
                         "ports": sorted({e.dst_port for e in evs if e.dst_port})[:10]},
                recommendation="Identify the process on the source host; block the destination pending review.",
            )
            findings.append(self._attach(f, evs))
        return findings


# ==========================================================================
# ICMP tunnelling
# ==========================================================================

@register
class ICMPExfilDetector(Detector):
    name = "icmp_exfil"
    rule_prefix = "NSM-EXFIL"
    description = "Oversized or high-volume ICMP echo carrying encoded payload."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in events:
            if ev.protocol != "icmp" and ev.kind != EventKind.ICMP:
                continue
            if not (ev.src_ip and ev.dst_ip):
                continue
            groups[(ev.src_ip, ev.dst_ip)].append(ev)

        findings = []
        for (src, dst), evs in groups.items():
            evs.sort(key=lambda e: e.timestamp)
            payloads = [e.icmp_payload_len for e in evs if e.icmp_payload_len]
            if not payloads and not any(e.bytes_out for e in evs):
                continue
            sizes = payloads or [e.bytes_out for e in evs if e.bytes_out]
            if not sizes:
                continue
            big = [s for s in sizes if s > cfg.icmp_payload_suspicious_bytes]
            if len(big) < 3 and len(evs) < cfg.icmp_min_packets:
                continue

            max_size = max(sizes)
            score = 0
            if max_size > cfg.icmp_payload_suspicious_bytes:
                score += 3
            if max_size > 256:
                score += 2
            if len(evs) >= cfg.icmp_min_packets:
                score += 1
            if not in_networks(dst, cfg.home_nets):
                score += 2
            entropies = [shannon_entropy(str(e.extra.get("payload", "")))
                         for e in evs if e.extra.get("payload")]
            if entropies and statistics.fmean(entropies) >= 4.5:
                score += 3
            if score < 4:
                continue

            f = Finding(
                rule_id="NSM-EXFIL-005",
                title=f"ICMP tunnelling: {src} -> {dst} (max payload {max_size}B)",
                severity="high" if score >= 6 else "medium",
                confidence="medium",
                description=(
                    f"{len(evs)} ICMP packets from {src} to {dst}; {len(big)} carried payloads above "
                    f"{cfg.icmp_payload_suspicious_bytes} bytes (max {max_size}B). A standard ping payload "
                    "is 32-56 bytes -- anything materially larger is carrying data, not diagnostics."
                ),
                src_ip=src, dst_ip=dst,
                mitre=["T1095", "T1048.003"],
                kill_chain="Exfiltration",
                metrics={"packets": len(evs), "max_payload": max_size,
                         "oversized_packets": len(big),
                         "mean_payload": round(statistics.fmean(sizes), 1),
                         "external_destination": not in_networks(dst, cfg.home_nets),
                         "score": score},
                recommendation="Block ICMP egress to the internet; extract and decode the payloads from PCAP.",
            )
            findings.append(self._attach(f, evs))
        return findings


# ==========================================================================
# FTP
# ==========================================================================

_SENSITIVE_EXT = (".csv", ".xlsx", ".xls", ".pdf", ".doc", ".docx", ".sql",
                  ".db", ".bak", ".zip", ".rar", ".7z", ".tar", ".gz", ".pst", ".key", ".pem")


@register
class FTPExfilDetector(Detector):
    name = "ftp_exfil"
    rule_prefix = "NSM-EXFIL"
    description = "FTP STOR uploads, cleartext credentials, sensitive filenames."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        ftp = [e for e in events if e.kind == EventKind.FTP or e.dst_port in (20, 21)]
        if not ftp:
            return []

        groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in ftp:
            if ev.src_ip and ev.dst_ip:
                groups[(ev.src_ip, ev.dst_ip)].append(ev)

        findings = []
        for (src, dst), evs in groups.items():
            evs.sort(key=lambda e: e.timestamp)
            stors = [e for e in evs if (e.ftp_command or "").upper() == "STOR"]
            users = sorted({e.ftp_arg for e in evs if (e.ftp_command or "").upper() == "USER" and e.ftp_arg})
            passes = [e for e in evs if (e.ftp_command or "").upper() == "PASS"]
            files = [e.ftp_arg for e in stors if e.ftp_arg]
            sensitive = [f for f in files if f.lower().endswith(_SENSITIVE_EXT)]

            if not stors and not sensitive:
                continue
            if len(stors) < cfg.ftp_stor_min_transfers and not sensitive:
                continue

            score = 2 * bool(stors) + 3 * bool(sensitive)
            if not in_networks(dst, cfg.home_nets):
                score += 3
            if any(u.lower() in ("anonymous", "guest", "ftp", "test") for u in users):
                score += 2
            if passes:
                score += 1  # cleartext credentials observable on the wire

            f = Finding(
                rule_id="NSM-EXFIL-006",
                title=f"FTP upload: {src} -> {dst} ({len(stors)} STOR, {len(sensitive)} sensitive)",
                severity="critical" if score >= 7 else "high" if score >= 5 else "medium",
                confidence="high" if sensitive else "medium",
                description=(
                    f"{len(stors)} STOR (upload) commands from {src} to {dst}"
                    + (f", including {', '.join(sensitive[:5])}" if sensitive else "")
                    + (f". Authenticated as {', '.join(users[:3])}" if users else "")
                    + ". FTP transmits credentials and data in cleartext, so the control channel gives "
                      "both the account used and the exact filenames taken."
                ),
                src_ip=src, dst_ip=dst,
                user=users[0] if users else None,
                mitre=["T1048.003"],
                kill_chain="Exfiltration",
                metrics={"stor_count": len(stors), "files": files[:20],
                         "sensitive_files": sensitive[:20], "users": users[:10],
                         "cleartext_password_observed": bool(passes),
                         "external_destination": not in_networks(dst, cfg.home_nets),
                         "score": score},
                recommendation=(
                    "Block plaintext FTP egress. Reconstruct the transferred files from PCAP "
                    "(Follow TCP Stream / File Export) to scope exactly what left, and rotate the "
                    "credentials that appeared in cleartext."
                ),
            )
            findings.append(self._attach(f, evs))
        return findings


# ==========================================================================
# Staging (precursor to exfiltration)
# ==========================================================================

@register
class WAFAttackDetector(Detector):
    name = "waf_attack"
    rule_prefix = "NSM-WEB"
    description = "Web application attacks reported by a WAF/IDS (SQLi, XSS, traversal)."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in events:
            sig = (ev.signature or "").lower()
            if not sig:
                continue
            if any(k in sig for k in ("sql injection", "sqli", "xss", "directory traversal",
                                      "path traversal", "command injection", "rfi", "lfi",
                                      "web_server", "web-application")):
                if ev.src_ip:
                    by_src[ev.src_ip].append(ev)

        findings = []
        for src, evs in by_src.items():
            evs.sort(key=lambda e: e.timestamp)
            types = sorted({(e.signature or "").strip() for e in evs})
            targets = sorted({e.dst_ip for e in evs if e.dst_ip})
            blocked = sum(1 for e in evs if e.action in (Action.BLOCK, Action.DROP))
            severity = "high" if len(types) >= 2 or blocked < len(evs) else "medium"

            f = Finding(
                rule_id="NSM-WEB-001",
                title=f"Web application attack from {src} ({len(types)} technique(s))",
                severity=severity,
                confidence="high",
                description=(
                    f"{len(evs)} web-attack signatures from {src} against {len(targets)} host(s): "
                    f"{'; '.join(types[:5])}. {blocked}/{len(evs)} were blocked. Multiple distinct "
                    "attack classes from one source indicates deliberate, tool-driven probing rather "
                    "than a stray scanner hit."
                ),
                src_ip=src,
                mitre=["T1190", "T1059"],
                kill_chain="Exploitation",
                metrics={"alerts": len(evs), "attack_types": types[:15],
                         "targets": targets[:15], "blocked": blocked,
                         "unblocked": len(evs) - blocked},
                recommendation=(
                    "Block the source. For any attack that was NOT blocked, treat the target as "
                    "potentially compromised and review its application and OS logs."
                ),
            )
            findings.append(self._attach(f, evs))
        return findings
