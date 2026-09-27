"""
Man-in-the-middle detectors: ARP spoofing, DNS spoofing, SSL stripping.

These operate on Layer-2 / DNS-response detail, so they need a PCAP source (see
nsmkit.pcap) or a log source that preserves MAC addresses and DNS answers.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from ..enrich import in_networks
from ..models import Action, Event, EventKind, Finding
from .base import Detector, register


# ==========================================================================
# ARP
# ==========================================================================

@register
class ARPSpoofDetector(Detector):
    name = "arp_spoof"
    rule_prefix = "NSM-MITM"
    description = "Conflicting IP-to-MAC bindings and gratuitous ARP floods."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        arp = [e for e in events if e.kind == EventKind.ARP and e.arp_sender_ip]
        if not arp:
            return []
        arp.sort(key=lambda e: e.timestamp)

        # ip -> {mac: [events]}
        bindings: dict[str, dict[str, list[Event]]] = defaultdict(lambda: defaultdict(list))
        for ev in arp:
            if ev.arp_opcode == 2 and ev.arp_sender_mac:
                bindings[ev.arp_sender_ip][ev.arp_sender_mac].append(ev)

        findings: list[Finding] = []
        for ip, macs in bindings.items():
            if len(macs) < cfg.arp_min_conflicting_macs:
                continue
            # The MAC that claimed the IP later, and less consistently, is the
            # likely impostor; the earliest sustained claimant is the real host.
            ordered = sorted(macs.items(), key=lambda kv: min(e.timestamp for e in kv[1]))
            legit_mac, legit_evs = ordered[0]
            impostors = ordered[1:]
            is_gateway = ip in cfg.gateway_ips

            all_evs = [e for evs in macs.values() for e in evs]
            all_evs.sort(key=lambda e: e.timestamp)

            f = Finding(
                rule_id="NSM-MITM-001",
                title=f"ARP spoofing: {ip} claimed by {len(macs)} MAC addresses",
                severity="critical" if is_gateway else "high",
                confidence="high",
                description=(
                    f"IP {ip} was advertised by {len(macs)} distinct MAC addresses. First/most "
                    f"consistent: {legit_mac} ({len(legit_evs)} replies). Competing claim(s): "
                    + "; ".join(f"{m} ({len(e)} replies)" for m, e in impostors)
                    + (". This IP is the default gateway, so poisoning it puts the attacker inline for "
                       "all traffic leaving the subnet." if is_gateway else ".")
                    + " ARP has no authentication -- any host can assert 'x is at y', which is what "
                      "makes this possible."
                ),
                entity=ip,
                mitre=["T1557.002"],
                kill_chain="Exploitation",
                metrics={"ip": ip, "mac_count": len(macs),
                         "macs": {m: len(e) for m, e in macs.items()},
                         "likely_legitimate_mac": legit_mac,
                         "suspect_macs": [m for m, _ in impostors],
                         "is_gateway": is_gateway},
                recommendation=(
                    "Identify the switch port behind the suspect MAC and isolate it. Deploy Dynamic ARP "
                    "Inspection with DHCP snooping, and add static ARP entries for the gateway on "
                    "critical hosts. Assume all cleartext traffic in the window was observed."
                ),
            )
            findings.append(self._attach(f, all_evs))

        # Gratuitous-ARP flooding: an attacker must keep re-poisoning the cache.
        grat: dict[str, list[Event]] = defaultdict(list)
        for ev in arp:
            if ev.arp_is_gratuitous and ev.arp_sender_mac:
                grat[ev.arp_sender_mac].append(ev)
        for mac, evs in grat.items():
            evs.sort(key=lambda e: e.timestamp)
            left = 0
            best: list[Event] = []
            for right in range(len(evs)):
                while (evs[right].timestamp - evs[left].timestamp).total_seconds() > cfg.arp_window_s:
                    left += 1
                if right - left + 1 > len(best):
                    best = evs[left:right + 1]
            if len(best) < cfg.arp_gratuitous_burst:
                continue
            claimed = sorted({e.arp_sender_ip for e in best if e.arp_sender_ip})
            f = Finding(
                rule_id="NSM-MITM-002",
                title=f"Gratuitous ARP flood from {mac} ({len(best)} replies)",
                severity="high",
                confidence="medium",
                description=(
                    f"{mac} sent {len(best)} unsolicited ARP replies in {cfg.arp_window_s}s claiming "
                    f"{len(claimed)} IP address(es): {', '.join(claimed[:5])}. Repeated gratuitous ARP "
                    "is how an attacker keeps a poisoned cache from ageing out."
                ),
                entity=mac,
                mitre=["T1557.002"],
                kill_chain="Exploitation",
                metrics={"mac": mac, "replies": len(best), "claimed_ips": claimed[:20]},
                recommendation="Trace the MAC to a switch port and isolate; enable Dynamic ARP Inspection.",
            )
            findings.append(self._attach(f, best))

        return findings


# ==========================================================================
# DNS spoofing
# ==========================================================================

@register
class DNSSpoofDetector(Detector):
    name = "dns_spoof"
    rule_prefix = "NSM-MITM"
    description = "Forged DNS answers: rogue responder, conflicting answers, tiny TTLs."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        responses = [e for e in events
                     if e.dns_is_response and e.dns_query and e.timestamp]
        if not responses:
            return []
        responses.sort(key=lambda e: e.timestamp)

        findings: list[Finding] = []

        # --- 1. Answers from a source that is not an approved resolver ---
        rogue: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for ev in responses:
            if not ev.src_ip:
                continue
            if ev.src_ip in cfg.known_resolvers:
                continue
            if in_networks(ev.src_ip, cfg.home_nets) and ev.src_ip in cfg.gateway_ips:
                continue
            rogue[(ev.src_ip, ev.dns_query)].append(ev)

        for (src, qname), evs in rogue.items():
            f = Finding(
                rule_id="NSM-MITM-003",
                title=f"DNS answer from unapproved responder {src} for {qname}",
                severity="critical",
                confidence="high",
                description=(
                    f"{len(evs)} DNS responses for '{qname}' originated from {src}, which is not in the "
                    f"approved resolver list {cfg.known_resolvers}. A reply from an unexpected source is "
                    "the single most reliable indicator of DNS spoofing -- the victim is being pointed "
                    "at an attacker-controlled address."
                    + (f" Answer given: {evs[0].dns_answer}." if evs[0].dns_answer else "")
                ),
                src_ip=src, entity=qname,
                mitre=["T1557", "T1071.004"],
                kill_chain="Exploitation",
                metrics={"responder": src, "query": qname, "responses": len(evs),
                         "answers": sorted({e.dns_answer for e in evs if e.dns_answer})[:5],
                         "ttls": sorted({e.dns_ttl for e in evs if e.dns_ttl is not None})[:5]},
                recommendation=(
                    "Treat the responder as hostile and isolate it. Flush DNS caches on affected hosts, "
                    "and check for a preceding ARP poisoning event that put this host inline."
                ),
            )
            findings.append(self._attach(f, evs))

        # --- 2. Two different answers to the same query, close together (race) ---
        by_query: dict[str, list[Event]] = defaultdict(list)
        for ev in responses:
            by_query[ev.dns_query].append(ev)

        for qname, evs in by_query.items():
            answers = {e.dns_answer for e in evs if e.dns_answer}
            if len(answers) < 2:
                continue
            racing = []
            for i in range(len(evs) - 1):
                gap = (evs[i + 1].timestamp - evs[i].timestamp).total_seconds()
                if gap <= cfg.dns_spoof_race_window_s and evs[i].dns_answer != evs[i + 1].dns_answer:
                    racing.extend([evs[i], evs[i + 1]])
            if not racing:
                continue
            f = Finding(
                rule_id="NSM-MITM-004",
                title=f"Conflicting DNS answers for {qname}",
                severity="high",
                confidence="high",
                description=(
                    f"'{qname}' received {len(answers)} different answers ({', '.join(sorted(a for a in answers if a)[:4])}) "
                    f"within {cfg.dns_spoof_race_window_s}s of each other. A legitimate resolver and a "
                    "forged responder both replying is the classic cache-poisoning race."
                ),
                entity=qname,
                mitre=["T1557"],
                kill_chain="Exploitation",
                metrics={"query": qname, "distinct_answers": sorted(a for a in answers if a)[:10],
                         "responders": sorted({e.src_ip for e in evs if e.src_ip})[:10]},
                recommendation="Determine which answer is authoritative; isolate the rogue responder.",
            )
            findings.append(self._attach(f, racing))

        # --- 3. Abnormally short TTLs (attacker keeps control short-lived) ---
        short_ttl: dict[str, list[Event]] = defaultdict(list)
        for ev in responses:
            if ev.dns_ttl is not None and 0 <= ev.dns_ttl <= cfg.dns_spoof_ttl_max:
                short_ttl[ev.dns_query].append(ev)
        for qname, evs in short_ttl.items():
            if len(evs) < 3:
                continue
            ttls = [e.dns_ttl for e in evs]
            f = Finding(
                rule_id="NSM-MITM-005",
                title=f"Suspiciously short DNS TTL for {qname} (min {min(ttls)}s)",
                severity="medium",
                confidence="low",
                description=(
                    f"{len(evs)} answers for '{qname}' carried TTLs of {min(ttls)}-{max(ttls)}s. "
                    "Attackers use very low TTLs so the poisoned entry expires quickly and they can "
                    "reassert control; fast-flux C2 infrastructure looks the same."
                ),
                entity=qname,
                mitre=["T1557", "T1568.001"],
                kill_chain="Command & Control",
                metrics={"query": qname, "min_ttl": min(ttls), "max_ttl": max(ttls),
                         "responses": len(evs),
                         "responders": sorted({e.src_ip for e in evs if e.src_ip})[:5]},
                recommendation="Compare against the domain's authoritative TTL; treat as a supporting indicator.",
            )
            findings.append(self._attach(f, evs))

        return findings


# ==========================================================================
# SSL stripping
# ==========================================================================

@register
class SSLStripDetector(Detector):
    name = "ssl_strip"
    rule_prefix = "NSM-MITM"
    description = "A host that normally speaks TLS suddenly served over cleartext HTTP."

    # Field names that indicate credentials in a POST body.
    CRED_TOKENS = ("password", "passwd", "pwd", "pass=", "user=", "username",
                   "login", "token", "session", "auth")

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg

        # Which hosts have been seen doing TLS at all?
        tls_hosts: set[str] = set()
        for ev in events:
            if ev.kind == EventKind.TLS and ev.http_host:
                tls_hosts.add(ev.http_host.lower())
            elif ev.dst_port == 443 and ev.http_host:
                tls_hosts.add(ev.http_host.lower())

        http_events = [e for e in events
                       if e.kind == EventKind.HTTP and (e.dst_port in (80, 8080, None))]

        findings: list[Finding] = []

        # --- 1. Downgrade: a TLS-capable host served over plain HTTP ---
        downgraded: dict[str, list[Event]] = defaultdict(list)
        for ev in http_events:
            host = (ev.http_host or "").lower()
            if host and host in tls_hosts:
                downgraded[host].append(ev)

        for host, evs in downgraded.items():
            evs.sort(key=lambda e: e.timestamp)
            f = Finding(
                rule_id="NSM-MITM-006",
                title=f"TLS downgrade on {host} ({len(evs)} cleartext requests)",
                severity="critical",
                confidence="high",
                description=(
                    f"'{host}' was observed completing TLS handshakes (so it normally serves HTTPS), "
                    f"yet {len(evs)} requests to it travelled over cleartext HTTP. That asymmetry is the "
                    "definition of SSL stripping: the attacker keeps HTTPS to the real server and relays "
                    "plain HTTP to the victim."
                ),
                entity=host,
                dst_ip=evs[0].dst_ip,
                mitre=["T1557", "T1040"],
                kill_chain="Exploitation",
                metrics={"host": host, "cleartext_requests": len(evs),
                         "clients": sorted({e.src_ip for e in evs if e.src_ip})[:10],
                         "relay_ips": sorted({e.dst_ip for e in evs if e.dst_ip})[:10]},
                recommendation=(
                    "Enforce HSTS with preloading on the site. On the network, find the relay host "
                    "(the IP serving the HTTP) and correlate with ARP/DNS spoofing findings. Rotate any "
                    "credential submitted during the window."
                ),
            )
            findings.append(self._attach(f, evs))

        # --- 2. Credentials in cleartext ---
        # Only count requests that actually carried credentials: a POST the WAF
        # blocked, or one flagged as an attack, is an inbound attack against us,
        # not one of our users leaking a password.
        cred_events = []
        for ev in http_events:
            if (ev.http_method or "").upper() != "POST":
                continue
            if ev.action in (Action.BLOCK, Action.DROP, Action.RESET):
                continue
            if ev.signature or ev.classification:
                continue
            if ev.src_ip and not in_networks(ev.src_ip, cfg.home_nets):
                continue          # the submitter must be one of our hosts
            blob = " ".join(filter(None, [ev.http_uri or "",
                                          str(ev.extra.get("body", "")),
                                          str(ev.extra.get("post_data", "")),
                                          str(ev.extra.get("request", ""))])).lower()
            if any(t in blob for t in self.CRED_TOKENS):
                cred_events.append(ev)

        if cred_events:
            cred_events.sort(key=lambda e: e.timestamp)
            f = Finding(
                rule_id="NSM-MITM-007",
                title=f"Credentials submitted in cleartext HTTP ({len(cred_events)} requests)",
                severity="critical",
                confidence="high",
                description=(
                    f"{len(cred_events)} HTTP POST requests carried credential-shaped fields over an "
                    "unencrypted channel. Anyone positioned on the path -- including the MITM that "
                    "stripped the TLS -- has these credentials in plaintext."
                ),
                mitre=["T1040", "T1552.001"],
                kill_chain="Credential Access",
                metrics={"requests": len(cred_events),
                         "clients": sorted({e.src_ip for e in cred_events if e.src_ip})[:10],
                         "destinations": sorted({e.http_host or e.dst_ip
                                                 for e in cred_events if (e.http_host or e.dst_ip)})[:10]},
                recommendation="Force a password reset for every account involved; assume the credentials are burned.",
            )
            findings.append(self._attach(f, cred_events))

        return findings
