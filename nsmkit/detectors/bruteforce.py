"""
Credential-access detectors over authentication events (VPN, SSH, AD, portal).

Three distinct shapes, deliberately separated because the response differs:
  many failures, one user, one source     -> brute force
  few failures, many users, one source    -> password spray (evades lockout)
  failures then a SUCCESS                 -> likely successful compromise
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from ..enrich import in_networks
from ..models import Action, Event, EventKind, Finding
from .base import Detector, register
from ._window import best_distinct, best_count  # noqa: E402


def _auth(events: Sequence[Event]) -> list[Event]:
    return sorted((e for e in events if e.kind == EventKind.AUTH and e.timestamp),
                  key=lambda e: e.timestamp)


@register
class BruteForceDetector(Detector):
    name = "brute_force"
    rule_prefix = "NSM-CRED"
    description = "High volume of authentication failures from a single source."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in _auth(events):
            if ev.action is Action.FAILURE and ev.src_ip:
                by_src[ev.src_ip].append(ev)

        findings: list[Finding] = []
        for src, evs in by_src.items():
            best = best_count(evs, cfg.bruteforce_window_s)
            if len(best) < cfg.bruteforce_min_failures:
                continue

            users = sorted({e.user for e in best if e.user})
            span = (best[-1].timestamp - best[0].timestamp).total_seconds() or 1.0
            rate = len(best) / span

            # A single target user with a fast, regular cadence is scripted.
            f = Finding(
                rule_id="NSM-CRED-001",
                title=f"Authentication brute force from {src} ({len(best)} failures)",
                severity="high",
                confidence="high" if len(users) <= 2 else "medium",
                description=(
                    f"{src} produced {len(best)} failed authentications in {span:.0f}s "
                    f"({rate * 60:.1f}/min) against {len(users)} account(s): {', '.join(users[:6])}. "
                    "Repetition from one source to one destination is the brute-force signature."
                ),
                src_ip=src,
                user=users[0] if len(users) == 1 else None,
                mitre=["T1110.001"],
                kill_chain="Credential Access",
                metrics={"failures": len(best), "window_seconds": round(span),
                         "attempts_per_min": round(rate * 60, 2),
                         "targeted_users": users[:20], "distinct_users": len(users),
                         "external_source": not in_networks(src, cfg.home_nets)},
                recommendation=(
                    "Block the source IP, force a password reset on the targeted accounts, and check "
                    "for any SUCCESS from this IP in the same window (see NSM-CRED-003)."
                ),
            )
            findings.append(self._attach(f, best))
        return findings


@register
class PasswordSprayDetector(Detector):
    name = "password_spray"
    rule_prefix = "NSM-CRED"
    description = "Few attempts against many accounts -- lockout-evading spray."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in _auth(events):
            if ev.action is Action.FAILURE and ev.src_ip and ev.user:
                by_src[ev.src_ip].append(ev)

        findings: list[Finding] = []
        for src, evs in by_src.items():
            best = best_distinct(evs, lambda e: e.user, cfg.spray_window_s)
            if not best:
                continue

            per_user: dict[str, int] = defaultdict(int)
            for e in best:
                per_user[e.user] += 1
            users = list(per_user)
            if len(users) < cfg.spray_min_users:
                continue
            # The defining trait: broad user coverage with shallow depth per user.
            if max(per_user.values()) > cfg.spray_max_attempts_per_user:
                continue

            f = Finding(
                rule_id="NSM-CRED-002",
                title=f"Password spray from {src} ({len(users)} accounts)",
                severity="high",
                confidence="high",
                description=(
                    f"{src} attempted {len(best)} authentications spread across {len(users)} distinct "
                    f"accounts, at most {max(per_user.values())} per account -- shallow-and-wide, which "
                    "is how attackers stay under account-lockout thresholds. Volume alone would not "
                    "trigger a brute-force rule."
                ),
                src_ip=src,
                mitre=["T1110.003"],
                kill_chain="Credential Access",
                metrics={"distinct_users": len(users), "users": users[:30],
                         "total_attempts": len(best),
                         "max_per_user": max(per_user.values())},
                recommendation="Block the source, review whether any sprayed account succeeded, and "
                               "confirm MFA coverage on the targeted service.",
            )
            findings.append(self._attach(f, best))
        return findings


@register
class SuccessAfterFailuresDetector(Detector):
    name = "success_after_failures"
    rule_prefix = "NSM-CRED"
    description = "A successful login immediately following a burst of failures."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        by_src: dict[str, list[Event]] = defaultdict(list)
        for ev in _auth(events):
            if ev.src_ip:
                by_src[ev.src_ip].append(ev)

        findings: list[Finding] = []
        for src, evs in by_src.items():
            for i, ev in enumerate(evs):
                if ev.action is not Action.SUCCESS:
                    continue
                # Count failures immediately preceding this success, same source,
                # same user where the user is known.
                preceding = []
                for prev in reversed(evs[:i]):
                    if (ev.timestamp - prev.timestamp).total_seconds() > cfg.success_after_window_s:
                        break
                    if prev.action is Action.FAILURE and (prev.user == ev.user or ev.user is None):
                        preceding.append(prev)
                if len(preceding) < cfg.success_after_failures:
                    continue

                chain = list(reversed(preceding)) + [ev]
                f = Finding(
                    rule_id="NSM-CRED-003",
                    title=f"Likely credential compromise: {ev.user or '?'} @ {src}",
                    severity="critical",
                    confidence="high",
                    description=(
                        f"{len(preceding)} failed authentications for '{ev.user}' from {src} were "
                        f"followed by a SUCCESS at {ev.timestamp}. "
                        + (f"The session was assigned {ev.assigned_ip}, which becomes the pivot IP for "
                           "lateral-movement hunting." if ev.assigned_ip else "")
                    ),
                    src_ip=src, user=ev.user,
                    mitre=["T1110", "T1078"],
                    kill_chain="Initial Access",
                    metrics={"preceding_failures": len(preceding),
                             "success_time": ev.timestamp.isoformat(),
                             "assigned_ip": ev.assigned_ip,
                             "service_account": bool(ev.user and (
                                 ev.user.lower().startswith("svc") or ev.user in cfg.service_accounts))},
                    recommendation=(
                        "Treat as confirmed compromise. Disable the account, revoke sessions, and pivot on "
                        + (f"{ev.assigned_ip} " if ev.assigned_ip else "the assigned VPN address ")
                        + "in firewall and IDS logs to scope lateral movement."
                    ),
                )
                findings.append(self._attach(f, chain))
        return findings


@register
class AnomalousVPNSessionDetector(Detector):
    name = "anomalous_vpn"
    rule_prefix = "NSM-CRED"
    description = "Successful VPN logins from unusual sources or at unusual hours."

    def run(self, events: Sequence[Event]) -> list[Finding]:
        cfg = self.cfg
        start, end = cfg.business_hours
        by_user: dict[str, list[Event]] = defaultdict(list)
        for ev in _auth(events):
            if ev.action is Action.SUCCESS and ev.user:
                by_user[ev.user].append(ev)

        findings: list[Finding] = []
        for user, evs in by_user.items():
            sources = {e.src_ip for e in evs if e.src_ip}
            odd_hours = [e for e in evs if not (start <= e.timestamp.hour < end)]
            if len(sources) < 3 and len(odd_hours) < 3:
                continue
            severity = "medium"
            if user.lower().startswith("svc") or user in cfg.service_accounts:
                severity = "high"  # service accounts should have a narrow, fixed source set

            f = Finding(
                rule_id="NSM-CRED-004",
                title=f"Anomalous session pattern for account '{user}'",
                severity=severity,
                confidence="low",
                description=(
                    f"Account '{user}' authenticated successfully from {len(sources)} distinct source "
                    f"addresses, {len(odd_hours)} of {len(evs)} sessions outside {start:02d}:00-{end:02d}:00. "
                    "Broad source diversity on one account is a shared-credential or stolen-credential signal."
                ),
                user=user,
                mitre=["T1078"],
                kill_chain="Persistence",
                metrics={"distinct_sources": len(sources), "sources": sorted(sources)[:20],
                         "sessions": len(evs), "off_hours_sessions": len(odd_hours)},
                recommendation="Correlate against the user's expected work location and hours; "
                               "for service accounts, pin the allowed source list.",
            )
            findings.append(self._attach(f, evs))
        return findings
