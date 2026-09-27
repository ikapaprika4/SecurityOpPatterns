"""
HTTP anomaly detection (Wireshark: Traffic Analysis, task 6) -- known audit-
tool user agents, a host cycling through wildly different user agents in a
short window, and the Log4Shell (CVE-2021-44228) JNDI pattern.

Findings are aggregated per source -> destination (and tool): a sqlmap run is
thousands of requests, and one finding per packet buried everything else in
the report. The frames list keeps the first 25 packets as evidence.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ..models import Finding, PacketRecord
from .base import AnalysisContext, Detector, register

_JNDI_RE = re.compile(r"\$\{jndi:(ldap|rmi|dns|ldaps|iiop|nis|nds|corba|https?)://", re.IGNORECASE)

# Log4j resolves nested lookups before the jndi: prefix is ever seen, so real
# payloads hide it: ${${lower:j}ndi:...}, ${${::-j}${::-n}di:...},
# ${${env:NaN:-j}ndi...}, ${j${upper:n}di:...}. Collapse every nested lookup
# to the character it yields (the default after ":-", or the argument of
# lower/upper), repeatedly, then match the plain form.
_NESTED = re.compile(r"\$\{(?:[^${}]*?:-([^${}]*)|(?:lower|upper):([^${}]*))\}", re.IGNORECASE)


def deobfuscate_jndi(value: str) -> str:
    text = value
    for _ in range(10):
        new = _NESTED.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(2), text)
        if new == text:
            break
        text = new
    return text


def _has_jndi(value: str) -> bool:
    return bool(_JNDI_RE.search(value) or _JNDI_RE.search(deobfuscate_jndi(value))
                or "Exploit.class" in value)


@register
class ScannerUserAgentDetector(Detector):
    id = "HTTP-UA-01"
    title = "Known scanner / audit-tool user agent"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        groups: dict[tuple, list[PacketRecord]] = defaultdict(list)
        uas: dict[tuple, set] = defaultdict(set)
        for p in packets:
            ua = p.fields.get("http.user_agent")
            if not ua:
                continue
            hit = next((tool for tool in self.cfg.scanner_user_agents if tool in ua.lower()), None)
            if hit:
                key = (p.src_ip, p.dst_ip, hit)
                groups[key].append(p)
                uas[key].add(ua)

        findings = []
        for (src, dst, tool), pkts in groups.items():
            ua_list = sorted(uas[(src, dst, tool)])
            paths = sorted({p.fields.get("http.request.uri", "") for p in pkts} - {""})
            findings.append(self._finding(
                severity="medium", confidence="high",
                description=(f"{src} sent {len(pkts)} HTTP request(s) to {dst} with a User-Agent "
                             f"identifying {tool} ({ua_list[0]!r}) -- either an authorised scan "
                             f"or unauthenticated reconnaissance/exploitation tooling."),
                frames=[p.frame_number for p in pkts[:25]],
                evidence={"src": src, "dst": dst, "user_agent": ua_list[0], "tool": tool,
                          "requests": len(pkts), "sample_paths": paths[:10]},
                recommendation="Confirm this matches a scheduled vulnerability scan window and "
                                "source. Never allowlist a user agent on its own -- it's "
                                "trivially forged.",
                mitre="T1595.002 Active Scanning: Vulnerability Scanning",
            ))
        return findings


@register
class UserAgentInconsistencyDetector(Detector):
    id = "HTTP-UA-02"
    title = "Same host, wildly different user agents in a short window"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        by_src: dict[str, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            if p.fields.get("http.user_agent"):
                by_src[p.src_ip].append(p)

        findings = []
        for src, pkts in by_src.items():
            uas = {p.fields["http.user_agent"] for p in pkts}
            if len(uas) < 3:
                continue
            findings.append(self._finding(
                severity="low", confidence="low",
                description=(f"{src} sent {len(uas)} different User-Agent strings across "
                             f"{len(pkts)} HTTP requests in this capture. Could be several real "
                             f"applications sharing one NAT'd IP -- or a tool rotating its "
                             f"fingerprint. Never treat the user agent as authoritative on its "
                             f"own."),
                frames=[p.frame_number for p in pkts[:10]],
                evidence={"src": src, "user_agents": sorted(uas)[:15]},
                recommendation="Use this as a secondary signal only -- correlate with request "
                                "timing, targeted paths, and response codes before acting on it.",
            ))
        return findings


@register
class Log4jJndiDetector(Detector):
    id = "HTTP-LOG4J-01"
    title = "Log4Shell JNDI exploitation pattern"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        groups: dict[tuple, list[tuple]] = defaultdict(list)
        for p in packets:
            f = p.fields
            haystacks = {
                "user_agent": f.get("http.user_agent"),
                "uri": f.get("http.request.uri"),
                "host": f.get("http.host"),
                "referer": f.get("http.referer"),
                "x_forwarded_for": f.get("http.x_forwarded_for"),
                "cookie": f.get("http.cookie"),
                "body": f.get("http.file_data"),
            }
            for name, value in haystacks.items():
                if value and _has_jndi(value):
                    groups[(p.src_ip, p.dst_ip)].append((p, name, value))
                    break

        findings = []
        for (src, dst), hits in groups.items():
            p, field_name, value = hits[0]
            decoded = deobfuscate_jndi(value)
            obfuscated = decoded != value
            findings.append(self._finding(
                severity="critical", confidence="high",
                description=(f"{src} sent {len(hits)} request(s) to {dst} carrying a JNDI lookup "
                             f"(first in the {field_name} field"
                             + (", obfuscated with nested lookups" if obfuscated else "")
                             + ") -- the Log4Shell (CVE-2021-44228) exploitation pattern. Once "
                             "Log4j resolves the lookup, it fetches and executes the referenced "
                             "class."),
                frames=[h[0].frame_number for h in hits[:25]],
                evidence={"src": src, "dst": dst, "field": field_name,
                          "payload": value[:300],
                          **({"deobfuscated": decoded[:300]} if obfuscated else {}),
                          "requests": len(hits)},
                recommendation="Treat as a confirmed exploitation attempt against any "
                                "log4j-core-bearing service that received this request. Check "
                                "whether an outbound LDAP/RMI/DNS callback to an attacker "
                                "infrastructure IP followed.",
                mitre="T1190 Exploit Public-Facing Application",
            ))
        return findings
