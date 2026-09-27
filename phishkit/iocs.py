"""
IOC handling: defanging and export.

Defanging is not cosmetic. An analyst pastes indicators into tickets, chats and
reports that render links as clickable; one accidental click on a live phishing
URL from a corporate machine is an incident. Everything that leaves this tool
is defanged by default.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Iterable

_SCHEME_RE = re.compile(r"^(https?|ftp|ftps|file)://", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang(value: str) -> str:
    """
    `http://evil.com/a` -> `hxxp[://]evil[.]com/a`
    `1.2.3.4`           -> `1[.]2[.]3[.]4`
    `bob@evil.com`      -> `bob[@]evil[.]com`
    """
    if not value:
        return value
    out = value
    out = re.sub(r"^https://", "hxxps[://]", out, flags=re.I)
    out = re.sub(r"^http://", "hxxp[://]", out, flags=re.I)
    out = re.sub(r"^ftp://", "fxp[://]", out, flags=re.I)
    out = out.replace("@", "[@]")
    # Only defang dots in the host portion, so paths stay readable.
    if "[://]" in out:
        head, sep, tail = out.partition("[://]")
        host, slash, path = tail.partition("/")
        host = host.replace(".", "[.]")
        out = f"{head}{sep}{host}{slash}{path}"
    else:
        out = out.replace(".", "[.]")
    return out


def refang(value: str) -> str:
    """Reverse defanging — for feeding an indicator back into a tool."""
    if not value:
        return value
    out = value
    out = out.replace("[.]", ".").replace("(.)", ".").replace("[.", ".").replace(".]", ".")
    out = out.replace("[@]", "@").replace("(@)", "@").replace("[at]", "@")
    out = re.sub(r"hxxps?\[://\]", lambda m: "https://" if "s" in m.group(0) else "http://", out, flags=re.I)
    out = re.sub(r"hxxps?://", lambda m: "https://" if "s" in m.group(0) else "http://", out, flags=re.I)
    out = out.replace("[://]", "://")
    return out


def defang_all(values: Iterable[str]) -> list[str]:
    return [defang(v) for v in values]


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

CONTEXT_KINDS = ("context_domains", "context_urls", "context_ips")


def never_block_domain(host: str) -> bool:
    """Domains that must never become a domain-level block, however bad the
    message: a brand's own domains (a phish links to the real help page as a
    decoy), consumer webmail (a BEC from one Gmail account must not blocklist
    gmail.com), URL shorteners, and the shared hosting platforms themselves
    (block `evil-share.pages.dev`, never `pages.dev`)."""
    from .brands import brand_of_domain, registrable
    from .detectors import FREEMAIL
    from .urls import ABUSED_HOSTING, SHORTENERS
    h = (host or "").lower().strip(".")
    if not h:
        return True
    reg = registrable(h)
    return (bool(brand_of_domain(h)) or reg in FREEMAIL or h in SHORTENERS or reg in SHORTENERS
            or h in ABUSED_HOSTING or (h == reg and reg in ABUSED_HOSTING))


def collect_iocs(result) -> dict[str, list[str]]:
    """Gather every indicator worth pivoting on, defanged, de-duplicated, sorted.

    Indicators that are real but must not be blocked -- a brand's genuine
    domains, consumer webmail, shared platforms, the webmail provider's own
    outbound IP -- go under `context_*` keys. They are shown to the analyst
    but left out of every blocklist / MISP / STIX / CSV export."""
    from .brands import brand_of_domain, registrable
    from .detectors import FREEMAIL
    from .models import AuthResult
    from .urls import ABUSED_HOSTING
    e = result.email
    iocs: dict[str, set[str]] = {
        "sender_addresses": set(), "sender_domains": set(), "reply_to": set(),
        "originating_ips": set(), "urls": set(), "url_domains": set(),
        "attachment_names": set(), "attachment_sha256": set(),
        "attachment_md5": set(), "attachment_sha1": set(),
        "message_ids": set(), "subjects": set(),
        "context_domains": set(), "context_urls": set(), "context_ips": set(),
    }

    def domain(kind: str, host: str) -> None:
        if host:
            iocs["context_domains" if never_block_domain(host) else kind].add(defang(host))

    def url(value: str, host: str) -> None:
        on_brand = bool(brand_of_domain(host)) and not any(
            host == p or host.endswith("." + p) for p in ABUSED_HOSTING)
        iocs["context_urls" if on_brand else "urls"].add(defang(value))

    if e.from_addr and e.from_addr.address:
        iocs["sender_addresses"].add(defang(e.from_addr.address))
        domain("sender_domains", e.from_addr.domain)
    if e.reply_to and e.reply_to.address:
        iocs["reply_to"].add(defang(e.reply_to.address))
        domain("sender_domains", e.reply_to.domain)
    if e.return_path and e.return_path.domain:
        domain("sender_domains", e.return_path.domain)

    # Mail that genuinely left a webmail provider (SPF pass for gmail.com,
    # outlook.com, ...) originates from that provider's shared servers.
    sender_reg = registrable(e.from_addr.domain) if e.from_addr and e.from_addr.domain else ""
    provider_origin = e.auth.spf is AuthResult.PASS and (
        sender_reg in FREEMAIL or bool(brand_of_domain(sender_reg)))
    for ip in (e.originating_ip, e.x_originating_ip):
        if ip:
            iocs["context_ips" if provider_origin else "originating_ips"].add(defang(ip))

    from .urls import _domain_of, unwrap
    for u in e.urls:
        # A wrapped link (Safe Links, Proofpoint, ...) is stored as the wrapper;
        # the destination that matters is the unwrapped one. Each is judged
        # by its own host: the wrapper is Microsoft's, the destination is not.
        final = unwrap(u.url)[0]
        url(final, _domain_of(final))
        domain("url_domains", u.domain)
        for step in [u.url, *u.redirect_chain]:
            if step != final:
                url(step, _domain_of(step))

    for a in e.attachments:
        if a.filename:
            iocs["attachment_names"].add(a.filename)
        for key, val in (("attachment_sha256", a.sha256), ("attachment_md5", a.md5),
                         ("attachment_sha1", a.sha1)):
            if val:
                iocs[key].add(val)
        for u in a.embedded_urls:
            url(u, _domain_of(u))

    if e.message_id:
        iocs["message_ids"].add(e.message_id)
    if e.subject:
        iocs["subjects"].add(e.subject)

    return {k: sorted(v) for k, v in iocs.items() if v}


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

_MISP_TYPE = {
    "sender_addresses": "email-src", "reply_to": "email-reply-to",
    "sender_domains": "domain", "url_domains": "domain",
    "originating_ips": "ip-src", "urls": "url",
    "attachment_names": "filename", "attachment_sha256": "sha256",
    "attachment_md5": "md5", "attachment_sha1": "sha1",
    "subjects": "email-subject", "message_ids": "email-message-id",
}


def to_csv(iocs: dict[str, list[str]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "misp_type", "value"])
    for kind, values in iocs.items():
        if kind in CONTEXT_KINDS:
            continue
        for v in values:
            w.writerow([kind, _MISP_TYPE.get(kind, "text"), v])
    return buf.getvalue()


def to_misp(iocs: dict[str, list[str]], info: str = "Phishing email") -> str:
    """A MISP-shaped event object. Values are refanged — MISP stores live IOCs."""
    attrs = []
    for kind, values in iocs.items():
        mtype = _MISP_TYPE.get(kind)
        if not mtype:
            continue
        for v in values:
            attrs.append({
                "type": mtype,
                "category": ("Payload delivery" if "attachment" in kind else "Network activity"),
                "value": refang(v),
                "to_ids": mtype in {"url", "domain", "sha256", "md5", "sha1", "ip-src"},
                "comment": f"phishkit: {kind}",
            })
    return json.dumps({"Event": {"info": info, "analysis": "2", "threat_level_id": "2",
                                 "Attribute": attrs}}, indent=2)


def to_stix_lite(iocs: dict[str, list[str]]) -> str:
    """STIX 2.1 indicator objects with simple patterns. Values refanged."""
    pattern_for = {
        "urls": "[url:value = '{}']",
        "url_domains": "[domain-name:value = '{}']",
        "sender_domains": "[domain-name:value = '{}']",
        "originating_ips": "[ipv4-addr:value = '{}']",
        "attachment_sha256": "[file:hashes.'SHA-256' = '{}']",
        "attachment_md5": "[file:hashes.MD5 = '{}']",
        "sender_addresses": "[email-addr:value = '{}']",
        "reply_to": "[email-addr:value = '{}']",
    }
    objs: list[dict[str, Any]] = []
    n = 0
    for kind, values in iocs.items():
        tmpl = pattern_for.get(kind)
        if not tmpl:
            continue
        for v in values:
            n += 1
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--phishkit-{n:04d}",
                "name": f"{kind}: {v}",
                "pattern": tmpl.format(refang(v)),
                "pattern_type": "stix",
                "labels": ["malicious-activity", "phishing"],
            })
    return json.dumps({"type": "bundle", "id": "bundle--phishkit", "objects": objs}, indent=2)


def to_blocklist(iocs: dict[str, list[str]]) -> str:
    """Plain refanged values, one per line — paste into a gateway or firewall."""
    lines = ["# Domains"]
    lines += sorted({refang(v) for v in iocs.get("url_domains", []) + iocs.get("sender_domains", [])})
    lines += ["", "# URLs"] + sorted({refang(v) for v in iocs.get("urls", [])})
    lines += ["", "# IPs"] + sorted({refang(v) for v in iocs.get("originating_ips", [])})
    lines += ["", "# File hashes (SHA256)"] + sorted(iocs.get("attachment_sha256", []))
    lines += ["", "# Sender / reply-to addresses"] + sorted(
        {refang(v) for v in iocs.get("sender_addresses", []) + iocs.get("reply_to", [])})
    return "\n".join(lines) + "\n"
