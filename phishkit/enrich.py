"""
Optional reputation enrichment.

Offline by default. Nothing here runs unless the caller asks for it and an API
key is present, because two things matter operationally:

  1. **Submitting an indicator is a disclosure.** Uploading an attachment to a
     public sandbox can expose customer data, and querying an attacker's unique
     URL can tell them their campaign was detected. Hash lookups are safe;
     file uploads and URL submissions are a judgement call.
  2. An analyst must be able to run the whole toolkit with no network at all.

Keys are read from the environment:
    VT_API_KEY          VirusTotal
    URLSCAN_API_KEY     urlscan.io
    IPINFO_TOKEN        ipinfo.io
    ABUSEIPDB_API_KEY   AbuseIPDB
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

USER_AGENT = "phishkit/1.0 (email analysis)"
TIMEOUT = 20


def _get_json(url: str, headers: Optional[dict] = None,
              data: Optional[bytes] = None) -> Optional[dict]:
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return {"_error": f"HTTP {exc.code}", "_detail": body}
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------

def vt_file_report(sha256: str, api_key: Optional[str] = None) -> Optional[dict]:
    """
    Look a hash up on VirusTotal. Hash lookup only — this never uploads a file,
    so it discloses nothing about the sample's content.
    """
    key = api_key or os.environ.get("VT_API_KEY")
    if not key:
        return {"_skipped": "VT_API_KEY not set"}
    res = _get_json(f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": key})
    if not res or "_error" in res:
        return res
    stats = (res.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}))
    attrs = res.get("data", {}).get("attributes", {})
    return {
        "sha256": sha256,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "type_description": attrs.get("type_description"),
        "names": (attrs.get("names") or [])[:5],
        "first_seen": attrs.get("first_submission_date"),
        "reputation": attrs.get("reputation"),
    }


def vt_url_report(url: str, api_key: Optional[str] = None) -> Optional[dict]:
    """Look a URL up by its VT identifier (base64url of the URL) — no submission."""
    import base64
    key = api_key or os.environ.get("VT_API_KEY")
    if not key:
        return {"_skipped": "VT_API_KEY not set"}
    ident = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    res = _get_json(f"https://www.virustotal.com/api/v3/urls/{ident}",
                    headers={"x-apikey": key})
    if not res or "_error" in res:
        return res
    attrs = res.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "url": url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "categories": list((attrs.get("categories") or {}).values())[:5],
        "final_url": attrs.get("last_final_url"),
        "title": attrs.get("title"),
    }


def vt_domain_report(domain: str, api_key: Optional[str] = None) -> Optional[dict]:
    key = api_key or os.environ.get("VT_API_KEY")
    if not key:
        return {"_skipped": "VT_API_KEY not set"}
    res = _get_json(f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": key})
    if not res or "_error" in res:
        return res
    attrs = res.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "domain": domain,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "reputation": attrs.get("reputation"),
        "creation_date": attrs.get("creation_date"),
        "registrar": attrs.get("registrar"),
        "categories": list((attrs.get("categories") or {}).values())[:5],
    }


# --------------------------------------------------------------------------
# IP geolocation and reputation
# --------------------------------------------------------------------------

def ipinfo(ip: str, token: Optional[str] = None) -> Optional[dict]:
    """Geolocation and owning organisation for the originating IP."""
    tok = token or os.environ.get("IPINFO_TOKEN")
    url = f"https://ipinfo.io/{ip}/json" + (f"?token={tok}" if tok else "")
    res = _get_json(url)
    if not res or "_error" in res:
        return res
    return {k: res.get(k) for k in
            ("ip", "hostname", "city", "region", "country", "org", "asn", "timezone")
            if res.get(k)}


def abuseipdb(ip: str, api_key: Optional[str] = None) -> Optional[dict]:
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"_skipped": "ABUSEIPDB_API_KEY not set"}
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    res = _get_json(f"https://api.abuseipdb.com/api/v2/check?{q}",
                    headers={"Key": key, "Accept": "application/json"})
    if not res or "_error" in res:
        return res
    d = res.get("data", {})
    return {"ip": ip, "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"), "country": d.get("countryCode"),
            "isp": d.get("isp"), "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor")}


# --------------------------------------------------------------------------
# urlscan.io
# --------------------------------------------------------------------------

def urlscan_search(query: str, api_key: Optional[str] = None) -> Optional[dict]:
    """
    Search existing urlscan results. Passive — it submits nothing, so the
    attacker learns nothing. Prefer this over `urlscan_submit`.
    """
    headers = {}
    key = api_key or os.environ.get("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    q = urllib.parse.urlencode({"q": query, "size": 5})
    res = _get_json(f"https://urlscan.io/api/v1/search/?{q}", headers=headers)
    if not res or "_error" in res:
        return res
    return {"total": res.get("total", 0),
            "results": [{"url": r.get("page", {}).get("url"),
                         "domain": r.get("page", {}).get("domain"),
                         "ip": r.get("page", {}).get("ip"),
                         "country": r.get("page", {}).get("country"),
                         "time": r.get("task", {}).get("time"),
                         "screenshot": r.get("screenshot"),
                         "result": r.get("result")}
                        for r in (res.get("results") or [])[:5]]}


def urlscan_submit(url: str, api_key: Optional[str] = None,
                   visibility: str = "unlisted", wait: bool = False) -> Optional[dict]:
    """
    Actively scan a URL.

    This fetches the page from urlscan's infrastructure. For a campaign-unique
    URL the operator may see the hit and learn they were detected, so submit
    deliberately, and never with `visibility="public"` for anything that embeds
    a victim identifier.
    """
    key = api_key or os.environ.get("URLSCAN_API_KEY")
    if not key:
        return {"_skipped": "URLSCAN_API_KEY not set"}
    payload = json.dumps({"url": url, "visibility": visibility}).encode()
    res = _get_json("https://urlscan.io/api/v1/scan/",
                    headers={"API-Key": key, "Content-Type": "application/json"},
                    data=payload)
    if not res or "_error" in res or not wait:
        return res
    api = res.get("api")
    for _ in range(15):
        time.sleep(4)
        got = _get_json(api)
        if got and "_error" not in got and got.get("page"):
            return {"result": res.get("result"), "page": got.get("page"),
                    "verdicts": got.get("verdicts", {}).get("overall", {})}
    return res


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def enrich_result(result, *, do_files: bool = True, do_urls: bool = True,
                  do_ips: bool = True, submit_urls: bool = False) -> dict[str, Any]:
    """
    Run whichever lookups have credentials available. Returns a dict keyed by
    indicator; every entry is either data, `_error`, or `_skipped`, so a missing
    key never looks like a clean verdict.
    """
    out: dict[str, Any] = {"files": {}, "urls": {}, "domains": {}, "ips": {}}
    e = result.email

    if do_files:
        for a in e.attachments:
            if a.sha256:
                out["files"][a.sha256] = vt_file_report(a.sha256)

    if do_urls:
        seen_domains = set()
        for u in e.urls[:15]:
            out["urls"][u.url] = vt_url_report(u.url)
            if submit_urls:
                out["urls"][u.url] = {**(out["urls"][u.url] or {}),
                                      "urlscan": urlscan_submit(u.url)}
            elif u.domain:
                out["urls"][u.url] = {**(out["urls"][u.url] or {}),
                                      "urlscan_passive": urlscan_search(f"domain:{u.domain}")}
            if u.domain and u.domain not in seen_domains:
                seen_domains.add(u.domain)
                out["domains"][u.domain] = vt_domain_report(u.domain)

    if do_ips:
        for ip in {e.originating_ip, e.x_originating_ip}:
            if ip:
                out["ips"][ip] = {"ipinfo": ipinfo(ip), "abuseipdb": abuseipdb(ip)}

    return out
