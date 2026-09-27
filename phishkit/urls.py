"""
URL extraction and analysis.

Extraction must cover three places, because a URL present in only one of them
is usually the interesting one:
  1. the rendered text          — what the user reads
  2. HTML `href` / `src`        — where the click actually goes
  3. the raw source             — obfuscated, commented-out, or hidden elements

A mismatch between (1) and (2) is link manipulation: the anchor says
"tracking number 1Z999AA10123456784", the href says something else entirely.
"""

from __future__ import annotations

import html as html_mod
import ipaddress
import re
import urllib.parse
from typing import Iterable, Optional

from .brands import lookalike_brand, registrable
from .models import ExtractedURL

# --------------------------------------------------------------------------
# URL shorteners and redirectors
# --------------------------------------------------------------------------

SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "bl.ink", "snip.ly",
    "lnkd.in", "db.tt", "qr.ae", "adf.ly", "bitly.com", "j.mp", "tr.im",
    "tiny.cc", "s.id", "shorte.st", "clck.ru", "u.to", "v.gd", "x.co",
    "soo.gd", "1url.com", "prettylinkpro.com", "vzturl.com", "linktr.ee",
    "short.io", "kutt.it", "t.ly", "surl.li", "shrtco.de", "gg.gg", "ity.im",
    "trib.al", "mcaf.ee", "po.st", "urlz.fr", "chilp.it", "hyperurl.co",
}

# Services that legitimately host content but are abused to stage phishing
# pages, so the domain's own reputation is no reassurance.
ABUSED_HOSTING: set[str] = {
    "firebasestorage.googleapis.com", "storage.googleapis.com", "web.app",
    "firebaseapp.com", "blob.core.windows.net", "azurewebsites.net",
    "s3.amazonaws.com", "amazonaws.com", "sharepoint.com", "onedrive.live.com",
    "docs.google.com", "drive.google.com", "forms.gle", "sites.google.com",
    "glitch.me", "repl.co", "replit.dev", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "github.io", "gitbook.io", "weebly.com",
    "wixsite.com", "godaddysites.com", "000webhostapp.com", "herokuapp.com",
    "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "r2.dev", "bubbleapps.io", "typeform.com", "jotform.com", "canva.site",
}

# Link-rewriting / click-tracking wrappers. The real destination is a parameter,
# so unwrap before judging: a wrapped malicious URL still reaches the user.
REWRAPPERS: dict[str, tuple[str, ...]] = {
    "safelinks.protection.outlook.com": ("url",),
    "urldefense.proofpoint.com": ("u",),
    "urldefense.com": ("u",),
    "protect-us.mimecast.com": ("u",),
    "protect.mimecast.com": ("u",),
    "clicktime.symantec.com": ("u",),
    "linkprotect.cudasvc.com": ("a",),
    "secure-web.cisco.com": ("u",),
    "google.com": ("q", "url"),            # /url?q= open redirect
    "l.facebook.com": ("u",),
    "out.reddit.com": ("url",),
}

# Words in a URL path that signal a credential-harvesting page.
CREDENTIAL_PATH_TERMS = (
    "login", "signin", "sign-in", "logon", "auth", "authenticate", "verify",
    "verification", "validate", "account", "secure", "security", "update",
    "confirm", "password", "credential", "recover", "unlock", "reactivate",
    "billing", "payment", "invoice", "webmail", "owa", "session",
)

_URL_RE = re.compile(
    r"""\b(?:(?:https?|ftp|file)://|www\d?\.)[^\s<>"'`\]\)\}]{2,2000}""", re.I)
_HREF_RE = re.compile(
    r"""<\s*a\b[^>]*?href\s*=\s*(?P<q>["']?)(?P<url>[^"'\s>]+)(?P=q)[^>]*>(?P<text>.*?)</\s*a\s*>""",
    re.I | re.S)
_SRC_RE = re.compile(
    r"""<\s*(?P<tag>img|iframe|script|link|form|embed|source)\b[^>]*?"""
    r"""(?:src|action|href)\s*=\s*(?P<q>["']?)(?P<url>[^"'\s>]+)(?P=q)""", re.I)
_IMG_TAG_RE = re.compile(r"<\s*img\b[^>]*>", re.I)
_TAG_STRIP = re.compile(r"<[^>]+>")


def _clean(url: str) -> str:
    u = html_mod.unescape(url.strip())
    u = u.strip("<>\"'` \t\r\n")
    u = u.rstrip(".,;:!?)»”’")
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def _domain_of(url: str) -> str:
    try:
        netloc = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ""
    if "@" in netloc:                    # https://paypal.com@evil.ru/ — userinfo trick
        netloc = netloc.rsplit("@", 1)[1]
    return netloc.split(":")[0].lower().strip("[]")


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def unwrap(url: str, depth: int = 0) -> tuple[str, list[str]]:
    """
    Recursively unwrap known click-tracking / link-rewriting wrappers.

    Returns `(final_url, chain)`. The chain is evidence: it shows the analyst
    that the message went through a rewriter and what it was hiding.
    """
    chain: list[str] = []
    current = url
    while depth < 6:
        host = _domain_of(current)
        params = None
        for wrapper, keys in REWRAPPERS.items():
            if host == wrapper or host.endswith("." + wrapper):
                params = keys
                break
        if not params:
            break
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(current).query)
        except ValueError:
            break
        nxt = None
        for key in params:
            if key in qs and qs[key]:
                cand = urllib.parse.unquote(qs[key][0])
                if cand.lower().startswith(("http://", "https://")):
                    nxt = cand
                    break
        if not nxt or nxt == current:
            break
        chain.append(current)
        current = nxt
        depth += 1
    return current, chain


# --------------------------------------------------------------------------
# Tracking pixels
# --------------------------------------------------------------------------

_DIM_RE = re.compile(r"""\b(width|height)\s*[:=]\s*["']?\s*(\d+)""", re.I)
_HIDDEN_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0", re.I)
_PIXEL_NAME_RE = re.compile(
    r"(pixel|beacon|track|tracking|open\.gif|spacer|clear\.gif|1x1|blank\.gif|"
    r"invisible|\bimg\.php|\bo\.gif|\bwt\.gif)", re.I)


def is_tracking_pixel(img_tag: str, url: str) -> tuple[bool, str]:
    """
    A tracking pixel is a tiny or hidden remote image whose only purpose is to
    fire a request when the mail is opened, telling the sender the address is
    live and when it was read. This is why mail clients block remote images by
    default — the Yahoo behaviour in the shipping-notification sample.
    """
    dims = {k.lower(): int(v) for k, v in _DIM_RE.findall(img_tag)}
    if dims.get("width", 99) <= 3 and dims.get("height", 99) <= 3:
        return True, f"{dims.get('width')}x{dims.get('height')} remote image"
    if _HIDDEN_RE.search(img_tag):
        return True, "remote image hidden with CSS"
    if _PIXEL_NAME_RE.search(url):
        return True, "filename/path matches a known tracking-pixel pattern"
    if dims.get("width") == 1 or dims.get("height") == 1:
        return True, "1-pixel dimension"
    return False, ""


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def extract_urls(body_text: str = "", body_html: str = "",
                 extra: Optional[Iterable[str]] = None) -> list[ExtractedURL]:
    """Extract and analyse every URL in the message. De-duplicated by URL."""
    found: dict[str, ExtractedURL] = {}

    def add(url: str, source: str, display_text: str = "") -> Optional[ExtractedURL]:
        u = _clean(url)
        if not u or u.lower().startswith(("mailto:", "tel:", "javascript:", "data:", "cid:", "#")):
            return None
        if not re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
            return None
        if u in found:
            if display_text and not found[u].display_text:
                found[u].display_text = display_text
            return found[u]
        final, chain = unwrap(u)
        eu = ExtractedURL(url=u, source=source, display_text=display_text,
                          redirect_chain=chain)
        try:
            parts = urllib.parse.urlsplit(final)
            eu.scheme = parts.scheme.lower()
            eu.path = parts.path or ""
        except ValueError:
            pass
        eu.domain = _domain_of(final)
        if chain:
            eu.notes.append(f"Wrapped by a link-rewriting service; unwrapped to {final}")
        found[u] = eu
        return eu

    # 1. HTML anchors — href plus the visible anchor text
    for m in _HREF_RE.finditer(body_html or ""):
        text = _TAG_STRIP.sub("", m.group("text") or "").strip()
        text = html_mod.unescape(re.sub(r"\s+", " ", text))[:300]
        add(m.group("url"), "html_href", text)

    # 2. Remote resources — img/iframe/script/form; classify tracking pixels
    for m in _SRC_RE.finditer(body_html or ""):
        eu = add(m.group("url"), f"html_{m.group('tag').lower()}")
        if eu and m.group("tag").lower() == "img":
            start = max(0, m.start() - 400)
            tag_match = None
            for t in _IMG_TAG_RE.finditer(body_html, start, m.end() + 400):
                if t.start() <= m.start() <= t.end():
                    tag_match = t.group(0)
                    break
            pixel, why = is_tracking_pixel(tag_match or m.group(0), eu.url)
            if pixel:
                eu.is_tracking_pixel = True
                eu.notes.append(f"Tracking pixel: {why}")

    # 3. Bare URLs in the plain-text body and in the raw HTML source
    for m in _URL_RE.finditer(body_text or ""):
        add(m.group(0), "text")
    for m in _URL_RE.finditer(body_html or ""):
        add(m.group(0), "html_raw")

    # 4. Anything the caller found elsewhere (headers, attachments)
    for u in (extra or []):
        add(u, "attachment")

    for eu in found.values():
        analyse_url(eu)
    return list(found.values())


def analyse_url(eu: ExtractedURL) -> ExtractedURL:
    """Attach the per-URL red flags."""
    host = eu.domain
    if not host:
        eu.notes.append("URL has no parseable host")
        return eu

    if is_ip_literal(host):
        eu.is_ip_literal = True
        eu.notes.append("Link points at a bare IP address — legitimate services use domain names")

    reg = registrable(host)
    if reg in SHORTENERS or host in SHORTENERS:
        eu.is_shortener = True
        eu.notes.append("URL shortener — the final destination is hidden. Expand it "
                        "(wheregoes.com, urlscan.io) rather than clicking it")

    for hosting in ABUSED_HOSTING:
        if host == hosting or host.endswith("." + hosting):
            eu.notes.append(f"Hosted on {hosting} — a legitimate platform frequently abused "
                            "to stage phishing pages, so its reputation proves nothing")
            break

    la = lookalike_brand(host)
    if la:
        brand, legit, technique = la
        eu.lookalike_of = legit
        eu.notes.append(f"Domain imitates {brand} ({legit}) via {technique}")

    path_low = (eu.path or "").lower()
    hits = [t for t in CREDENTIAL_PATH_TERMS if t in path_low]
    if hits:
        eu.notes.append(f"Path suggests a credential/payment page: {', '.join(hits[:5])}")

    if "@" in urllib.parse.urlsplit(eu.url).netloc:
        eu.notes.append("URL contains '@' before the host — everything left of it is ignored "
                        "by the browser, so the visible brand is decoration")

    if host.count(".") >= 4:
        eu.notes.append(f"Unusually deep subdomain chain ({host.count('.') + 1} labels) — "
                        "used to push a trusted-looking name to the left of the real domain")

    if len(eu.url) > 150:
        eu.notes.append(f"Very long URL ({len(eu.url)} chars) — length obscures the destination")

    if re.search(r"%[0-9a-fA-F]{2}", eu.url) and eu.url.count("%") >= 4:
        eu.notes.append("Heavy percent-encoding — a common obfuscation technique")

    if re.search(r"\bxn--", host):
        eu.notes.append("Punycode (xn--) domain — may render as a homoglyph of a real brand")

    return eu


def display_text_mismatch(eu: ExtractedURL) -> Optional[str]:
    """
    Anchor text claims one destination, href goes to another.

    Only fires when the anchor text is itself URL- or domain-shaped; ordinary
    call-to-action text ("Cancel the order") is not a mismatch, it is just a label.
    """
    text = (eu.display_text or "").strip()
    if not text or len(text) > 200:
        return None
    m = re.search(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})", text, re.I)
    if not m:
        return None
    claimed = m.group(1).lower().rstrip(".")
    if claimed in {"e.g", "i.e"} or " " in claimed:
        return None
    actual = eu.domain
    if not actual:
        return None
    if registrable(claimed) == registrable(actual):
        return None
    return f"Link text shows '{claimed}' but the href goes to '{actual}'"
