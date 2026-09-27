"""
Detection rules.

Every rule returns Findings carrying a `score`. The scores sum to a phishing
score which maps to a verdict — no single indicator decides the case, which is
what keeps legitimate marketing mail (urgent language + tracking pixel + a
shortener) out of the phishing bucket while a spoofed sender with a lookalike
link lands squarely in it.

Rule ID scheme:
    PH-HDR-*   header and identity
    PH-AUTH-*  SPF / DKIM / DMARC
    PH-URL-*   links
    PH-ATT-*   attachments
    PH-SOC-*   social engineering
"""

from __future__ import annotations

from typing import Optional

from .brands import (GENERIC_AUTHORITY, brand_of_domain, brands_mentioned,
                     lookalike_brand, registrable)
from .models import (AuthResult, Finding, ParsedEmail, PhishType, Verdict)
from .social import analyse_language, targets_executive
from .urls import display_text_mismatch

# --------------------------------------------------------------------------
# Free / disposable mail providers — legitimate for people, never for a brand
# --------------------------------------------------------------------------

FREEMAIL = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "mail.com", "gmx.com", "gmx.net", "yandex.com",
    "yandex.ru", "zoho.com", "protonmail.com", "proton.me", "icloud.com",
    "inbox.com", "fastmail.com", "tutanota.com", "163.com", "qq.com", "126.com",
}

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "getnada.com",
    "temp-mail.org", "trashmail.com", "maildrop.cc", "dispostable.com",
}

# TLDs with a persistently high abuse rate. Not proof — a weight.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "club", "click", "link", "work", "gq", "cf",
    "ml", "ga", "tk", "buzz", "rest", "monster", "cyou", "quest", "surf",
    "icu", "sbs", "cfd", "bond", "lol", "loan", "download", "review", "country",
    "stream", "date", "racing", "science", "party", "faith", "accountant",
}


def _score_finding(rule_id: str, title: str, severity: str, confidence: str,
                   score: int, description: str, category: str,
                   evidence: Optional[list[str]] = None,
                   mitre: Optional[list[str]] = None,
                   recommendation: str = "") -> Finding:
    f = Finding(rule_id=rule_id, title=title, severity=severity, confidence=confidence,
                score=score, description=description, category=category,
                mitre=mitre or [], recommendation=recommendation)
    for item in (evidence or []):
        f.add_evidence(item)
    return f


# ==========================================================================
# Header / identity
# ==========================================================================

def check_headers(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    frm = e.from_addr
    if not frm or not frm.address:
        out.append(_score_finding(
            "PH-HDR-000", "Missing or unparseable From address", "medium", "high", 10,
            "The message has no usable From header. Legitimate mail always has one; "
            "its absence indicates a hand-crafted message or a broken sender.",
            "header", mitre=["T1566"]))
        return out

    from_domain = frm.domain
    display = frm.display_name or ""

    # --- PH-HDR-001: display name asserts an address that is not the real one ---
    # "PayPal Service <service@paypal.com>" as a display name, actually sent from
    # gibberish@sultanbogor.com. Mail clients show the display name, not the address.
    import re
    m = re.search(r"[\w.+\-]+@[\w.\-]+\.\w+", display)
    if m:
        claimed = m.group(0).lower()
        if claimed != frm.address:
            out.append(_score_finding(
                "PH-HDR-001",
                "Display name contains a different email address than the real sender",
                "critical", "high", 35,
                f"The display name presents '{claimed}' while the message was actually sent "
                f"from '{frm.address}'. Mail clients render the display name prominently and "
                "the real address only on inspection, which is exactly what this exploits.",
                "header", evidence=[f"From: {frm.raw}"], mitre=["T1566.002"],
                recommendation="Treat the sender as spoofed. Block the real sending domain."))

    # --- PH-HDR-002: display name claims a brand the domain does not belong to ---
    claimed_brands = brands_mentioned(display)
    if claimed_brands:
        actual_brand = brand_of_domain(from_domain)
        impostor = [b for b in claimed_brands if b != actual_brand]
        if impostor and not actual_brand:
            brand = impostor[0]
            free = registrable(from_domain) in FREEMAIL
            out.append(_score_finding(
                "PH-HDR-002",
                f"Display name impersonates {brand.title()} but the domain is unrelated",
                "critical", "high", 30 + (10 if free else 0),
                f"The display name '{display}' claims to be {brand.title()}, but the message "
                f"comes from '{from_domain}', which is not a {brand.title()} domain."
                + (" It is a free webmail domain — no brand sends transactional mail from "
                   "consumer webmail." if free else ""),
                "header", evidence=[f"From: {frm.raw}"], mitre=["T1566.002"],
                recommendation=f"Verify against the real {brand.title()} sending domains; "
                               "block and add the sender to the deny list."))

    # --- PH-HDR-003: generic authority display name from an unrelated domain ---
    low_display = display.lower().strip()
    if any(g in low_display for g in GENERIC_AUTHORITY) and not brand_of_domain(from_domain):
        out.append(_score_finding(
            "PH-HDR-003", f"Generic authority display name '{display}'", "medium", "medium", 12,
            f"'{display}' borrows institutional authority without naming a verifiable "
            f"organisation, while the sending domain '{from_domain}' has no relationship to it.",
            "header", evidence=[f"From: {frm.raw}"], mitre=["T1566"]))

    # --- PH-HDR-004: Reply-To diverges from From ---
    if e.reply_to and e.reply_to.address and e.reply_to.address != frm.address:
        reply_reg = registrable(e.reply_to.domain)
        # Two mailboxes at a free/disposable provider are two different people,
        # not one organisation: a "CEO" on gmail.com asking for replies to
        # another gmail.com account is the classic BEC setup.
        shared_provider = reply_reg in FREEMAIL or reply_reg in DISPOSABLE
        same_org = reply_reg == registrable(from_domain) and not shared_provider
        sev, sc = ("high", 22) if not same_org else ("low", 3)
        where = (f" -- a different {reply_reg} account, so a different person"
                 if reply_reg == registrable(from_domain) else " on a different domain")
        out.append(_score_finding(
            "PH-HDR-004", "Reply-To differs from the From address",
            sev, "high" if not same_org else "low", sc,
            f"Replies are directed to '{e.reply_to.address}' rather than the apparent sender "
            f"'{frm.address}'"
            + ("" if same_org else where + ". This is how an attacker receives "
               "the victim's reply while the message still appears to come from the "
               "impersonated party — the defining mechanic of BEC."),
            "header", evidence=[f"From: {frm.address}", f"Reply-To: {e.reply_to.address}"],
            mitre=["T1534"],
            recommendation="Route any reply nowhere; add the Reply-To address to the IOC list."))

    # --- PH-HDR-005: Return-Path / envelope mismatch (the SPF-checked identity) ---
    if e.return_path and e.return_path.domain:
        if registrable(e.return_path.domain) != registrable(from_domain):
            out.append(_score_finding(
                "PH-HDR-005", "Return-Path domain does not match the From domain",
                "medium", "medium", 14,
                f"The envelope sender is '{e.return_path.address}' ({e.return_path.domain}) "
                f"while the header From is '{from_domain}'. SPF validates the envelope, not the "
                "From the user sees, so a mismatch is how a message passes SPF while still "
                "displaying a spoofed sender — this is precisely what DMARC alignment catches.",
                "header", evidence=[f"Return-Path: {e.return_path.raw}", f"From: {frm.address}"],
                mitre=["T1566"]))

    # --- PH-HDR-006: BCC delivery ---
    if e.is_bcc_delivery:
        out.append(_score_finding(
            "PH-HDR-006", "Recipient was BCC'd rather than addressed directly",
            "medium", "high", 12,
            "The recipient does not appear in the To or Cc headers, so the message was blind "
            "carbon copied. Bulk phishing uses BCC to hide the recipient list and to send one "
            "message to many targets without revealing the campaign's scope.",
            "header", evidence=[f"To: {[a.address for a in e.to] or '(empty)'}"],
            mitre=["T1566"]))

    # --- PH-HDR-007: free / disposable sending domain ---
    reg_from = registrable(from_domain)
    if reg_from in DISPOSABLE:
        out.append(_score_finding(
            "PH-HDR-007", f"Sent from a disposable email provider ({reg_from})",
            "high", "high", 20,
            "Disposable/throwaway mail providers exist to be untraceable and are almost never "
            "used for legitimate business correspondence.",
            "header", evidence=[f"From: {frm.address}"], mitre=["T1566"]))
    elif reg_from in FREEMAIL and (claimed_brands or any(g in low_display for g in GENERIC_AUTHORITY)):
        out.append(_score_finding(
            "PH-HDR-008", "Corporate identity claimed from a free webmail account",
            "high", "high", 18,
            f"The message presents itself as '{display}' but was sent from {reg_from}, a "
            "consumer webmail provider. Organisations send from their own domains.",
            "header", evidence=[f"From: {frm.raw}"], mitre=["T1566.002"]))

    # --- PH-HDR-009: sending domain imitates a brand ---
    la = lookalike_brand(from_domain)
    if la:
        brand, legit, technique = la
        out.append(_score_finding(
            "PH-HDR-009", f"Sending domain imitates {brand.title()} ({technique})",
            "critical", "high", 35,
            f"'{from_domain}' is not a {brand.title()} domain but is constructed to be mistaken "
            f"for '{legit}' via {technique}. A reader scanning the address bar will not catch it.",
            "header", evidence=[f"From: {frm.address}", f"Legitimate: {legit}"],
            mitre=["T1583.001", "T1566.002"],
            recommendation=f"Block {from_domain}; check whether other users received mail from it."))

    # --- PH-HDR-010: suspicious TLD ---
    tld = from_domain.rsplit(".", 1)[-1] if "." in from_domain else ""
    if tld in SUSPICIOUS_TLDS:
        out.append(_score_finding(
            "PH-HDR-010", f"Sending domain uses a high-abuse TLD (.{tld})",
            "low", "medium", 8,
            f"'.{tld}' has a persistently high abuse rate. On its own this proves nothing, "
            "but it raises the weight of every other indicator on this message.",
            "header", evidence=[f"From: {frm.address}"]))

    # --- PH-HDR-011: no Received chain / forged origin ---
    if not e.received_chain:
        out.append(_score_finding(
            "PH-HDR-011", "No Received headers", "medium", "medium", 10,
            "The message carries no delivery path. Either the headers were stripped, or the "
            "message was crafted rather than delivered through mail servers.",
            "header"))
    elif len(e.received_chain) == 1:
        out.append(_score_finding(
            "PH-HDR-012", "Single-hop delivery path", "low", "low", 5,
            "Only one Received header. Internet mail normally traverses several servers; a "
            "single hop suggests direct injection into the receiving MTA.",
            "header", evidence=[e.received_chain[0].raw[:300]]))

    # --- PH-HDR-013: missing Message-ID ---
    if not e.message_id:
        out.append(_score_finding(
            "PH-HDR-013", "Missing Message-ID header", "low", "medium", 6,
            "Every conforming MTA stamps a Message-ID. Its absence points to a message "
            "generated by a script or a mass-mailing tool rather than a mail client.",
            "header"))

    # --- PH-HDR-014: subject/body claim a brand the sender is not ---
    text_brands = brands_mentioned(f"{e.subject}\n{e.body_text[:4000]}")
    if text_brands:
        actual = brand_of_domain(from_domain)
        mismatched = [b for b in text_brands if b != actual]
        already = {f.rule_id for f in out}
        if mismatched and not actual and "PH-HDR-002" not in already and "PH-HDR-009" not in already:
            out.append(_score_finding(
                "PH-HDR-014",
                f"Message content impersonates {mismatched[0].title()} but the sender is unrelated",
                "high", "medium", 20,
                f"The subject and body present the message as {mismatched[0].title()} "
                f"correspondence, while it was sent from '{from_domain}'.",
                "header", evidence=[f"Subject: {e.subject}", f"From: {frm.address}"],
                mitre=["T1566.002"]))

    return out


# ==========================================================================
# Authentication
# ==========================================================================

def check_authentication(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    a = e.auth
    from_domain = e.from_addr.domain if e.from_addr else ""

    fail_map = {
        AuthResult.FAIL: ("critical", 30,
                          "the sending server is NOT authorised for this domain; the receiving "
                          "policy for a Fail is to reject the message outright"),
        AuthResult.SOFTFAIL: ("high", 18,
                              "the sending server is not listed as authorised, but the domain "
                              "asked receivers to accept and flag rather than reject (~all)"),
        AuthResult.PERMERROR: ("medium", 12,
                               "the SPF record could not be evaluated — a syntax error, a lookup "
                               "limit breach, or a misconfiguration"),
        AuthResult.TEMPERROR: ("medium", 10, "a temporary DNS failure prevented evaluation"),
        AuthResult.NEUTRAL: ("low", 5, "the domain explicitly takes no position on this sender"),
        AuthResult.NONE: ("low", 6, "the domain publishes no SPF record at all"),
    }

    if a.spf in fail_map:
        sev, sc, why = fail_map[a.spf]
        out.append(_score_finding(
            "PH-AUTH-001", f"SPF {a.spf.value}", sev, "high", sc,
            f"SPF returned {a.spf.value} for {a.spf_domain or from_domain}: {why}. "
            f"The prescribed action for this result is to {a.spf_action} the message.",
            "auth", evidence=a.raw_headers[:3], mitre=["T1566"],
            recommendation="Confirm with the domain owner's published SPF record "
                           "(dmarcian SPF Surveyor) before releasing the message."))

    dkim_map = {
        AuthResult.FAIL: ("critical", 28,
                          "the signature did not validate against the public key in DNS, so the "
                          "message was altered in transit or the signature was forged"),
        AuthResult.PERMERROR: ("high", 16,
                               "permanent DKIM failure — an invalid signature, a missing or "
                               "incorrect DNS record, a forwarder modifying the message, or a "
                               "misconfigured setup"),
        AuthResult.TEMPERROR: ("medium", 8, "a temporary failure prevented key retrieval"),
        AuthResult.NONE: ("low", 6, "the message carries no DKIM signature"),
    }
    if a.dkim in dkim_map:
        sev, sc, why = dkim_map[a.dkim]
        out.append(_score_finding(
            "PH-AUTH-002", f"DKIM {a.dkim.value}", sev, "high", sc,
            f"DKIM returned {a.dkim.value}: {why}. DKIM survives forwarding, which makes a "
            "failure more meaningful than an SPF failure on a forwarded message.",
            "auth", evidence=a.raw_headers[:3], mitre=["T1566"]))

    if a.dmarc is AuthResult.FAIL:
        out.append(_score_finding(
            "PH-AUTH-003", "DMARC fail", "critical", "high", 32,
            f"DMARC failed for {from_domain}: neither SPF nor DKIM aligned with the domain in "
            "the From header. Alignment is the whole point of DMARC — it ties the "
            "authenticated identity to the identity the user actually sees."
            + (f" The domain's published policy is p={a.dmarc_policy}."
               if a.dmarc_policy else ""),
            "auth", evidence=a.raw_headers[:3], mitre=["T1566"],
            recommendation=("Quarantine or reject per the domain's policy. If the domain "
                            "publishes p=none, this message would still have been delivered — "
                            "raise that with the domain owner.")))
    elif a.dmarc in (AuthResult.NONE, AuthResult.UNKNOWN) and (
            a.spf in (AuthResult.FAIL, AuthResult.SOFTFAIL) or a.dkim is AuthResult.FAIL):
        out.append(_score_finding(
            "PH-AUTH-004", "No DMARC evaluation despite an SPF/DKIM failure",
            "medium", "medium", 10,
            "SPF or DKIM failed and no DMARC verdict was recorded, so nothing enforced a policy "
            "on the failure. The message was delivered on the strength of no decision at all.",
            "auth", evidence=a.raw_headers[:3]))

    if not a.raw_headers:
        out.append(_score_finding(
            "PH-AUTH-005", "No Authentication-Results header present", "medium", "medium", 8,
            "The receiving infrastructure recorded no SPF/DKIM/DMARC verdict. The message's "
            "sender identity is therefore entirely unverified — treat every identity claim in "
            "it as unproven.",
            "auth", recommendation="Verify the domain's SPF/DKIM/DMARC records manually "
                                   "(dmarcian Domain Checker) and evaluate the origin IP."))

    if a.all_passed:
        out.append(_score_finding(
            "PH-AUTH-006", "SPF, DKIM and DMARC all pass", "info", "high", -12,
            "All three authentication checks passed, so the message genuinely originates from "
            "infrastructure authorised by the From domain. Note what this does and does not "
            "mean: it proves the domain is real, not that it is trustworthy — an attacker's own "
            "domain, or a compromised legitimate account (BEC), passes all three.",
            "auth", evidence=a.raw_headers[:2]))

    return out


# ==========================================================================
# URLs
# ==========================================================================

def check_urls(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    urls = e.urls
    if not urls:
        return out

    shorteners = [u for u in urls if u.is_shortener]
    if shorteners:
        out.append(_score_finding(
            "PH-URL-001", f"URL shortener used ({len(shorteners)} link(s))",
            "high", "high", 20,
            "A shortening service hides the final destination, so neither the user nor a "
            "content filter can judge the landing page before the click. Legitimate "
            "transactional mail links to its own domain.",
            "url", evidence=[u.defanged for u in shorteners], mitre=["T1566.002"],
            recommendation="Expand the link without visiting it (wheregoes.com, urlscan.io) "
                           "and analyse the final destination."))

    lookalikes = [u for u in urls if u.lookalike_of]
    if lookalikes:
        out.append(_score_finding(
            "PH-URL-002", f"Link domain imitates a known brand ({len(lookalikes)})",
            "critical", "high", 35,
            "One or more links point to a domain constructed to be mistaken for a legitimate "
            "brand. This is the destination the credential-harvesting page lives on.",
            "url", evidence=[f"{u.defanged}  (imitates {u.lookalike_of})" for u in lookalikes],
            mitre=["T1583.001", "T1566.002"],
            recommendation="Block the domain at the proxy and gateway; submit to urlscan.io "
                           "for a screenshot of the landing page."))

    ip_links = [u for u in urls if u.is_ip_literal]
    if ip_links:
        out.append(_score_finding(
            "PH-URL-003", "Link points directly at an IP address", "high", "high", 25,
            "The link addresses a raw IP rather than a domain name. Legitimate services use "
            "named hosts with certificates; a bare IP means infrastructure set up to be "
            "disposable and unattributable.",
            "url", evidence=[u.defanged for u in ip_links], mitre=["T1566.002"]))

    pixels = [u for u in urls if u.is_tracking_pixel]
    if pixels:
        out.append(_score_finding(
            "PH-URL-004", f"Tracking pixel(s) embedded ({len(pixels)})",
            "medium", "high", 12,
            "The message embeds tiny or hidden remote images. Loading one tells the sender the "
            "mailbox is live, when it was opened, and often the client and IP — confirming the "
            "address as a target for follow-up. This is why mail clients block remote images "
            "by default.",
            "url", evidence=[f"{u.defanged}  [{'; '.join(u.notes)}]" for u in pixels],
            mitre=["T1598"],
            recommendation="Do not load remote content. Add the tracking host to the IOC list."))

    for u in urls:
        mismatch = display_text_mismatch(u)
        if mismatch:
            out.append(_score_finding(
                "PH-URL-005", "Link text does not match its destination",
                "critical", "high", 30, mismatch + ". The visible text is the lure; the href is "
                "where the click actually lands.", "url",
                evidence=[f"text: {u.display_text[:120]}", f"href: {u.defanged}"],
                mitre=["T1566.002"]))
            break

    cred_urls = [u for u in urls
                 if any("credential/payment page" in n for n in u.notes)]
    if cred_urls:
        external = [u for u in cred_urls if not brand_of_domain(u.domain)]
        if external:
            out.append(_score_finding(
                "PH-URL-006", "Link path indicates a credential or payment page",
                "high", "medium", 18,
                "The URL path contains login/verify/account/billing terms and the host does not "
                "belong to the brand being impersonated — the shape of a harvesting portal.",
                "url", evidence=[u.defanged for u in external[:5]], mitre=["T1566.002", "T1056"]))

    abused = [u for u in urls if any("frequently abused" in n for n in u.notes)]
    if abused:
        out.append(_score_finding(
            "PH-URL-007", "Link hosted on a commonly abused platform", "medium", "medium", 12,
            "The landing page sits on a legitimate hosting or file-sharing platform. Attackers "
            "use these because the domain reputation is good and TLS is provided free — the "
            "platform's trustworthiness says nothing about the page.",
            "url", evidence=[u.defanged for u in abused[:5]], mitre=["T1583.006"]))

    wrapped = [u for u in urls if u.redirect_chain]
    if wrapped:
        out.append(_score_finding(
            "PH-URL-008", "Link passes through a redirect or rewriting service",
            "medium", "medium", 10,
            "The URL was unwrapped through a click-tracking or link-rewriting service. Chained "
            "redirection hides the destination from basic filters and is the mechanism behind "
            "multi-stage lures (a share page, then a document page, then the login portal).",
            "url", evidence=[" -> ".join([*u.redirect_chain, u.url])[:380] for u in wrapped[:3]]))

    # Sender domain never appears among the link domains
    if e.from_addr and e.from_addr.domain and urls:
        from_reg = registrable(e.from_addr.domain)
        link_regs = {registrable(u.domain) for u in urls if u.domain}
        clickable = [u for u in urls if u.source in ("html_href", "text")]
        if clickable and from_reg not in link_regs:
            out.append(_score_finding(
                "PH-URL-009", "No link points back to the sender's own domain",
                "low", "low", 6,
                f"Every link leads away from '{from_reg}'. Legitimate transactional mail almost "
                "always contains at least one link to the sender's own site.",
                "url", evidence=sorted(link_regs)[:8]))

    return out


# ==========================================================================
# Attachments
# ==========================================================================

def check_attachments(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    for a in e.attachments:
        if a.has_double_extension:
            out.append(_score_finding(
                "PH-ATT-001", f"Double extension on '{a.filename}'", "critical", "high", 40,
                f"'{a.filename}' presents a benign extension followed by an executable one. "
                "Windows hides known extensions by default, so the user sees only the harmless "
                "half.",
                "attachment", evidence=[f"{a.filename}  sha256={a.sha256}"],
                mitre=["T1566.001", "T1036.007"],
                recommendation="Do not open. Detonate in a sandbox; submit the SHA256 to "
                               "VirusTotal and block it at the gateway."))
        elif a.is_dangerous:
            out.append(_score_finding(
                "PH-ATT-002", f"Executable attachment '{a.filename}'", "critical", "high", 38,
                f"'.{a.extension}' is directly executable or script-capable. Legitimate business "
                "correspondence effectively never delivers one by email.",
                "attachment", evidence=[f"{a.filename}  sha256={a.sha256}"] + a.notes,
                mitre=["T1566.001", "T1204.002"],
                recommendation="Quarantine the message. Sandbox the file and hunt the hash "
                               "across the estate."))
        elif a.macro_capable:
            out.append(_score_finding(
                "PH-ATT-003", f"Macro-capable document '{a.filename}'", "high", "medium", 22,
                f"'.{a.extension}' can carry VBA macros or remote-template references, which is "
                "how an Office attachment executes code on open."
                + (" A .dot (Word template) is a particularly unusual format for a receipt or "
                   "invoice." if a.extension in ("dot", "dotm") else ""),
                "attachment", evidence=[f"{a.filename}  sha256={a.sha256}"] + a.notes,
                mitre=["T1566.001", "T1204.002", "T1221"],
                recommendation="Detonate in ANY.RUN / Hybrid Analysis / Joe Sandbox and record "
                               "the network callbacks and dropped files."))

        if a.embedded_urls:
            out.append(_score_finding(
                "PH-ATT-004", f"Attachment '{a.filename}' contains embedded links",
                "high", "high", 24,
                f"{len(a.embedded_urls)} URL(s) are embedded inside the attachment. Putting the "
                "link in a document instead of the message body is how the URL is kept away "
                "from link scanners and reputation checks that only read the body.",
                "attachment",
                evidence=[__import__("phishkit.iocs", fromlist=["defang"]).defang(u)
                          for u in a.embedded_urls[:6]],
                mitre=["T1566.001"],
                recommendation="Analyse each embedded URL as if it had been in the body."))

        if a.notes:
            magic = [n for n in a.notes if "magic bytes" in n or "MZ" in n]
            if magic:
                out.append(_score_finding(
                    "PH-ATT-005", f"File type does not match extension: '{a.filename}'",
                    "critical", "high", 35,
                    "; ".join(magic) + ". Deliberate mislabelling defeats extension-based "
                    "filtering and misleads the user.",
                    "attachment", evidence=[f"sha256={a.sha256}"], mitre=["T1036.008"]))

        if a.extension in {"zip", "rar", "7z", "iso", "img"}:
            out.append(_score_finding(
                "PH-ATT-006", f"Archive/container attachment '{a.filename}'",
                "medium", "medium", 14,
                f"'.{a.extension}' hides its contents from most mail filters."
                + (" ISO/IMG containers also bypass Mark-of-the-Web, so files extracted from "
                   "them do not trigger the usual 'downloaded from the internet' warnings."
                   if a.extension in {"iso", "img"} else ""),
                "attachment", evidence=[f"{a.filename}  sha256={a.sha256}"],
                mitre=["T1566.001", "T1553.005"]))

    # An empty body whose only content is an attachment
    body_len = len((e.body_text or "").strip()) + len((e.body_html or "").strip())
    if e.attachments and body_len < 120:
        out.append(_score_finding(
            "PH-ATT-007", "Empty message body with an attachment", "high", "medium", 20,
            "The message carries no meaningful body text — its entire purpose is to deliver the "
            "attachment. A legitimate sender explains what they are sending and why.",
            "attachment", evidence=[a.filename for a in e.attachments],
            mitre=["T1566.001"]))

    return out


# ==========================================================================
# Social engineering
# ==========================================================================

def check_social(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    body = (e.body_text or "") + "\n" + (e.body_html or "")[:20000]
    sa = analyse_language(e.subject or "", body)

    if sa.misspellings:
        pairs = ", ".join(f"'{k}' (for {v})" for k, v in list(sa.misspellings.items())[:4])
        out.append(_score_finding(
            "PH-SOC-001", "Deliberately misspelled brand name", "high", "high", 22,
            f"The message contains {pairs}. A near-miss spelling reads correctly at a glance "
            "while evading exact-match brand filters — this is a technique, not a typo.",
            "social", evidence=list(sa.misspellings.keys()), mitre=["T1566"]))

    if sa.urgency or sa.threat:
        terms = (sa.urgency + sa.threat)[:6]
        sev = "high" if (sa.urgency and sa.threat) else "medium"
        out.append(_score_finding(
            "PH-SOC-002", "Artificial urgency and/or consequence framing", sev, "medium",
            10 + 6 * bool(sa.urgency and sa.threat),
            "The message manufactures time pressure and threatens a consequence "
            f"({', '.join(terms)}). Urgency exists to prevent the recipient from stopping to "
            "verify — it is the load-bearing element of the lure.",
            "social", evidence=terms, mitre=["T1566"]))

    if sa.credential:
        out.append(_score_finding(
            "PH-SOC-003", "Requests credentials or payment details", "high", "high", 25,
            f"The message asks the recipient to supply or confirm sensitive information "
            f"({', '.join(sa.credential[:4])}). No legitimate provider asks for credentials via "
            "an emailed link.",
            "social", evidence=sa.credential[:6], mitre=["T1598.003", "T1566.002"]))

    if sa.bec and not e.urls and not e.attachments:
        out.append(_score_finding(
            "PH-SOC-004", "Business Email Compromise pattern", "critical", "medium", 28,
            f"The message contains no link and no attachment — only an authority-backed request "
            f"({', '.join(sa.bec[:4])}). BEC carries no technical payload, which is why gateways "
            "pass it: the payload is the instruction itself.",
            "social", evidence=sa.bec[:6], mitre=["T1534", "T1566"],
            recommendation="Verify out of band with the named individual on a known-good number. "
                           "Never confirm via a reply to this thread."))

    if sa.generic_greeting:
        out.append(_score_finding(
            "PH-SOC-005", "Generic, impersonal greeting", "low", "medium", 6,
            f"The message opens with {sa.generic_greeting[0]!r}. A provider that holds an "
            "account for you knows your name; bulk phishing cannot personalise at scale.",
            "social", evidence=sa.generic_greeting[:3], mitre=["T1566"]))

    exec_hit = targets_executive(f"{e.subject}\n{body[:3000]}")
    if exec_hit and (sa.bec or sa.urgency):
        out.append(_score_finding(
            "PH-SOC-006", f"Executive impersonation or targeting ({exec_hit})",
            "high", "medium", 18,
            f"The message references '{exec_hit}' alongside urgency or a financial request — "
            "the whaling pattern, where authority substitutes for verification.",
            "social", evidence=[exec_hit], mitre=["T1566", "T1534"]))

    if sa.excessive_caps or sa.excessive_punctuation:
        out.append(_score_finding(
            "PH-SOC-007", "Subject line uses attention-grabbing formatting", "low", "low", 4,
            "Excessive capitalisation or punctuation in the subject is a bulk-mail signal.",
            "social", evidence=[e.subject]))

    if sa.score >= 30:
        out.append(_score_finding(
            "PH-SOC-008", f"High social-engineering density (language score {sa.score})",
            "medium", "medium", 8,
            "Multiple independent lure categories appear together — urgency, threat, credential "
            "request and a single call to action. The combination is far more indicative than "
            "any one of them alone.",
            "social", evidence=[str(sa.as_dict())[:380]]))

    return out


# ==========================================================================
# Scoring and verdict
# ==========================================================================

VERDICT_THRESHOLDS = [
    (50, Verdict.PHISHING),
    (25, Verdict.SUSPICIOUS),
    (10, Verdict.SPAM),
]


def score_to_verdict(score: int, has_malicious_attachment: bool = False) -> Verdict:
    """
    Map the summed score to a disposition.

    MALICIOUS is reserved for *weaponised* mail — one carrying an executable,
    double-extension or macro-capable attachment. A credential-harvesting page
    with no payload is PHISHING however high it scores: the distinction changes
    the response (host containment and hash hunting vs. credential reset and
    URL blocking), so collapsing them would mislead the responder.
    """
    if has_malicious_attachment and score >= 50:
        return Verdict.MALICIOUS
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return Verdict.BENIGN


ALL_CHECKS = (check_headers, check_authentication, check_urls, check_attachments, check_social)


def run_all(e: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check(e))
        except Exception as exc:                      # a broken rule must not kill the case
            findings.append(_score_finding(
                "PH-ERR-001", f"Detector {check.__name__} failed", "info", "low", 0,
                f"{type(exc).__name__}: {exc}", "general"))
    return findings
