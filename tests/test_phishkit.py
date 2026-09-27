"""
Verification suite.  python tests/test_phishkit.py   (or: python -m pytest tests/ -q)

Covers parsing, each analysis primitive, each detector's positive case, and a
negative case for every rule that could plausibly over-fire — plus a full
end-to-end pass over the generated sample corpus, including a legitimate
message that must come back BENIGN.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from email.message import EmailMessage
from email.utils import formatdate

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishkit import analyze_bytes, analyze_file                       # noqa: E402
from phishkit.brands import (brand_of_domain, brands_mentioned,        # noqa: E402
                             levenshtein, lookalike_brand, registrable, skeleton)
from phishkit.detectors import score_to_verdict                        # noqa: E402
from phishkit.iocs import defang, refang, to_csv, to_misp, to_stix_lite  # noqa: E402
from phishkit.models import AuthResult, Verdict                        # noqa: E402
from phishkit.parser import (originating_ip, parse_address,            # noqa: E402
                             parse_authentication_results, parse_email_bytes,
                             parse_received)
from phishkit.social import analyse_language, targets_executive        # noqa: E402
from phishkit.urls import display_text_mismatch, extract_urls, unwrap  # noqa: E402


def build(subject="Test", frm="a@example.com", to="v@example.org",
          text="hello", html=None, headers=None, attachments=None) -> bytes:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = frm
    if to:
        m["To"] = to
    m["Date"] = formatdate(1726000000, localtime=False)
    m["Message-ID"] = "<test@example.org>"
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for fn, data, mt, st in (attachments or []):
        m.add_attachment(data, maintype=mt, subtype=st, filename=fn)
    return m.as_bytes()


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


# ==========================================================================
# Address / header parsing
# ==========================================================================

def test_parse_address_anatomy():
    a = parse_address('"David" <david@example.com>')
    assert a.display_name == "David"
    assert a.address == "david@example.com"
    assert a.local_part == "david"          # the mailbox on the destination system
    assert a.domain == "example.com"      # the server responsible for the message


def test_parse_address_bare():
    a = parse_address("service@paypal.com")
    assert a.address == "service@paypal.com" and a.display_name == ""


def test_parse_encoded_subject():
    raw = build(subject="=?utf-8?B?VXJnZW50OiBBY3Rpb24gUmVxdWlyZWQ=?=")
    e = parse_email_bytes(raw)
    assert e.subject == "Urgent: Action Required"


def test_received_parsing_and_origin():
    hops = [
        parse_received("from relay.internal (relay.internal [10.0.0.5]) by mx.example.org "
                       "with ESMTP; Mon, 9 Sep 2024 12:00:02 +0000", 0),
        parse_received("from evil.example (evil.example [203.0.113.9]) by relay.internal "
                       "with SMTP; Mon, 9 Sep 2024 12:00:00 +0000", 1),
    ]
    assert hops[1].from_ip == "203.0.113.9"
    assert hops[0].by_host == "mx.example.org"
    # Received headers are prepended, so the LAST entry is the origin; internal
    # RFC1918 relays must not be reported as the source.
    assert originating_ip(hops) == "203.0.113.9"


def test_originating_ip_skips_private():
    hops = [parse_received("from a (a [192.168.1.9]) by b; Mon, 9 Sep 2024 12:00:00 +0000", 0),
            parse_received("from c (c [10.1.1.1]) by d; Mon, 9 Sep 2024 12:00:00 +0000", 1)]
    assert originating_ip(hops) in ("10.1.1.1", "192.168.1.9")   # no public hop exists


def test_authentication_results_parsing():
    ar = parse_authentication_results([
        ("Authentication-Results",
         "mx.example.org; spf=fail smtp.mailfrom=sultanbogor.example; "
         "dkim=permerror header.d=beginpro.example; dmarc=fail p=reject"),
    ])
    assert ar.spf is AuthResult.FAIL
    assert ar.dkim is AuthResult.PERMERROR
    assert ar.dmarc is AuthResult.FAIL
    # The greedy-local-part bug truncated this to "r.example".
    assert ar.spf_domain == "sultanbogor.example"
    assert ar.dkim_domain == "beginpro.example"
    assert ar.dmarc_policy == "reject"


def test_spf_action_mapping():
    ar = parse_authentication_results([("Received-SPF", "softfail (example)")])
    assert ar.spf is AuthResult.SOFTFAIL
    assert ar.spf_action == "flag"           # SoftFail => accept but mark suspicious
    ar2 = parse_authentication_results([("Received-SPF", "fail (example)")])
    assert ar2.spf_action == "reject"
    ar3 = parse_authentication_results([("Received-SPF", "pass (example)")])
    assert ar3.spf_action == "accept"


# ==========================================================================
# Enrichment primitives
# ==========================================================================

def test_defang_roundtrip():
    assert defang("http://www.suspiciousdomain.com") == "hxxp[://]www[.]suspiciousdomain[.]com"
    assert defang("1.2.3.4") == "1[.]2[.]3[.]4"
    assert defang("bob@evil.com") == "bob[@]evil[.]com"
    assert refang("hxxp[://]www[.]evil[.]com/a.php") == "http://www.evil.com/a.php"
    assert refang(defang("https://evil.com/x")) == "https://evil.com/x"


def test_defang_keeps_path_readable():
    d = defang("https://evil.com/login/verify.php?id=1")
    assert "[.]" in d and "/login/verify.php" in d


def test_skeleton_and_levenshtein():
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("netfIix") == skeleton("netflix")     # capital I vs lowercase l
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert levenshtein("gogle", "google") == 1
    assert levenshtein("abc", "xyz", cap=1) > 1


def test_registrable_domain():
    assert registrable("a.b.evil.co.uk") == "evil.co.uk"
    assert registrable("mail.google.com") == "google.com"


def test_brand_lookalikes_positive():
    for domain in ("paypa1.com", "netfIix.com", "micros0ft.com", "arnazon.com",
                   "paypal-secure.com", "paypal.com.verify-account.ru",
                   "verify-apple-id.net", "dhl-express-tracking.example"):
        assert lookalike_brand(domain), f"{domain} should be flagged"


def test_brand_lookalikes_negative():
    """Real brand infrastructure and ordinary words must not be flagged."""
    for domain in ("paypal.com", "paypalobjects.com", "microsoftonline.com",
                   "outlook.office365.com", "github.com", "amazonaws.com",
                   "live-stream.tv", "delivery-service.net", "my-bank.co.uk",
                   "apple-orchard-farm.co.uk", "target-practice.com",
                   "chase-the-sun.blog", "applied-research.org"):
        assert not lookalike_brand(domain), f"{domain} false positive"


def test_brand_of_domain():
    assert brand_of_domain("mail.paypal.com") == "paypal"
    assert brand_of_domain("outlook.office365.com") == "microsoft"
    assert brand_of_domain("evil.example") is None


def test_brands_mentioned():
    assert "netflix" in brands_mentioned("Your Netflix account")
    assert "microsoft" in brands_mentioned("Shared via OneDrive")
    assert brands_mentioned("Just a normal message") == set()


# ==========================================================================
# URL analysis
# ==========================================================================

def test_extract_urls_from_href_and_text():
    urls = extract_urls(body_text="visit http://plain.example/a",
                        body_html='<a href="https://href.example/b">Click here</a>')
    got = {u.url for u in urls}
    assert "http://plain.example/a" in got
    assert "https://href.example/b" in got
    anchor = next(u for u in urls if u.url.endswith("/b"))
    assert anchor.display_text == "Click here"


def test_shortener_detection():
    urls = extract_urls(body_html='<a href="https://bit.ly/phishkit-demo-refund">Cancel the order</a>')
    assert urls[0].is_shortener


def test_ip_literal_link():
    urls = extract_urls(body_html='<a href="http://198.51.100.203/track.php">track</a>')
    assert urls[0].is_ip_literal


def test_tracking_pixel_detection():
    urls = extract_urls(
        body_html='<img src="http://beginpro.example/Tracking.png?uid=1" '
                  'width="1" height="1" style="display:none">')
    assert urls and urls[0].is_tracking_pixel


def test_normal_image_is_not_a_pixel():
    urls = extract_urls(
        body_html='<img src="https://cdn.example/logo.png" width="200" height="60" alt="Logo">')
    assert urls and not urls[0].is_tracking_pixel


def test_display_text_mismatch_positive():
    urls = extract_urls(
        body_html='<a href="http://198.51.100.9/x">ups.example/track/1Z999AA1</a>')
    assert display_text_mismatch(urls[0])


def test_display_text_mismatch_ignores_plain_labels():
    """'Cancel the order' is a label, not a claimed destination."""
    urls = extract_urls(body_html='<a href="https://bit.ly/abc">Cancel the order</a>')
    assert display_text_mismatch(urls[0]) is None


def test_display_text_mismatch_same_org_ok():
    urls = extract_urls(
        body_html='<a href="https://mail.github.com/x">github.com/settings</a>')
    assert display_text_mismatch(urls[0]) is None


def test_unwrap_safelinks():
    wrapped = ("https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example"
               "%2Flogin&data=05")
    final, chain = unwrap(wrapped)
    assert final == "https://evil.example/login"
    assert chain == [wrapped]


def test_credential_path_flagged():
    urls = extract_urls(body_html='<a href="http://x.example/secure/login/verify.php">go</a>')
    assert any("credential/payment page" in n for n in urls[0].notes)


# ==========================================================================
# Social engineering
# ==========================================================================

def test_language_urgency_and_threat():
    sa = analyse_language("Action Required: Your account will be suspended",
                          "You must verify your account immediately within 24 hours.")
    assert sa.urgency and sa.threat and sa.credential
    assert sa.score > 25


def test_language_benign():
    sa = analyse_language("Meeting notes from Tuesday",
                          "Hi Alex, here are the notes from our sync. Thanks, Sam")
    assert sa.score < 10


def test_brand_misspelling_detected():
    sa = analyse_language("Your Netllx ID has been suspended", "Update billing")
    assert "netllx" in sa.misspellings


def test_executive_targeting():
    assert targets_executive("From the CEO regarding an urgent transfer")
    assert targets_executive("Lunch on Thursday?") is None


# ==========================================================================
# Detector positives
# ==========================================================================

def test_display_name_spoof():
    r = analyze_bytes(build(frm='"service@paypal.com" <gibberish@evil.example>'))
    assert "PH-HDR-001" in rule_ids(r)


def test_brand_impersonation_display_name():
    r = analyze_bytes(build(frm='"PayPal Service" <billing@evil.example>'))
    assert "PH-HDR-002" in rule_ids(r)


def test_no_impersonation_flag_for_real_brand():
    r = analyze_bytes(build(frm='"GitHub" <noreply@github.com>'))
    assert "PH-HDR-002" not in rule_ids(r)
    assert "PH-HDR-009" not in rule_ids(r)


def test_reply_to_divergence():
    r = analyze_bytes(build(frm="ceo@corp.example",
                            headers={"Reply-To": "attacker@evil.example"}))
    assert "PH-HDR-004" in rule_ids(r)


def test_reply_to_same_org_is_low():
    r = analyze_bytes(build(frm="noreply@corp.example",
                            headers={"Reply-To": "support@corp.example"}))
    f = next((f for f in r.findings if f.rule_id == "PH-HDR-004"), None)
    assert f is not None and f.severity == "low" and f.score <= 5


def test_reply_to_another_freemail_account_is_not_same_org():
    # gmail.com -> another gmail.com mailbox: same domain, different person.
    r = analyze_bytes(build(frm='"Margaret Ellis (CEO)" <m_ellis@gmail.com>',
                            headers={"Reply-To": "m_ellis.finance@gmail.com"}))
    f = next((f for f in r.findings if f.rule_id == "PH-HDR-004"), None)
    assert f is not None and f.severity == "high" and f.score == 22
    assert "different gmail.com account" in f.description


def test_bcc_delivery():
    r = analyze_bytes(build(to=None, headers={"Delivered-To": "victim@example.org"}))
    assert "PH-HDR-006" in rule_ids(r)


def test_lookalike_sender_domain():
    r = analyze_bytes(build(frm='"Support" <billing@paypa1.com>'))
    assert "PH-HDR-009" in rule_ids(r)


def test_spf_fail_finding():
    r = analyze_bytes(build(headers={
        "Authentication-Results": "mx; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail"}))
    ids = rule_ids(r)
    assert "PH-AUTH-001" in ids and "PH-AUTH-003" in ids


def test_all_auth_pass_reduces_score():
    passing = analyze_bytes(build(frm="noreply@github.com", headers={
        "Authentication-Results": "mx; spf=pass smtp.mailfrom=github.com; "
                                  "dkim=pass header.d=github.com; dmarc=pass"}))
    assert "PH-AUTH-006" in rule_ids(passing)
    neg = next(f for f in passing.findings if f.rule_id == "PH-AUTH-006")
    assert neg.score < 0        # authentication success must pull the score DOWN


def test_shortener_finding():
    r = analyze_bytes(build(html='<a href="https://bit.ly/xyz">Cancel</a>'))
    assert "PH-URL-001" in rule_ids(r)


def test_tracking_pixel_finding():
    r = analyze_bytes(build(html='<img src="http://e.example/p.gif" width="1" height="1">'))
    assert "PH-URL-004" in rule_ids(r)


def test_dangerous_attachment():
    r = analyze_bytes(build(attachments=[("payload.exe", b"MZ\x90\x00stub",
                                          "application", "octet-stream")]))
    assert "PH-ATT-002" in rule_ids(r)


def test_double_extension():
    r = analyze_bytes(build(attachments=[("invoice.pdf.exe", b"MZ\x90\x00",
                                          "application", "octet-stream")]))
    assert "PH-ATT-001" in rule_ids(r)


def test_macro_capable_document():
    r = analyze_bytes(build(attachments=[("Receipt.dot", b"\xd0\xcf\x11\xe0stub",
                                          "application", "msword")]))
    assert "PH-ATT-003" in rule_ids(r)


def test_renamed_executable_detected_by_magic_bytes():
    r = analyze_bytes(build(attachments=[("report.pdf", b"MZ\x90\x00this is a PE",
                                          "application", "pdf")]))
    assert "PH-ATT-005" in rule_ids(r)


def test_empty_body_with_attachment():
    r = analyze_bytes(build(text=" ", attachments=[("x.dot", b"\xd0\xcf\x11\xe0",
                                                    "application", "msword")]))
    assert "PH-ATT-007" in rule_ids(r)


def test_pdf_embedded_url_extracted():
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    from make_phish_samples import make_pdf_with_link
    pdf = make_pdf_with_link("http://evil.example/netflix/login.php")
    r = analyze_bytes(build(attachments=[("doc.pdf", pdf, "application", "pdf")]))
    assert "PH-ATT-004" in rule_ids(r)
    assert any("evil.example" in u.url for u in r.email.urls)


def test_bec_pattern():
    r = analyze_bytes(build(
        subject="Are you at your desk?",
        frm='"Margaret Ellis (CEO)" <m_ellis@gmail.com>',
        text="I need you to process an urgent payment. The banking details have "
             "changed. Please keep this confidential. I'm in a meeting."))
    assert "PH-SOC-004" in rule_ids(r)
    assert Verdict.PHISHING == r.verdict or r.score >= 25


def test_credential_request_language():
    r = analyze_bytes(build(text="Please verify your account and confirm your password."))
    assert "PH-SOC-003" in rule_ids(r)


def test_generic_greeting():
    r = analyze_bytes(build(text="Dear Customer, your invoice is attached."))
    assert "PH-SOC-005" in rule_ids(r)


# ==========================================================================
# Detector negatives — a legitimate message must stay clean
# ==========================================================================

def test_legitimate_message_is_benign():
    raw = build(
        subject="Your monthly statement is ready",
        frm='"GitHub" <noreply@github.com>',
        text="Hi Alex,\n\nYour September statement is available.\n\nThanks,\nThe GitHub team",
        html='<p>Hi Alex,</p><p><a href="https://github.com/settings/billing">'
             'View your statement</a></p>',
        headers={"Authentication-Results":
                 "mx; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; "
                 "dmarc=pass p=reject",
                 "Return-Path": "<noreply@github.com>"})
    r = analyze_bytes(raw)
    assert r.verdict is Verdict.BENIGN, f"scored {r.score}: {[f.rule_id for f in r.findings]}"
    assert r.phish_types == []


def test_marketing_email_not_phishing():
    """Urgency + a tracking pixel + a shortener alone must not reach 'phishing'."""
    raw = build(
        subject="Last chance: 20% off ends today",
        frm='"Acme Store" <news@acmestore.example>',
        text="Our sale ends today. Shop now.",
        html='<a href="https://acmestore.example/sale">Shop now</a>'
             '<img src="https://acmestore.example/open.gif" width="1" height="1">',
        headers={"Authentication-Results":
                 "mx; spf=pass smtp.mailfrom=acmestore.example; "
                 "dkim=pass header.d=acmestore.example; dmarc=pass"})
    r = analyze_bytes(raw)
    assert r.verdict in (Verdict.BENIGN, Verdict.SPAM, Verdict.SUSPICIOUS), \
        f"{r.verdict} at {r.score}"


def test_internal_newsletter_with_many_links_is_clean():
    links = "".join(f'<a href="https://intranet.corp.example/a{i}">Item {i}</a>'
                    for i in range(15))
    raw = build(subject="Weekly team digest",
                frm='"Comms" <comms@corp.example>',
                text="This week's updates.", html=links,
                headers={"Authentication-Results":
                         "mx; spf=pass smtp.mailfrom=corp.example; "
                         "dkim=pass header.d=corp.example; dmarc=pass"})
    r = analyze_bytes(raw)
    assert r.verdict in (Verdict.BENIGN, Verdict.SPAM)


# ==========================================================================
# Scoring / verdicts
# ==========================================================================

def test_verdict_thresholds():
    assert score_to_verdict(0) is Verdict.BENIGN
    assert score_to_verdict(12) is Verdict.SPAM
    assert score_to_verdict(30) is Verdict.SUSPICIOUS
    assert score_to_verdict(60) is Verdict.PHISHING
    # MALICIOUS is reserved for weaponised mail, not merely a high score.
    assert score_to_verdict(200) is Verdict.PHISHING
    assert score_to_verdict(60, has_malicious_attachment=True) is Verdict.MALICIOUS


# ==========================================================================
# IOC export
# ==========================================================================

def test_ioc_collection_and_export():
    r = analyze_bytes(build(
        frm='"Support" <billing@paypa1.com>',
        html='<a href="http://evil.example/login">verify</a>',
        attachments=[("x.exe", b"MZ\x90\x00", "application", "octet-stream")]))
    iocs = r.iocs
    assert any("paypa1" in v for v in iocs.get("sender_domains", []))
    assert any("evil" in v for v in iocs.get("urls", []))
    assert iocs.get("attachment_sha256")
    # Everything exported to a human is defanged.
    assert all("hxxp" in u or "[" in u for u in iocs["urls"])
    # Machine formats are refanged so a tool can consume them.
    assert "http://evil.example/login" in to_misp(iocs)
    assert "stix" in to_stix_lite(iocs)
    assert "misp_type" in to_csv(iocs)


# ==========================================================================
# End-to-end over the sample corpus
# ==========================================================================

def test_sample_corpus_end_to_end():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, os.path.join(root, "tools", "make_phish_samples.py"), tmp],
                       check=True, capture_output=True, cwd=root)
        expected = {
            "1_paypal_shortener.eml": {Verdict.PHISHING, Verdict.MALICIOUS},
            "2_shipping_pixel.eml": {Verdict.PHISHING, Verdict.MALICIOUS},
            "3_credential_harvest.eml": {Verdict.PHISHING, Verdict.MALICIOUS},
            "4_netflix_pdf.eml": {Verdict.PHISHING, Verdict.MALICIOUS},
            "5_apple_dot_bcc.eml": {Verdict.MALICIOUS},
            "6_dhl_xlsx.eml": {Verdict.MALICIOUS},
            "7_bec_wire.eml": {Verdict.PHISHING, Verdict.SUSPICIOUS},
            "8_legitimate.eml": {Verdict.BENIGN},
        }
        for name, allowed in expected.items():
            r = analyze_file(os.path.join(tmp, name))
            assert r.verdict in allowed, \
                f"{name}: got {r.verdict.value} (score {r.score}), expected {allowed}"


# ==========================================================================
# Outlook .msg (native), mbox, and IOC context separation
# ==========================================================================

_MSG_HEADERS = "\r\n".join([
    "Received: from mail.bad.example (mail.bad.example [203.0.113.5]) by mx.example.org "
    "with ESMTP id X; Wed, 11 Sep 2024 04:46:40 +0000",
    "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=bad.example; dkim=none; "
    "dmarc=fail",
    'From: "PayPal Service" <service@bad.example>',
    "To: victim@example.org",
    "Subject: Confirm your account",
    "Message-ID: <m1@bad.example>",
])


def test_msg_round_trip_native():
    from phishkit.msg import build_msg
    from phishkit.parser import parse_email_bytes  # noqa: F401 (import check)
    big = b"%PDF-1.4\n" + b"A" * 9000 + b"/URI (http://evil.example/pay)"   # > 4 KiB: regular sectors
    raw = build_msg(_MSG_HEADERS, "Confirm your account", "Please verify your account now.",
                    html='<a href="http://evil.example/login">verify</a>',
                    attachments=[("statement.pdf", big), ("tiny.txt", b"hi")])
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "report.msg")
        with open(path, "wb") as fh:
            fh.write(raw)
        r = analyze_file(path)
    e = r.email
    assert e.from_addr.address == "service@bad.example"
    assert e.auth.spf is AuthResult.FAIL and e.originating_ip == "203.0.113.5"
    assert [a.filename for a in e.attachments] == ["statement.pdf", "tiny.txt"]
    assert e.attachments[0].data == big                         # regular-sector stream intact
    assert any("evil.example/pay" in u.url for u in e.urls)      # link inside the PDF
    assert any("evil.example/login" in u.url for u in e.urls)    # link in the HTML body
    assert r.verdict in (Verdict.PHISHING, Verdict.MALICIOUS)


def test_msg_without_transport_headers_says_so():
    from phishkit.msg import build_msg
    raw = build_msg("", "Draft", "hello")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "draft.msg")
        with open(path, "wb") as fh:
            fh.write(raw)
        r = analyze_file(path)
    assert r.email.subject == "Draft"
    assert any("transport headers" in n for n in r.email.parse_errors)


def test_renamed_msg_is_recognised_by_content():
    from phishkit.msg import build_msg
    raw = build_msg(_MSG_HEADERS, "Confirm your account", "verify your account")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "forwarded.eml")          # wrong extension on purpose
        with open(path, "wb") as fh:
            fh.write(raw)
        r = analyze_file(path)
    assert r.email.from_addr.address == "service@bad.example"


def test_mbox_is_split_into_messages():
    import mailbox
    from phishkit import analyze_paths
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "box.mbox")
        box = mailbox.mbox(path)
        for i in range(3):
            box.add(build(subject=f"message {i}"))
        box.flush()
        box.close()
        results = analyze_paths([path])
    assert [r.email.subject for r in results] == ["message 0", "message 1", "message 2"]
    assert results[1].email.source_path.endswith("#2")


def _sample(name):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "samples", "phishkit", name)


def test_ioc_context_keeps_webmail_out_of_blocklists():
    from phishkit.iocs import to_blocklist
    r = analyze_file(_sample("7_bec_wire.eml"))
    assert "gmail[.]com" in r.iocs["context_domains"]
    assert "gmail[.]com" not in r.iocs.get("sender_domains", [])
    assert "m_ellis[.]ceo[@]gmail[.]com" in r.iocs["sender_addresses"]
    assert r.iocs.get("context_ips") and not r.iocs.get("originating_ips")
    lines = to_blocklist(r.iocs).splitlines()
    assert "gmail.com" not in lines and "outlook.com" not in lines
    assert "m_ellis.ceo@gmail.com" in lines
    assert "m_ellis.finance@gmail.com" in lines      # the BEC reply-to: where replies go


def test_ioc_unwraps_safelinks_destination():
    r = analyze_file(_sample("3_credential_harvest.eml"))
    assert "hxxps[://]onedrive-share-demo[.]pages[.]dev/doc/view?id=9931" in r.iocs["urls"]
    assert not any("safelinks" in u for u in r.iocs["urls"])
    assert any("safelinks" in u for u in r.iocs["context_urls"])


def test_ioc_decoy_brand_link_is_context():
    r = analyze_file(_sample("4_netflix_pdf.eml"))
    assert "help[.]netflix[.]com" in r.iocs["context_domains"]
    assert "help[.]netflix[.]com" not in r.iocs.get("url_domains", [])
    assert any("update-billing-portal" in u for u in r.iocs["urls"])


def test_plain_eml_renamed_to_msg_is_read_as_email():
    # A .msg name on RFC 5322 text used to fail as "not an OLE2 file" and
    # score an empty message -- a BEC mail came back as mere spam.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "renamed.msg")
        with open(path, "wb") as fh, open(_sample("7_bec_wire.eml"), "rb") as src:
            fh.write(src.read())
        r = analyze_file(path)
    assert r.email.subject and r.email.from_addr, r.email.parse_errors
    assert r.verdict.value == analyze_file(_sample("7_bec_wire.eml")).verdict.value
    assert any("not an Outlook file" in e for e in r.email.parse_errors)


def test_headerless_input_is_flagged_as_not_an_email():
    pe = parse_email_bytes(b"Hi team,\nnotes from today's meeting below.\n")
    assert any("No email headers" in e for e in pe.parse_errors)
    assert not any("No email headers" in e for e in parse_email_bytes(build()).parse_errors)


def test_malformed_email_does_not_raise():
    for junk in (b"", b"not an email at all", b"From: \x00\xff\r\n\r\nbody",
                 b"Subject: x\r\nContent-Type: multipart/mixed; boundary=nope\r\n\r\n--nope"):
        r = analyze_bytes(junk)
        assert r is not None and isinstance(r.score, int)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
