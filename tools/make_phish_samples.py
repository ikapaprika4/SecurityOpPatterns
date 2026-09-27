#!/usr/bin/env python3
"""
Generate .eml samples modelled on the campaign patterns from the material, so
the toolkit can be exercised end to end without handling live malicious mail.

All domains use RFC 2606 / RFC 5737 reserved values where possible; nothing
here resolves or is live. Samples produced:

  1_paypal_shortener.eml      spoofed display name + URL shortener + branded HTML
  2_shipping_pixel.eml        generic authority sender + tracking pixel + link manipulation
  3_credential_harvest.eml    multi-brand layering + redirect chain + fake login portal
  4_netflix_pdf.eml           brand misspelling + PDF attachment with an embedded link
  5_apple_dot_bcc.eml         BCC delivery + empty body + .dot attachment
  6_dhl_xlsx.eml              branded HTML + macro-capable .xlsx with a remote link
  7_bec_wire.eml              no link, no attachment — pure BEC pretext
  8_legitimate.eml            a genuine notification that must NOT be flagged

Usage:  python tools/make_phish_samples.py [outdir]    (default: samples/phishkit)
"""

from __future__ import annotations

import base64
import os
import sys
import zipfile
import zlib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "samples", "phishkit")
OUT = DEFAULT_OUT


def received(frm_host, frm_ip, by_host, when):
    # EmailMessage refuses embedded newlines in header values, so keep the
    # Received header on one logical line; the parser folds either way.
    return (f"from {frm_host} ({frm_host} [{frm_ip}]) by {by_host} with ESMTP id ABC123 "
            f"for <victim@example.org>; {when}")


def write(name: str, msg: EmailMessage) -> None:
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(msg.as_bytes())
    print(f"  {path}")


def base_msg(subject, from_hdr, to_hdr="victim@example.org", date_off=0):
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = from_hdr
    if to_hdr:
        m["To"] = to_hdr
    m["Date"] = formatdate(1726000000 + date_off, localtime=False)
    m["Message-ID"] = make_msgid(domain="example.org")
    return m


def make_pdf_with_link(url: str) -> bytes:
    """A minimal but structurally valid PDF with a /URI link annotation."""
    content = b"BT /F1 18 Tf 60 700 Td (Update your payment account) Tj ET"
    stream = zlib.compress(content)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Annots [5 0 R] /Resources << /Font << /F1 6 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" /Filter /FlateDecode >>\nstream\n"
        + stream + b"\nendstream",
        b"<< /Type /Annot /Subtype /Link /Rect [60 690 400 720] /Border [0 0 0] "
        b"/A << /Type /Action /S /URI /URI (" + url.encode() + b") >> >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n"
            f"{xref}\n%%EOF").encode()
    return bytes(out)


def make_xlsx_with_link(url: str) -> bytes:
    """A minimal OOXML package with an external relationship target."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="rels" ContentType='
                   '"application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/></Types>')
        z.writestr("_rels/.rels",
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                   'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                   'Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0"?><workbook><sheets><sheet name="Invoice" sheetId="1" '
                   'r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/worksheets/_rels/sheet1.xml.rels",
                   f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                   f'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                   f'openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                   f'Target="{url}" TargetMode="External"/></Relationships>')
        z.writestr("xl/worksheets/sheet1.xml",
                   '<?xml version="1.0"?><worksheet><sheetData><row r="1"><c r="A1" t="str">'
                   '<v>Rechnung / Invoice - Mumbai, India - 发票</v></c></row></sheetData>'
                   '<hyperlinks><hyperlink ref="A1" r:id="rId1"/></hyperlinks></worksheet>')
        z.writestr("xl/vbaProject.bin", b"\x00\x01\x02VBA-PROJECT-PLACEHOLDER")
    return buf.getvalue()


def main(out_dir: str = DEFAULT_OUT) -> None:
    global OUT
    OUT = out_dir
    os.makedirs(OUT, exist_ok=True)

    # --------------------------------------------------------------------------
    # 1. PayPal receipt — spoofed display name, URL shortener, branded HTML
    # --------------------------------------------------------------------------
    m = base_msg("Receipt for your payment of $749.99 to Apple Store Gift Cards",
                 '"service@paypal.com" <gibberish@sultanbogor.example>',
                 "vgmpv_yh0hyvo@yahoo.example")
    m["Reply-To"] = "refund-desk@sultanbogor.example"
    m["Return-Path"] = "<bounce@sultanbogor.example>"
    m["Received"] = received("mail.sultanbogor.example", "198.51.100.77",
                             "mx.yahoo.example", formatdate(1726000000, localtime=False))
    m["Authentication-Results"] = ("mx.yahoo.example; spf=fail smtp.mailfrom=sultanbogor.example; "
                                   "dkim=none; dmarc=fail header.from=sultanbogor.example")
    m["Received-SPF"] = "fail (mx.yahoo.example: domain of sultanbogor.example does not designate 198.51.100.77 as permitted sender)"
    m.set_content(
        "You sent a payment of $749.99 USD to Apple Store Gift Cards.\n"
        "If you did not authorise this transaction, cancel the order within 24 hours.\n")
    m.add_alternative("""<html><body style="font-family:Arial">
    <img src="https://www.paypalobjects.example/logo.png" width="120" alt="PayPal">
    <h2>Receipt for your payment</h2>
    <p>Dear Customer,</p>
    <p>You sent a payment of <b>$749.99 USD</b> to Apple Store Gift Cards.</p>
    <p>If you did not authorise this transaction, you must act immediately.
    This order will be processed within 24 hours.</p>
    <p><a href="https://bit.ly/phishkit-demo-refund" style="background:#0070ba;color:#fff;
    padding:12px 24px;text-decoration:none;border-radius:4px">Cancel the order</a></p>
    <p>Questions? Call our billing department at +1-(888)-000-1234.</p>
    </body></html>""", subtype="html")
    write("1_paypal_shortener.eml", m)


    # --------------------------------------------------------------------------
    # 2. Shipping notification — tracking pixel + link manipulation
    # --------------------------------------------------------------------------
    m = base_msg("Your package 1Z999AA10123456784 could not be delivered",
                 '"Distribution Center" <contact@beginpro.example>', date_off=3600)
    m["Received"] = received("beginpro.example", "203.0.113.44", "mx.example.org",
                             formatdate(1726003600, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=softfail smtp.mailfrom=beginpro.example; "
                                   "dkim=permerror header.d=beginpro.example; dmarc=fail")
    m.set_content("Your parcel is on hold. Tracking number 1Z999AA10123456784.\n")
    m.add_alternative("""<html><body>
    <p>Dear Customer,</p>
    <p>Your package could not be delivered. Please confirm your address to avoid the
    parcel being returned. This is your final notice.</p>
    <p>Tracking number:
    <a href="http://198.51.100.203/track/redirect.php?id=8891">ups.example/track/1Z999AA10123456784</a></p>
    <img src="http://beginpro.example/Tracking.png?uid=vgmpv_yh0hyvo" width="1" height="1"
         style="display:none" alt="">
    </body></html>""", subtype="html")
    write("2_shipping_pixel.eml", m)


    # --------------------------------------------------------------------------
    # 3. Credential harvesting — brand layering + redirect chain
    # --------------------------------------------------------------------------
    m = base_msg("You have received a new fax document - Expires today",
                 '"Microsoft OneDrive" <no-reply@shared-docs-portal.example>', date_off=7200)
    m["Reply-To"] = "recovery@shared-docs-portal.example"
    m["Received"] = received("shared-docs-portal.example", "203.0.113.91", "mx.example.org",
                             formatdate(1726007200, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=neutral smtp.mailfrom=shared-docs-portal.example; "
                                   "dkim=none; dmarc=none")
    m.set_content("A fax document has been shared with you. The link expires today.\n")
    m.add_alternative("""<html><body style="font-family:Segoe UI">
    <img src="https://res.example/microsoft-logo.png" width="108" alt="Microsoft">
    <h3>A document has been shared with you via OneDrive</h3>
    <p>Dear User,</p>
    <p>You have received a new fax document (2 pages, Adobe PDF).
    <b>This link expires today</b> — download it before it is removed.</p>
    <p><a href="https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fonedrive-share-demo.pages.dev%2Fdoc%2Fview%3Fid%3D9931&amp;data=05">Download Document Here</a></p>
    <p>To view the document you will be asked to sign in to continue and verify your
    identity with your email provider.</p>
    <p style="font-size:10px;color:#888">Powered by Adobe Document Cloud</p>
    </body></html>""", subtype="html")
    write("3_credential_harvest.eml", m)


    # --------------------------------------------------------------------------
    # 4. Netflix — brand misspelling + PDF attachment carrying the link
    # --------------------------------------------------------------------------
    m = base_msg("Your Netllx ID has been suspended - Action Required",
                 '"Netllx billing" <no-reply@billing-secure-netfIix.example>', date_off=10800)
    m["Received"] = received("billing-secure-netfIix.example", "203.0.113.132",
                             "mx.example.org", formatdate(1726010800, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=fail smtp.mailfrom=billing-secure-netfIix.example; "
                                   "dkim=fail header.d=billing-secure-netfIix.example; dmarc=fail p=reject")
    m.set_content("We were unable to process your payment. Update your billing information.\n")
    m.add_alternative("""<html><body style="background:#000;color:#fff;font-family:Helvetica">
    <h1 style="color:#e50914">NETLLX</h1>
    <p>Dear Customer,</p>
    <p>We're having some trouble with your current billing information.
    Your membership has been <b>suspended</b>. To avoid termination of your account,
    please update your payment details within 24 hours.</p>
    <p>Please open the attached document to update your account.</p>
    <p>Need help? Visit <a href="https://help.netflix.com">help.netflix.com</a>
    or call 1.844.505.2993.</p>
    </body></html>""", subtype="html")
    pdf = make_pdf_with_link("http://update-billing-portal.example/netflix/login.php?ref=8823")
    m.add_attachment(pdf, maintype="application", subtype="pdf",
                     filename="Netllx_Billing_Update.pdf")
    write("4_netflix_pdf.eml", m)


    # --------------------------------------------------------------------------
    # 5. Apple — BCC delivery, empty body, .dot attachment
    # --------------------------------------------------------------------------
    m = EmailMessage()
    m["Subject"] = "Action Required: Unauthorized purchase of $129.00 on your acount"
    m["From"] = '"Apple Support" <suport@icloud-verify-appleid.example>'
    m["Date"] = formatdate(1726014400, localtime=False)
    m["Message-ID"] = make_msgid(domain="example.org")
    m["Received"] = received("icloud-verify-appleid.example", "203.0.113.201",
                             "mx.example.org", formatdate(1726014400, localtime=False))
    m["Delivered-To"] = "victim@example.org"
    m["Authentication-Results"] = ("mx.example.org; spf=fail smtp.mailfrom=icloud-verify-appleid.example; "
                                   "dkim=none; dmarc=fail")
    m.set_content(" ")
    dot_body = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
                + b"Microsoft Word Template - see attached receipt"
                + b"http://apps-ios-appleid-verify.example/secure/login/session/"
                  b"a8f7d6e5c4b3a2910f8e7d6c5b4a39281706f5e4d3c2b1a0/index.php")
    m.add_attachment(dot_body, maintype="application", subtype="msword",
                     filename="Receipt_Apple_Store.dot")
    write("5_apple_dot_bcc.eml", m)


    # --------------------------------------------------------------------------
    # 6. DHL — branded HTML + macro-capable spreadsheet with a remote link
    # --------------------------------------------------------------------------
    m = base_msg("DHL Express - Shipment Document AWB 4592817736",
                 '"DHL Express" <noreply@dhl-express-tracking.example>', date_off=18000)
    m["Received"] = received("dhl-express-tracking.example", "203.0.113.55",
                             "mx.example.org", formatdate(1726018000, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=softfail smtp.mailfrom=dhl-express-tracking.example; "
                                   "dkim=none; dmarc=fail")
    m.set_content("Please find attached the shipping document for AWB 4592817736.\n")
    m.add_alternative("""<html><body style="font-family:Arial">
    <div style="background:#ffcc00;padding:12px"><span style="color:#d40511;
    font-weight:bold;font-size:22px">DHL</span> Express</div>
    <p>Dear Customer,</p>
    <p>Your shipment is ready for dispatch. Please review the attached invoice and
    confirm the delivery address.</p>
    <p>AWB: 4592817736</p>
    </body></html>""", subtype="html")
    xlsx = make_xlsx_with_link("http://cdn-invoice-dhl.example/download/regasms.exe")
    m.add_attachment(xlsx, maintype="application",
                     subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     filename="DHL_Invoice_4592817736.xlsm")
    write("6_dhl_xlsx.eml", m)


    # --------------------------------------------------------------------------
    # 7. BEC — no link, no attachment, pure pretext
    # --------------------------------------------------------------------------
    # Gmail usernames can't contain '_', so these fictional addresses can
    # never belong to a real mailbox.
    m = base_msg("Are you at your desk?",
                 '"Margaret Ellis (CEO)" <m_ellis.ceo@gmail.com>', date_off=21600)
    m["Reply-To"] = "m_ellis.finance@gmail.com"
    m["Received"] = received("mail-sor-f41.google.example", "198.51.100.41",
                             "mx.example.org", formatdate(1726021600, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=pass smtp.mailfrom=gmail.com; "
                                   "dkim=pass header.d=gmail.com; dmarc=pass")
    m.set_content(
        "Hi,\n\n"
        "Are you available? I need you to process an urgent payment for a vendor today. "
        "The banking details have changed since the last invoice — I'll send the new "
        "account details shortly.\n\n"
        "Please keep this confidential until the deal is announced. I'm in a meeting "
        "for the next two hours so email only.\n\n"
        "Margaret\nSent from my iPhone\n")
    write("7_bec_wire.eml", m)


    # --------------------------------------------------------------------------
    # 8. Legitimate notification — the control sample
    # --------------------------------------------------------------------------
    m = base_msg("Your monthly statement is ready",
                 '"GitHub" <noreply@github.com>', date_off=25200)
    m["Return-Path"] = "<noreply@github.com>"
    m["Received"] = received("out-1.smtp.github.com", "192.30.252.200",
                             "mx.example.org", formatdate(1726025200, localtime=False))
    m["Authentication-Results"] = ("mx.example.org; spf=pass smtp.mailfrom=github.com; "
                                   "dkim=pass header.d=github.com; dmarc=pass p=reject")
    m.set_content("Hi Alex,\n\nYour monthly statement for September is available in your "
                  "account settings.\n\nThanks,\nThe GitHub team\n")
    m.add_alternative("""<html><body style="font-family:-apple-system,sans-serif">
    <p>Hi Alex,</p>
    <p>Your monthly statement for September is now available.</p>
    <p><a href="https://github.com/settings/billing">View your statement</a></p>
    <p>Thanks,<br>The GitHub team</p>
    <p style="font-size:11px;color:#888">You are receiving this because you have a
    GitHub account. <a href="https://github.com/settings/notifications">Manage preferences</a></p>
    </body></html>""", subtype="html")
    write("8_legitimate.eml", m)

    # --------------------------------------------------------------------------
    # 9. The same kind of lure delivered as an Outlook .msg -- what a user's
    #    "Report phishing" button or a drag out of Outlook produces.
    # --------------------------------------------------------------------------
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from phishkit.msg import build_msg
    hdrs = "\r\n".join([
        "Received: from mail.micros0ft-support.example (mail.micros0ft-support.example "
        "[203.0.113.150]) by mx.example.org with ESMTP id MSG1; "
        + formatdate(1726030000, localtime=False),
        "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=micros0ft-support.example; "
        "dkim=none; dmarc=fail header.from=micros0ft-support.example",
        'From: "Microsoft 365 Admin" <admin@micros0ft-support.example>',
        "To: victim@example.org",
        "Subject: Your password expires today - keep your current password",
        "Date: " + formatdate(1726030000, localtime=False),
        "Message-ID: <msg-sample-9@micros0ft-support.example>",
        "MIME-Version: 1.0",
    ])
    html = ("<html><body><p>Dear User,</p><p>Your Microsoft 365 password expires today. "
            "To keep your current password, verify your account immediately.</p>"
            '<p><a href="https://login.micros0ft-support.example/owa/auth/verify.php">'
            "Keep current password</a></p></body></html>")
    msg_bytes = build_msg(hdrs, "Your password expires today - keep your current password",
                          "Your Microsoft 365 password expires today. Verify your account "
                          "immediately to keep your current password.", html=html,
                          attachments=[("Password_Policy.pdf.exe", b"MZ\x90\x00" + b"\x00" * 60)])
    with open(os.path.join(OUT, "9_m365_expiry.msg"), "wb") as fh:
        fh.write(msg_bytes)
    print(f"  {os.path.join(OUT, '9_m365_expiry.msg')}")

    # --------------------------------------------------------------------------
    # 10. An mbox holding a small campaign: every message becomes its own case.
    # --------------------------------------------------------------------------
    import mailbox
    box_path = os.path.join(OUT, "10_campaign.mbox")
    if os.path.exists(box_path):
        os.remove(box_path)
    box = mailbox.mbox(box_path)
    for i, name in enumerate(("recipient-a", "recipient-b", "recipient-c")):
        m = base_msg("Shared document: Q3 bonus schedule",
                     '"HR Department" <hr@payroll-portal-docs.example>',
                     f"{name}@example.org", date_off=40000 + i * 60)
        m["Received"] = received("payroll-portal-docs.example", "203.0.113.77", "mx.example.org",
                                 formatdate(1726040000 + i * 60, localtime=False))
        m["Authentication-Results"] = ("mx.example.org; spf=softfail smtp.mailfrom="
                                       "payroll-portal-docs.example; dkim=none; dmarc=fail")
        m.set_content("Please sign in to view the Q3 bonus schedule before it expires today.\n"
                      "https://payroll-portal-docs.example/sign-in/verify?u=" + name + "\n")
        box.add(m)
    box.flush()
    box.close()
    print(f"  {box_path}")

    print(f"\n10 samples written to {OUT}/")
    print(f"Run:  python -m phishkit.cli analyze {OUT} -v")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT)
