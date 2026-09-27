"""
Email parsing: .eml / raw MIME / .msg into a ParsedEmail.

Built on the stdlib `email` package so there is no mandatory dependency.
Everything is defensive -- a malformed or deliberately malformed message must
produce a partial result with a note, never an exception. Attackers break MIME
structure on purpose to defeat parsers.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import os
import re
import struct
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from typing import Optional

from .models import (Attachment, AuthenticationResults, AuthResult, EmailAddress,
                     ParsedEmail, ReceivedHop)

# --------------------------------------------------------------------------
# Header decoding
# --------------------------------------------------------------------------

def decode_mime_header(value: Optional[str]) -> str:
    """Decode RFC 2047 encoded-words (=?utf-8?B?...?=) safely."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        try:
            return "".join(
                (part.decode(enc or "utf-8", "replace") if isinstance(part, bytes) else part)
                for part, enc in decode_header(value))
        except Exception:
            return str(value)


def parse_address(value: Optional[str]) -> Optional[EmailAddress]:
    if not value:
        return None
    decoded = decode_mime_header(value)
    pairs = getaddresses([decoded])
    if not pairs:
        return EmailAddress(raw=decoded, display_name="", address=decoded.strip())
    name, addr = pairs[0]
    return EmailAddress(raw=decoded, display_name=(name or "").strip().strip('"'),
                        address=(addr or "").strip().lower())


def parse_address_list(value: Optional[str]) -> list[EmailAddress]:
    if not value:
        return []
    decoded = decode_mime_header(value)
    out = []
    for name, addr in getaddresses([decoded]):
        if addr or name:
            out.append(EmailAddress(raw=decoded, display_name=(name or "").strip().strip('"'),
                                    address=(addr or "").strip().lower()))
    return out


# --------------------------------------------------------------------------
# Received chain
# --------------------------------------------------------------------------

_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_RECV_FROM = re.compile(r"from\s+(?P<host>[^\s;()]+)", re.I)
_RECV_BY = re.compile(r"\bby\s+(?P<host>[^\s;()]+)", re.I)
_RECV_WITH = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9/\-]+)", re.I)
_RECV_IP = re.compile(rf"[\[(](?P<ip>{_IPV4}|[0-9a-fA-F:]{{6,}})[\])]")
_ANY_IPV4 = re.compile(_IPV4)

# Ranges that are never the true originator of an inbound internet email.
_NON_ROUTABLE = re.compile(
    r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)")


def parse_received(raw: str, index: int) -> ReceivedHop:
    """Parse one Received header into its from/by/with/timestamp parts."""
    hop = ReceivedHop(index=index, raw=" ".join(raw.split()))

    m = _RECV_FROM.search(raw)
    if m:
        hop.from_host = m.group("host").strip("<>[](),;")
    m = _RECV_BY.search(raw)
    if m:
        hop.by_host = m.group("host").strip("<>[](),;")
    m = _RECV_WITH.search(raw)
    if m:
        hop.with_protocol = m.group("proto")

    # Prefer a bracketed IP (that is the literal the server recorded); fall back
    # to the first IPv4 in the "from" clause only.
    m = _RECV_IP.search(raw)
    if m:
        hop.from_ip = m.group("ip")
    else:
        head = raw.split(" by ")[0] if " by " in raw else raw
        m2 = _ANY_IPV4.search(head)
        if m2:
            hop.from_ip = m2.group(0)

    if ";" in raw:
        try:
            hop.timestamp = parsedate_to_datetime(raw.rsplit(";", 1)[1].strip())
        except Exception:
            hop.timestamp = None
    return hop


def originating_ip(hops: list[ReceivedHop]) -> str:
    """
    The source IP of the message.

    Received headers are PREPENDED, so the last one in the list is the first
    hop chronologically -- the originating server. Walk from oldest to newest
    and take the first public IP, because internal relays add RFC1918 hops that
    are not the origin.
    """
    for hop in reversed(hops):
        ip = hop.from_ip
        if ip and ":" not in ip and not _NON_ROUTABLE.match(ip):
            return ip
    for hop in reversed(hops):
        if hop.from_ip:
            return hop.from_ip
    return ""


def compute_hop_delays(hops: list[ReceivedHop]) -> None:
    """Seconds spent at each hop. A large gap can indicate a queue or a relay."""
    ordered = [h for h in reversed(hops) if h.timestamp]
    for i in range(1, len(ordered)):
        prev, cur = ordered[i - 1], ordered[i]
        try:
            cur.delay_seconds = (cur.timestamp - prev.timestamp).total_seconds()
        except Exception:
            cur.delay_seconds = None


# --------------------------------------------------------------------------
# Authentication-Results
# --------------------------------------------------------------------------

_AUTH_METHOD = re.compile(
    r"\b(?P<method>spf|dkim|dmarc)\s*=\s*(?P<result>pass|fail|softfail|neutral|none|"
    r"temperror|permerror|policy|bestguesspass)", re.I)
# The local part is optional but, when present, must be followed by '@' -- without
# the non-greedy anchor the local-part class eats into the domain and yields a
# truncated domain like "r.example" from "sultanbogor.example".
_AUTH_DOMAIN = re.compile(r"\b(?P<key>header\.d|header\.from|smtp\.mailfrom|envelope-from)"
                          r"\s*=\s*[<]?(?:(?P<local>[A-Za-z0-9._%+\-]+)@)?"
                          r"(?P<domain>[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})", re.I)
_DMARC_POLICY = re.compile(r"\b(?:p|dmarc)\s*=\s*(none|quarantine|reject)\b", re.I)


def parse_authentication_results(headers: list[tuple[str, str]]) -> AuthenticationResults:
    """
    Read the receiving MTA's verdicts out of Authentication-Results,
    Received-SPF, ARC-Authentication-Results and vendor X- headers.

    These are assertions made by the *receiving* infrastructure. Trust them only
    as far as you trust that infrastructure -- an attacker can forge an
    Authentication-Results header in a message they compose, so what matters is
    the one added by your own boundary MTA (usually the topmost).
    """
    ar = AuthenticationResults()
    relevant = ("authentication-results", "received-spf", "arc-authentication-results",
                "x-forefront-antispam-report", "authentication-results-original",
                "x-ms-exchange-authentication-results")

    for key, value in headers:
        if key.lower() not in relevant:
            continue
        ar.raw_headers.append(f"{key}: {' '.join(value.split())}")
        low = value.lower()

        if key.lower() == "received-spf":
            m = re.match(r"\s*(pass|fail|softfail|neutral|none|temperror|permerror)", low)
            if m and ar.spf is AuthResult.UNKNOWN:
                ar.spf = AuthResult(m.group(1))

        for m in _AUTH_METHOD.finditer(value):
            method = m.group("method").lower()
            raw_res = m.group("result").lower()
            res = AuthResult.PASS if raw_res == "bestguesspass" else AuthResult(raw_res)
            # First (topmost) assertion wins -- that is our own boundary MTA.
            if method == "spf" and ar.spf is AuthResult.UNKNOWN:
                ar.spf = res
            elif method == "dkim" and ar.dkim is AuthResult.UNKNOWN:
                ar.dkim = res
            elif method == "dmarc" and ar.dmarc is AuthResult.UNKNOWN:
                ar.dmarc = res

        # Attribute the domain by the keyword captured in the SAME match; a
        # look-behind window picks up the previous clause's keyword and swaps
        # the SPF and DKIM domains.
        for m in _AUTH_DOMAIN.finditer(value):
            key = m.group("key").lower()
            dom = m.group("domain").lower()
            if key == "header.d" and not ar.dkim_domain:
                ar.dkim_domain = dom
            elif key in ("smtp.mailfrom", "envelope-from") and not ar.spf_domain:
                ar.spf_domain = dom

        m = _DMARC_POLICY.search(value)
        if m and not ar.dmarc_policy:
            ar.dmarc_policy = m.group(1).lower()

    if not ar.raw_headers:
        ar.notes.append("No Authentication-Results header present -- the receiving MTA "
                        "either did not evaluate SPF/DKIM/DMARC or stripped its verdict.")
    return ar


# --------------------------------------------------------------------------
# Body and attachments
# --------------------------------------------------------------------------

_DANGEROUS_EXT = {
    # direct execution
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "gadget", "application",
    "bat", "cmd", "vb", "vbs", "vbe", "js", "jse", "ws", "wsf", "wsc", "wsh",
    "ps1", "ps1xml", "ps2", "psc1", "msh", "msh1", "scf", "lnk", "inf", "reg",
    "hta", "jar", "py", "sh", "apk", "iso", "img", "vhd", "diagcab", "appref-ms",
    "url", "settingcontent-ms", "library-ms", "chm", "dll", "ocx", "cpl",
}
_MACRO_EXT = {
    # legacy Office (macros allowed) and explicit macro-enabled formats
    "doc", "dot", "xls", "xlt", "xla", "ppt", "pot", "pps",
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm",
    "sldm", "mht", "mhtml",
}
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "bz2", "cab", "ace", "arj", "lzh", "xz"}


def _ext_of(filename: str) -> str:
    return filename.rsplit(".", 1)[1].lower().strip() if "." in filename else ""


def _has_double_extension(filename: str) -> bool:
    """`invoice.pdf.exe` -- a benign-looking extension followed by a real one."""
    parts = [p.lower() for p in filename.split(".") if p]
    if len(parts) < 3:
        return False
    benign = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
              "jpeg", "png", "gif", "csv", "rtf", "htm", "html", "zip", "xml"}
    return parts[-2] in benign and parts[-1] in (_DANGEROUS_EXT | {"zip", "rar"})


def _extract_pdf_urls(data: bytes) -> list[str]:
    """
    Pull URIs out of a PDF without a PDF library.

    Covers `/URI (http://...)` link annotations -- the mechanism the Netflix-style
    sample uses to hide the destination inside an attachment -- plus any
    plaintext URLs in uncompressed streams.
    """
    urls: list[str] = []
    try:
        for m in re.finditer(rb"/URI\s*\(([^)]{4,2000})\)", data):
            urls.append(m.group(1).decode("latin-1", "replace").strip())
        for m in re.finditer(rb"https?://[^\s<>\"'()\\\]]{4,500}", data):
            urls.append(m.group(0).decode("latin-1", "replace"))
        # Inflate FlateDecode streams so compressed link annotations are seen too.
        import zlib
        for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
            try:
                blob = zlib.decompress(m.group(1))
            except Exception:
                continue
            for m2 in re.finditer(rb"https?://[^\s<>\"'()\\\]]{4,500}", blob):
                urls.append(m2.group(0).decode("latin-1", "replace"))
            for m2 in re.finditer(rb"/URI\s*\(([^)]{4,2000})\)", blob):
                urls.append(m2.group(1).decode("latin-1", "replace").strip())
    except Exception:
        pass
    seen, out = set(), []
    for u in urls:
        u = u.strip().rstrip(").,;'\"")
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _extract_ooxml_urls(data: bytes) -> list[str]:
    """
    Read external relationship targets out of an OOXML file (.docx/.xlsx/.pptx).

    Remote links live in `word/_rels/*.rels` as `TargetMode="External"`. This is
    how a document reaches out on open (remote template injection) and how a
    click-through link is stored.
    """
    urls: list[str] = []
    try:
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            for name in names:
                if name.endswith(".rels") or name.endswith(".xml"):
                    try:
                        blob = z.read(name)
                    except Exception:
                        continue
                    for m in re.finditer(rb'Target="(https?://[^"]{4,600})"', blob):
                        urls.append(m.group(1).decode("utf-8", "replace"))
                    for m in re.finditer(rb"https?://[^\s<>\"']{4,600}", blob):
                        urls.append(m.group(0).decode("utf-8", "replace"))
            if any(n.startswith("word/vbaProject") or n.endswith("vbaProject.bin") for n in names):
                urls.append("__VBA_MACRO_PRESENT__")
    except Exception:
        pass
    # XML namespace declarations are not links -- every OOXML file contains
    # dozens of them, and they would swamp the real external target.
    ns_noise = ("schemas.openxmlformats.org", "schemas.microsoft.com",
                "www.w3.org", "purl.org", "schemas.xmlsoap.org",
                "docs.oasis-open.org", "schemas.opengis.net")
    seen, out = set(), []
    for u in urls:
        u = u.strip()
        if not u or u in seen:
            continue
        if u != "__VBA_MACRO_PRESENT__" and any(n in u for n in ns_noise):
            continue
        seen.add(u)
        out.append(u)
    return out


def build_attachment(part) -> Optional[Attachment]:
    filename = part.get_filename()
    disposition = (part.get_content_disposition() or "")
    ctype = part.get_content_type()

    if not filename and disposition != "attachment":
        return None
    if not filename:
        filename = f"unnamed.{(ctype.split('/')[-1] or 'bin')}"
    filename = decode_mime_header(filename)

    try:
        data = part.get_payload(decode=True) or b""
    except Exception:
        data = b""

    att = Attachment(
        filename=filename,
        content_type=ctype,
        content_disposition=disposition,
        transfer_encoding=part.get("Content-Transfer-Encoding", "") or "",
        data=data,
        extension=_ext_of(filename),
    )
    att.compute_hashes()
    att.is_dangerous = att.extension in _DANGEROUS_EXT
    att.has_double_extension = _has_double_extension(filename)
    att.macro_capable = att.extension in _MACRO_EXT

    if att.extension == "pdf" or data[:5] == b"%PDF-":
        att.embedded_urls = _extract_pdf_urls(data)
    elif data[:2] == b"PK" and att.extension in {
            "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm"}:
        found = _extract_ooxml_urls(data)
        if "__VBA_MACRO_PRESENT__" in found:
            att.macro_capable = True
            att.notes.append("vbaProject.bin present -- the document contains VBA macros")
            found = [u for u in found if u != "__VBA_MACRO_PRESENT__"]
        att.embedded_urls = found
    elif att.extension in _ARCHIVE_EXT:
        att.notes.append("Archive attachment -- contents are opaque to mail filters; "
                         "detonate in a sandbox")

    # Magic-byte vs. extension disagreement: a renamed executable.
    if data[:2] == b"MZ" and att.extension not in {"exe", "dll", "scr", "sys", "com", "ocx"}:
        att.is_dangerous = True
        att.notes.append(f"File starts with the MZ (PE executable) magic bytes but is named "
                         f"'.{att.extension}' -- the extension is a disguise")
    if data[:4] == b"%PDF" and att.extension not in {"pdf"}:
        att.notes.append("PDF magic bytes with a non-PDF extension")

    return att


# --------------------------------------------------------------------------
# Top-level parse
# --------------------------------------------------------------------------

def parse_email_bytes(raw: bytes, source_path: str = "") -> ParsedEmail:
    pe = ParsedEmail(source_path=source_path, raw=raw,
                     file_sha256=hashlib.sha256(raw).hexdigest())
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        pe.parse_errors.append(f"MIME parse failed: {exc}")
        return pe

    pe.all_headers = [(k, str(v)) for k, v in msg.items()]
    if not pe.all_headers:
        pe.parse_errors.append("No email headers found -- this does not look like an email "
                               "message, so the verdict below is not meaningful")

    pe.from_addr = parse_address(msg.get("From"))
    pe.reply_to = parse_address(msg.get("Reply-To"))
    pe.return_path = parse_address(msg.get("Return-Path"))
    pe.sender = parse_address(msg.get("Sender"))
    pe.to = parse_address_list(msg.get("To"))
    pe.cc = parse_address_list(msg.get("Cc"))
    pe.bcc = parse_address_list(msg.get("Bcc"))
    pe.subject = decode_mime_header(msg.get("Subject"))
    pe.message_id = (msg.get("Message-ID") or "").strip()

    try:
        if msg.get("Date"):
            pe.date = parsedate_to_datetime(msg.get("Date"))
    except Exception:
        pe.parse_errors.append("Unparseable Date header")

    for hdr in ("X-Originating-IP", "X-Original-IP", "X-Sender-IP", "X-Source-IP"):
        val = msg.get(hdr)
        if val:
            m = _ANY_IPV4.search(str(val))
            pe.x_originating_ip = m.group(0) if m else str(val).strip("[] ")
            break

    received = pe.headers_all("Received")
    pe.received_chain = [parse_received(r, i) for i, r in enumerate(received)]
    compute_hop_delays(pe.received_chain)
    pe.originating_ip = pe.x_originating_ip or originating_ip(pe.received_chain)

    # Body + attachments
    _walk(msg, pe)

    # BCC delivery: no To/Cc header at all, or an envelope recipient that appears
    # in neither. The Apple-support sample uses this to hide the recipient list.
    if not pe.to and not pe.cc:
        pe.is_bcc_delivery = True
    else:
        env = msg.get("Delivered-To") or msg.get("X-Envelope-To") or ""
        env = env.strip().lower().strip("<>")
        if env and env not in {a.address for a in pe.to + pe.cc}:
            pe.is_bcc_delivery = True

    pe.auth = parse_authentication_results(pe.all_headers)
    return pe


def _walk(msg, pe: ParsedEmail) -> None:
    """Collect text/html bodies and attachments from every MIME part."""
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition() or ""
        filename = part.get_filename()

        if filename or disposition == "attachment":
            att = build_attachment(part)
            if att:
                pe.attachments.append(att)
            continue

        try:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, "replace") if payload else ""
        except Exception:
            text = ""
            pe.parse_errors.append(f"Could not decode part {ctype}")

        if ctype == "text/plain":
            pe.body_text += text
        elif ctype == "text/html":
            pe.body_html += text
        elif ctype.startswith("message/"):
            pe.body_text += text


def parse_email_file(path: str) -> ParsedEmail:
    """Parse .eml / raw MIME / Outlook .msg (recognised by content, so a
    renamed .msg still works). .mbox files hold many messages: use
    parse_mailbox for those."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":          # OLE2: Outlook .msg
        return _parse_msg_file(path, data)
    pe = parse_email_bytes(data, source_path=path)
    if path.lower().endswith(".msg"):
        # A plain-text message saved as .msg (a common rename) -- read it as
        # what it is instead of failing as a broken Outlook file.
        pe.parse_errors.append("Named .msg but not an Outlook file; read as a plain RFC 5322 message")
    return pe


def is_mailbox(path: str) -> bool:
    """An mbox file: many messages, each introduced by a 'From ' line."""
    if path.lower().endswith(".mbox"):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return head.startswith(b"From ") and b"\nFrom " in head[5:] or (
        head.startswith(b"From ") and path.lower().endswith((".mbx", ".txt")))


def parse_mailbox(path: str) -> list[ParsedEmail]:
    """Every message in an mbox, each with source_path 'file.mbox#N'."""
    import mailbox
    out: list[ParsedEmail] = []
    box = mailbox.mbox(path, create=False)
    try:
        for i, msg in enumerate(box, start=1):
            try:
                raw = msg.as_bytes()
            except Exception as exc:  # noqa: BLE001
                pe = ParsedEmail(source_path=f"{path}#{i}")
                pe.parse_errors.append(f"mbox message {i} could not be read: {exc}")
                out.append(pe)
                continue
            out.append(parse_email_bytes(raw, source_path=f"{path}#{i}"))
    finally:
        box.close()
    return out


def _parse_msg_file(path: str, data: bytes | None = None) -> ParsedEmail:
    """Outlook .msg: rebuilt natively (see phishkit.msg) into RFC 5322 --
    original transport headers, bodies and attachments -- and parsed like
    any .eml. The optional extract_msg package is only a fallback."""
    from .msg import MsgError, msg_to_eml
    if data is None:
        with open(path, "rb") as fh:
            data = fh.read()
    try:
        eml, notes = msg_to_eml(data)
        pe = parse_email_bytes(eml, source_path=path)
        pe.raw = data
        pe.file_sha256 = hashlib.sha256(data).hexdigest()
        pe.parse_errors.extend(notes)
        return pe
    except (MsgError, struct.error, IndexError, ValueError) as exc:
        native_error = exc
    try:
        import extract_msg  # type: ignore
    except ImportError:
        pe = ParsedEmail(source_path=path, raw=data,
                         file_sha256=hashlib.sha256(data).hexdigest())
        pe.parse_errors.append(f"Could not read the Outlook .msg file: {native_error}")
        return pe
    m = extract_msg.Message(path)
    try:
        eml = m.asEmailMessage().as_bytes()          # newer extract_msg
    except Exception:
        parts = [f"From: {m.sender or ''}", f"To: {m.to or ''}", f"Cc: {m.cc or ''}",
                 f"Subject: {m.subject or ''}", f"Date: {m.date or ''}",
                 (m.header.as_string() if getattr(m, "header", None) else ""), "",
                 m.body or ""]
        eml = "\n".join(str(p) for p in parts).encode("utf-8", "replace")
    pe = parse_email_bytes(eml, source_path=path)
    try:
        for a in m.attachments:
            data = a.data if isinstance(a.data, bytes) else bytes(a.data or b"")
            att = Attachment(filename=a.longFilename or a.shortFilename or "attachment",
                             data=data, extension=_ext_of(a.longFilename or ""))
            att.compute_hashes()
            att.is_dangerous = att.extension in _DANGEROUS_EXT
            att.macro_capable = att.extension in _MACRO_EXT
            att.has_double_extension = _has_double_extension(att.filename)
            pe.attachments.append(att)
    except Exception as exc:
        pe.parse_errors.append(f"Attachment extraction from .msg failed: {exc}")
    return pe


def parse_directory(path: str) -> list[ParsedEmail]:
    out = []
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            if name.lower().endswith((".eml", ".msg", ".mbox", ".txt")):
                full = os.path.join(root, name)
                try:
                    if is_mailbox(full):
                        out.extend(parse_mailbox(full))
                    else:
                        out.append(parse_email_file(full))
                except Exception as exc:
                    pe = ParsedEmail(source_path=full)
                    pe.parse_errors.append(str(exc))
                    out.append(pe)
    return out
