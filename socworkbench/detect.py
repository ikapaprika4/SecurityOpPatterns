"""
Evidence recognition: which kit should read this file?

Content first, extension second -- analysts receive evidence renamed,
extensionless, or with the wrong extension (a .msg saved as .eml, a pcap
called capture.bin, logs as .txt). Every decision carries a human-readable
reason that the UI shows next to the case.
"""

from __future__ import annotations

import gzip
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Optional

PHISH, EVTX, NSM, TRAF = "phishkit", "evtxkit", "nsmkit", "trafkit"

KIT_LABELS = {PHISH: "Email", EVTX: "Windows events", NSM: "Network logs", TRAF: "Packet capture"}

_CFB = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_EMAIL_HEADER = re.compile(
    rb"^(?:Received|From|To|Subject|Date|Return-Path|Delivered-To|Message-I[Dd]|MIME-Version|"
    rb"Reply-To|X-[A-Za-z0-9-]+|Authentication-Results|DKIM-Signature|ARC-[A-Za-z-]+|"
    rb"Content-Type|Thread-Topic|Received-SPF)\s*:", re.M | re.I)
_TEXT_EXT = (".log", ".txt", ".csv", ".tsv", ".json", ".jsonl", ".ndjson")


@dataclass
class Sniff:
    kit: Optional[str]
    fmt: str
    reason: str


def _head(path: str, n: int = 65536) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def sniff(path: str) -> Sniff:
    name = os.path.basename(path)
    low = name.lower()
    try:
        head = _head(path)
    except OSError as exc:
        return Sniff(None, "unreadable", f"could not read the file: {exc}")
    if not head:
        return Sniff(None, "empty", "the file is empty")

    # ---- packet captures ------------------------------------------------
    from soccore.pcap import sniff_capture
    cap = sniff_capture(head)
    if cap == "pcap.gz":
        try:
            with gzip.open(path, "rb") as g:
                inner = sniff_capture(g.read(4))
        except OSError:
            inner = None
        if inner in ("pcap", "pcapng"):
            return Sniff(TRAF, f"{inner}.gz", f"gzip-compressed {inner} capture")
        cap = None
    elif cap:
        return Sniff(TRAF, cap, f"{cap} capture (magic bytes)")

    # ---- Windows event sources ------------------------------------------
    from evtxkit.parsers import sniff_format
    evt = sniff_format(head, name)
    if evt == "evtx":
        return Sniff(EVTX, "evtx", "Windows .evtx event log (ElfFile header)")
    if evt == "pshistory":
        return Sniff(EVTX, "pshistory", "PowerShell ConsoleHost history")
    if evt == "xml":
        return Sniff(EVTX, "xml", "Windows event XML (Event Viewer / wevtutil export)")

    # ---- Outlook .msg ----------------------------------------------------
    if head.startswith(_CFB):
        if low.endswith(".msg") or "__substg1.0_".encode("utf-16-le") in head \
                or _cfb_has_substg(path):
            return Sniff(PHISH, "msg", "Outlook .msg message (OLE2 container with MAPI properties)")
        return Sniff(None, "ole2", "an OLE2 Office document, not an email -- analyse the email "
                                   "that carried it, or detonate it in a sandbox")

    if evt == "jsonl":
        return Sniff(EVTX, "json", "Windows events as JSON (EventID / winlog fields)")

    # ---- email -----------------------------------------------------------
    if low.endswith(".mbox") or (head.startswith(b"From ") and b"\nFrom " in head):
        return Sniff(PHISH, "mbox", "mbox mailbox (several messages)")
    headers = _EMAIL_HEADER.findall(head[:16384])
    if len(headers) >= 3 and _looks_like_header_block(head):
        return Sniff(PHISH, "eml", "RFC 5322 email message")
    if low.endswith((".eml", ".msg")):
        # The name alone is not enough: scored as an email, text with no
        # headers at all would come back "spam" for the missing headers.
        if headers or _looks_like_header_block(head):
            return Sniff(PHISH, "eml", "email message (few standard headers)")
        return Sniff(None, "not-email", "named like an email, but contains no email headers")

    # ---- network logs ------------------------------------------------------
    if low.endswith(_TEXT_EXT) or _mostly_text(head):
        fmt = _nsm_grammar(path, head)
        if fmt:
            return Sniff(NSM, fmt, f"network log ({fmt} format)")
        if low.endswith((".csv", ".tsv")):
            return Sniff(NSM, "csv", "CSV export (treated as a network log)")

    if zipfile.is_zipfile(path):
        return Sniff(None, "zip", "zip archive")
    return Sniff(None, "unknown", "not a recognised evidence type (email, Windows event log, "
                                  "network log or packet capture)")


def _looks_like_header_block(head: bytes) -> bool:
    """The first non-empty line of an email is a header line, not prose."""
    first = head.lstrip(b"\xef\xbb\xbf\r\n ").split(b"\n", 1)[0]
    return bool(re.match(rb"^[A-Za-z][A-Za-z0-9-]*\s*:", first))


def _mostly_text(head: bytes) -> bool:
    sample = head[:8192]
    if not sample or b"\x00" in sample:
        return False
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample)
    return printable / len(sample) > 0.95


def _nsm_grammar(path: str, head: bytes) -> Optional[str]:
    """Score nsmkit's line parsers on a sample; return the winner if most
    lines parse."""
    from nsmkit.parsers import PARSERS, _DETECT_ORDER, event_from_dict
    text = head.decode("utf-8", "replace")
    lines = [ln for ln in text.splitlines()[:200] if ln.strip()]
    if len(lines) > 1 and not head.endswith(b"\n"):
        lines = lines[:-1]                      # the last line may be cut mid-way
    if not lines:
        return None
    if path.lower().endswith((".csv", ".tsv")):
        import csv
        import io
        try:
            rows = list(csv.DictReader(io.StringIO("\n".join(lines[:50]))))
        except csv.Error:
            rows = []
        ok = sum(1 for r in rows if event_from_dict({k: v for k, v in r.items() if k}))
        return "csv" if rows and ok / len(rows) >= 0.5 else None
    best, best_score = None, 0.0
    for name in _DETECT_ORDER:
        fn = PARSERS[name]
        hits = sum(1 for ln in lines if fn(ln) is not None)
        score = hits / len(lines)
        if score > best_score:
            best, best_score = name, score
    return best if best_score >= 0.5 else None


def _cfb_has_substg(path: str) -> bool:
    """Look for MAPI property stream names anywhere in the (small) file."""
    try:
        if os.path.getsize(path) > 64 * 1024 * 1024:
            return False
        with open(path, "rb") as fh:
            return "__substg1.0_".encode("utf-16-le") in fh.read()
    except OSError:
        return False
