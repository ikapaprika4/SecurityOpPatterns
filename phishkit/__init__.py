"""
phishkit — email and phishing analysis toolkit.

Pipeline:  parse -> extract artifacts -> detect -> score -> verdict -> IOCs

    from phishkit import analyze_file
    r = analyze_file("suspicious.eml")
    print(r.verdict, r.score)
    for f in r.findings:
        print(f.rule_id, f.title)
"""

from __future__ import annotations

from typing import Sequence

from .detectors import run_all, score_to_verdict
from .iocs import collect_iocs, defang, refang
from .models import (AnalysisResult, Attachment, AuthResult, EmailAddress,
                     ExtractedURL, Finding, ParsedEmail, PhishType, Verdict)
from .parser import (is_mailbox, parse_directory, parse_email_bytes, parse_email_file,
                     parse_mailbox)
from .social import classify_phish_type, targets_executive
from .urls import extract_urls

__version__ = "1.0.0"

__all__ = [
    "analyze", "analyze_file", "analyze_bytes", "analyze_directory",
    "AnalysisResult", "ParsedEmail", "Finding", "Verdict", "PhishType",
    "AuthResult", "EmailAddress", "ExtractedURL", "Attachment",
    "parse_email_file", "parse_email_bytes", "parse_directory",
    "collect_iocs", "defang", "refang", "__version__",
]


def analyze(email: ParsedEmail) -> AnalysisResult:
    """Run the full analysis over an already-parsed message."""
    # URLs come from the body AND from inside attachments -- an attachment is a
    # place to hide a link from body-only scanners.
    embedded = [u for a in email.attachments for u in a.embedded_urls]
    email.urls = extract_urls(email.body_text, email.body_html, extra=embedded)

    findings = run_all(email)
    score = max(0, sum(f.score for f in findings))

    weaponised = any(
        a.is_dangerous or a.has_double_extension or a.macro_capable
        for a in email.attachments)
    verdict = score_to_verdict(score, has_malicious_attachment=weaponised)

    body = (email.body_text or "") + "\n" + (email.body_html or "")[:20000]
    exec_hit = bool(targets_executive(f"{email.subject}\n{body[:3000]}"))
    types = classify_phish_type(
        email.subject or "", body,
        has_attachment=bool(email.attachments),
        has_url=bool(email.urls),
        recipient_count=len(email.to) + len(email.cc),
        exec_targeted=exec_hit,
    )

    result = AnalysisResult(
        email=email,
        findings=findings,
        score=score,
        verdict=verdict,
        # A benign message has no vector to classify -- the language classifier
        # always returns something, so suppress it rather than labelling clean
        # mail "spam" on the strength of the word "invoice".
        phish_types=([] if verdict is Verdict.BENIGN else
                     [PhishType(t) for t in types if t in PhishType._value2member_map_]),
    )
    result.iocs = collect_iocs(result)
    return result


def analyze_file(path: str) -> AnalysisResult:
    return analyze(parse_email_file(path))


def analyze_bytes(raw: bytes, source_path: str = "") -> AnalysisResult:
    return analyze(parse_email_bytes(raw, source_path=source_path))


def analyze_directory(path: str) -> list[AnalysisResult]:
    return [analyze(pe) for pe in parse_directory(path)]


def analyze_mailbox(path: str) -> list[AnalysisResult]:
    """Every message of an mbox file, each as its own case."""
    return [analyze(pe) for pe in parse_mailbox(path)]


def analyze_paths(paths: Sequence[str]) -> list[AnalysisResult]:
    """Accept a mix of files, mbox files and directories."""
    import os
    out: list[AnalysisResult] = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(analyze_directory(p))
        elif is_mailbox(p):
            out.extend(analyze_mailbox(p))
        else:
            out.append(analyze_file(p))
    return out
