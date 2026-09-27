"""Collection / Credential Access / Exfiltration staging detection
(Windows Threat Detection 3, Tasks 3-5): access to known-sensitive paths
(chat apps, crypto wallets, browser credential stores, SSH keys, SQL data),
archiving before exfiltration, keyword-searching files for credentials, and
a data-stealer heuristic that deliberately does *not* rely on command-line
text -- the room is explicit that stealers "rarely use CMD or PowerShell
commands but rely on their own code," so the only usable signal against
one is which *files* one process touches, not what it typed.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import EventRecord, Finding, SYSMON_FILE_CREATE, SYSMON_PROCESS_CREATE
from ..parsers import EVT_POWERSHELL_HISTORY
from ..processtree import ProcessTree
from ..util import any_substring, windowed_groups
from .base import Detector, register


@register
class SensitiveDataAccessDetector(Detector):
    id = "EVTX-COLLECT-SENSITIVE"
    title = "Access to a known sensitive data path"
    tactic = "Collection"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not (e.is_command_source or e.sysmon(SYSMON_FILE_CREATE)):
                continue
            haystack = f"{e.command_text} {e.target_filename}"
            hit = any_substring(haystack, self.config.sensitive_data_paths)
            if not hit:
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-COLLECT-SENSITIVE-01",
                    title="Access to a known sensitive data path",
                    tactic="Collection",
                    severity="high",
                    confidence="medium",
                    description=(
                        f"'{e.image or 'powershell.exe'}' referenced "
                        f"'{hit}' -- a path pattern matching browser "
                        f"credential stores, chat app data, crypto "
                        f"wallets, SSH keys, or database files. Not every "
                        f"hit is malicious (an admin restoring a wallet "
                        f"backup looks identical), so weigh this against "
                        f"the rest of the session."
                    ),
                    events=[e.index],
                    evidence={"matched_path": hit, "command_line": e.command_line, "target_filename": e.target_filename},
                    recommendation="Confirm business justification; if unexpected, treat as likely data collection.",
                )
            )
        return findings


@register
class DataStagingArchiveDetector(Detector):
    id = "EVTX-COLLECT-ARCHIVE"
    title = "Data archived, likely staged for exfiltration"
    tactic = "Collection"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.is_command_source:
                continue
            haystack = f"{e.image} {e.command_text}"
            hit = any_substring(haystack, self.config.archive_staging_commands)
            if not hit:
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-COLLECT-ARCHIVE-01",
                    title="Data archived, likely staged for exfiltration",
                    tactic="Collection",
                    severity="medium",
                    confidence="low",
                    description=(
                        f"'{hit}' was used to build an archive: "
                        f"'{e.command_line[:200]}'. Archiving is routine "
                        f"IT activity by itself, but immediately after "
                        f"sensitive-path access or a discovery sequence "
                        f"it's the staging step right before "
                        f"exfiltration."
                    ),
                    events=[e.index],
                    evidence={"command_line": e.command_line},
                    recommendation="Check what was archived and where the resulting file went next (upload, email, USB copy).",
                )
            )
        return findings


@register
class CredentialKeywordSearchDetector(Detector):
    id = "EVTX-COLLECT-CREDSEARCH"
    title = "Keyword search for credentials inside a file"
    tactic = "Credential Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.is_command_source:
                continue
            haystack = e.command_text
            hit = any_substring(haystack, self.config.credential_keyword_commands)
            if not hit:
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-COLLECT-CREDSEARCH-01",
                    title="Keyword search for credentials inside a file",
                    tactic="Credential Access",
                    severity="high",
                    confidence="medium",
                    description=(
                        f"Command line searched for a credential-related "
                        f"keyword: '{e.command_line[:200]}'. This is the "
                        f"room's own `findstr password` example -- a "
                        f"targeted search through file contents for "
                        f"secrets rather than just listing files."
                    ),
                    events=[e.index],
                    evidence={"command_line": e.command_line},
                    recommendation="Identify the source file(s) searched and rotate any credentials that may have been exposed.",
                )
            )
        return findings


@register
class PossibleDataStealerDetector(Detector):
    """Deliberately command-line-independent: groups Sysmon 11 file-create
    events by the writing process and flags one process touching several
    *distinct categories* of sensitive path within a short window -- the
    shape a data stealer's own code produces even when it never once
    invokes cmd.exe or powershell.exe."""

    id = "EVTX-COLLECT-STEALER"
    title = "Single process touched multiple sensitive-data categories"
    tactic = "Collection"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        by_image: dict[str, list[tuple[float, EventRecord]]] = defaultdict(list)
        for e in events:
            if not e.sysmon(SYSMON_FILE_CREATE):
                continue
            if any_substring(e.target_filename, self.config.sensitive_data_paths):
                by_image[e.image].append((e.ts, e))

        findings = []
        for image, items in by_image.items():
            for batch in windowed_groups(items, self.config.stealer_window_s):
                categories = set()
                for e in batch:
                    hit = any_substring(e.target_filename, self.config.sensitive_data_paths)
                    if hit:
                        categories.add(hit)
                if len(categories) >= self.config.stealer_distinct_category_threshold:
                    findings.append(
                        Finding(
                            rule_id="EVTX-COLLECT-STEALER-01",
                            title="Possible data stealer activity",
                            tactic="Collection",
                            severity="critical",
                            confidence="medium",
                            description=(
                                f"'{image}' touched {len(categories)} "
                                f"distinct sensitive-data categories "
                                f"({', '.join(sorted(categories))}) within "
                                f"{self.config.stealer_window_s:.0f}s via "
                                f"its own file activity, with no "
                                f"corresponding CMD/PowerShell commands "
                                f"required to trigger this rule -- the "
                                f"pattern the room describes for a data "
                                f"stealer's own code rather than a human "
                                f"operator typing commands."
                            ),
                            events=[e.index for e in batch][: self.config.max_evidence_events],
                            evidence={"image": image, "categories": sorted(categories)},
                            recommendation="Isolate the host immediately; a single process reaching this many unrelated sensitive sources at once is not routine software behavior.",
                        )
                    )
                    break
        return findings
