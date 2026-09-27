"""Phishing / removable-media execution detection (Windows Threat Detection
1, Tasks 3-5): the double-extension binary attachment, the LNK-hides-a-
PowerShell-payload attachment, and USB-origin execution -- three distinct
techniques that share one property the room states explicitly: all three
end with `explorer.exe` as the parent process, because a human double-
clicked something. That shared parent is exactly why these can't be told
apart from ordinary user activity by process-tree shape alone -- each
detector below needs its own extra evidence (a preceding file-create event,
a double extension, a non-system drive letter) to say more than "a user
opened a program."
"""

from __future__ import annotations

from ..models import EventRecord, Finding, SYSMON_FILE_CREATE, SYSMON_PROCESS_CREATE
from ..processtree import ProcessTree
from ..util import any_substring, has_double_extension, is_removable_drive_path, norm_path
from .base import Detector, register

_SCRIPT_HOSTS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")


@register
class DoubleExtensionExecutionDetector(Detector):
    id = "EVTX-EXEC-DOUBLEEXT"
    title = "Execution of a double-extension file"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.is_process_create or not has_double_extension(e.image):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-EXEC-DOUBLEEXT-01",
                    title="Execution of a double-extension file",
                    tactic="Initial Access",
                    severity="critical",
                    confidence="high",
                    description=(
                        f"'{e.image}' was launched (parent: "
                        f"'{e.parent_image or 'unknown'}') -- a double "
                        f"extension like invoice.pdf.exe is the room's own "
                        f"phishing-attachment disguise technique, relying "
                        f"on Windows hiding known extensions by default so "
                        f"the user only ever sees 'invoice.pdf'."
                    ),
                    events=[e.index],
                    evidence={"image": e.image, "parent_image": e.parent_image},
                    recommendation="Quarantine the file and its parent process's other activity immediately; this is very rarely a false positive.",
                )
            )
        return findings


@register
class ArchiveAttachmentExecutionDetector(Detector):
    """The room's own worked Sysmon event chain: a file appears in
    Downloads (event 11), then that same path is executed with
    explorer.exe as parent (event 1) -- the "user double-clicks the
    unarchived file" step."""

    id = "EVTX-EXEC-DOWNLOADED-ATTACHMENT"
    title = "Downloaded attachment executed"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        drops: dict[str, EventRecord] = {}
        for e in events:
            if not e.sysmon(SYSMON_FILE_CREATE):
                continue
            target = e.target_filename
            if any_substring(target, self.config.download_dir_markers):
                drops[norm_path(target)] = e

        if not drops:
            return []

        findings = []
        for e in events:
            if not e.is_process_create:
                continue
            if "explorer.exe" not in (e.parent_image or "").lower():
                continue
            drop = drops.get(norm_path(e.image))
            if drop is None:
                continue
            if not (drop.ts <= e.ts <= drop.ts + self.config.archive_to_execution_window_s):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-EXEC-DOWNLOADED-ATTACHMENT-01",
                    title="Downloaded attachment executed by the user",
                    tactic="Initial Access",
                    severity="high",
                    confidence="high",
                    description=(
                        f"'{e.image}' appeared in Downloads at "
                        f"{drop.time.isoformat()} and was launched "
                        f"{e.ts - drop.ts:.0f}s later with explorer.exe "
                        f"as its parent -- the full download-then-open "
                        f"chain from a phishing attachment."
                    ),
                    events=[drop.index, e.index],
                    evidence={"image": e.image, "dropped_at": drop.time.isoformat()},
                    recommendation="Treat the parent browser/mail session as compromised; identify how the file was delivered (email, drive-by download).",
                )
            )
        return findings


@register
class LnkPhishingDetector(Detector):
    """A .lnk file appears in Downloads, then explorer.exe appears to
    directly launch a script host -- because Explorer silently resolves
    the LNK's Target field, the process tree alone makes this
    indistinguishable from a user opening PowerShell themselves. The
    preceding file-create event is what actually proves an LNK phishing
    chain rather than routine PowerShell use."""

    id = "EVTX-EXEC-LNK-PHISHING"
    title = "LNK-shortcut phishing execution"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        lnk_drops: list[EventRecord] = []
        for e in events:
            if not e.sysmon(SYSMON_FILE_CREATE):
                continue
            target = e.target_filename
            if target.lower().endswith(self.config.lnk_extension) and any_substring(target, self.config.download_dir_markers):
                lnk_drops.append(e)

        if not lnk_drops:
            return []

        findings = []
        for e in events:
            if not e.is_process_create:
                continue
            if "explorer.exe" not in (e.parent_image or "").lower():
                continue
            image_lower = e.image.lower()
            if not any(image_lower.endswith("\\" + host) for host in _SCRIPT_HOSTS):
                continue
            matching_lnk = next(
                (d for d in lnk_drops if d.ts <= e.ts <= d.ts + self.config.lnk_to_execution_window_s),
                None,
            )
            if matching_lnk is None:
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-EXEC-LNK-PHISHING-01",
                    title="LNK-shortcut phishing execution",
                    tactic="Initial Access",
                    severity="critical",
                    confidence="medium",
                    description=(
                        f"A .lnk file was created at "
                        f"'{matching_lnk.target_filename}' "
                        f"{e.ts - matching_lnk.ts:.0f}s before "
                        f"'{e.image}' was launched with explorer.exe as "
                        f"its direct parent and command line "
                        f"'{e.command_line[:200]}'. Explorer silently "
                        f"resolves an LNK's Target field, so this looks "
                        f"identical to manual PowerShell use in the "
                        f"process tree alone -- the preceding LNK drop is "
                        f"what makes this phishing rather than routine "
                        f"admin activity."
                    ),
                    events=[matching_lnk.index, e.index],
                    evidence={"lnk_path": matching_lnk.target_filename, "launched": e.image, "command_line": e.command_line},
                    recommendation="Extract and review the LNK's Target field directly; treat the downloaded payload as active malware.",
                )
            )
        return findings


@register
class RemovableDriveExecutionDetector(Detector):
    id = "EVTX-EXEC-REMOVABLE"
    title = "Execution from a non-system drive"
    tactic = "Initial Access"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.is_process_create:
                continue
            if not is_removable_drive_path(e.image, self.config.removable_drive_letters):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-EXEC-REMOVABLE-01",
                    title="Execution from a non-system drive",
                    tactic="Initial Access",
                    severity="medium",
                    confidence="low",
                    description=(
                        f"'{e.image}' ran from a non-C: drive -- possible "
                        f"evidence of execution from a USB device, though "
                        f"this signal alone can't distinguish a USB drive "
                        f"from any other mounted or mapped volume (a "
                        f"limitation the room states directly)."
                    ),
                    events=[e.index],
                    evidence={"image": e.image, "parent_image": e.parent_image},
                    recommendation="Correlate with device-connection events (Security 20xx / DeviceSetupManager logs) to confirm removable media.",
                )
            )
        return findings
