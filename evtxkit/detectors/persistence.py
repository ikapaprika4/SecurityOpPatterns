"""Malware persistence detection (Windows Threat Detection 2, Tasks 4-5):
services, scheduled tasks, the Startup folder, and Run registry keys --
the four methods the room walks through, each with both a "the tool that
creates it ran" signal (Sysmon 1) and, where Windows logs it, a dedicated
Security/System event.
"""

from __future__ import annotations

import re

from ..models import (
    EVT_SCHEDULED_TASK_CREATED,
    EVT_SERVICE_INSTALLED_SECURITY,
    EVT_SERVICE_INSTALLED_SYSTEM,
    EventRecord,
    Finding,
    SYSMON_FILE_CREATE,
    SYSMON_PROCESS_CREATE,
    SYSMON_REGISTRY_SET,
)
from ..processtree import ProcessTree
from ..util import any_substring, norm_path
from .base import Detector, register

_BINPATH_RE = re.compile(r"binpath[=\s]+\"?([^\"]+)", re.I)
_TR_RE = re.compile(r"/tr\s+\"?([^\"]+?)(?:\"|\s+/|\s*$)", re.I)


def _is_suspicious_dir(path: str, config) -> bool:
    low = norm_path(path)
    return any_substring(low, config.suspicious_persistence_dirs) is not None


def _is_legitimate_dir(path: str, config) -> bool:
    low = norm_path(path)
    return any(low.startswith(d) for d in config.legitimate_service_dirs)


@register
class ServicePersistenceDetector(Detector):
    id = "EVTX-PERSIST-SERVICE"
    title = "Service created for persistence"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        # One service seen twice (the sc.exe launch AND the SCM's 7045) is one
        # finding with two evidence events, not two findings.
        by_binpath: dict[str, Finding] = {}
        for e in events:
            binpath = ""
            source = ""
            if e.is_process_create and e.image.lower().endswith("\\sc.exe"):
                if "create" not in e.command_line.lower():
                    continue
                m = _BINPATH_RE.search(e.command_line)
                binpath = m.group(1).strip() if m else ""
                source = f"sc.exe launch (event {e.event_id})"
            elif (e.event_id == EVT_SERVICE_INSTALLED_SECURITY and e.channel in ("Security", "Unknown")) \
                    or (e.event_id == EVT_SERVICE_INSTALLED_SYSTEM and e.channel in ("System", "Unknown")):
                binpath = e.get("ServiceFileName", "ImagePath")
                source = f"service install (event {e.event_id})"
            else:
                continue

            key = norm_path(binpath).strip('"')
            if key and key in by_binpath:
                by_binpath[key].events.append(e.index)
                continue

            suspicious = _is_suspicious_dir(binpath, self.config)
            legit = _is_legitimate_dir(binpath, self.config)
            severity = "high" if suspicious else ("low" if legit else "medium")
            findings.append(
                Finding(
                    rule_id="EVTX-PERSIST-SERVICE-01",
                    title="Service created for persistence",
                    tactic="Persistence",
                    severity=severity,
                    confidence="medium" if suspicious else "low",
                    description=(
                        f"A Windows service was created pointing to "
                        f"'{binpath or '(binary path not captured)'}', "
                        f"detected via {source}. Services created by "
                        f"malware to survive reboot commonly point to "
                        f"C:\\Temp, C:\\ProgramData, or AppData rather "
                        f"than Program Files/System32."
                    ),
                    events=[e.index],
                    evidence={"binary_path": binpath, "in_suspicious_dir": suspicious,
                              "service_name": e.get("ServiceName")},
                    recommendation="Verify the service and binary are expected; if not, stop/delete the service and quarantine the binary.",
                )
            )
            if key:
                by_binpath[key] = findings[-1]
        return findings


@register
class ScheduledTaskPersistenceDetector(Detector):
    id = "EVTX-PERSIST-TASK"
    title = "Scheduled task created for persistence"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            target = ""
            source = ""
            if e.is_process_create and e.image.lower().endswith("\\schtasks.exe"):
                if "/create" not in e.command_line.lower():
                    continue
                m = _TR_RE.search(e.command_line)
                target = m.group(1).strip() if m else ""
                source = "schtasks.exe launch (Sysmon 1)"
            elif e.event_id == EVT_SCHEDULED_TASK_CREATED:
                content = e.get("TaskContent")
                m = _TR_RE.search(content) if content else None
                target = m.group(1).strip() if m else e.get("TaskName")
                source = "task creation (event 4698)"
            else:
                continue

            suspicious = _is_suspicious_dir(target, self.config)
            severity = "high" if suspicious else "medium"
            findings.append(
                Finding(
                    rule_id="EVTX-PERSIST-TASK-01",
                    title="Scheduled task created for persistence",
                    tactic="Persistence",
                    severity=severity,
                    confidence="medium" if suspicious else "low",
                    description=(
                        f"A scheduled task was created running "
                        f"'{target or '(target not captured)'}', "
                        f"detected via {source}. Scheduled tasks are the "
                        f"room's own noted most common persistence "
                        f"method precisely because they're easy to "
                        f"configure and hide."
                    ),
                    events=[e.index],
                    evidence={"target": target, "in_suspicious_dir": suspicious},
                    recommendation="Review the task in Task Scheduler; delete if unexpected and investigate the creating session.",
                )
            )
        return findings


@register
class StartupFolderPersistenceDetector(Detector):
    id = "EVTX-PERSIST-STARTUP"
    title = "File dropped into the Startup folder"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.sysmon(SYSMON_FILE_CREATE):
                continue
            target = e.target_filename
            if not any_substring(target, self.config.startup_folder_markers):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-PERSIST-STARTUP-01",
                    title="File dropped into the Startup folder",
                    tactic="Persistence",
                    severity="high",
                    confidence="medium",
                    description=(
                        f"'{e.image}' created '{target}' inside a Startup "
                        f"folder (Sysmon event 11). The Startup folder is "
                        f"normally empty -- legitimate installers rarely "
                        f"use it, so any new file here is worth "
                        f"reviewing."
                    ),
                    events=[e.index],
                    evidence={"created_by": e.image, "target": target},
                    recommendation="Remove the file if unexpected; it will run automatically on every logon until then.",
                )
            )
        return findings


@register
class RunKeyPersistenceDetector(Detector):
    id = "EVTX-PERSIST-RUNKEY"
    title = "Run/RunOnce registry key modified"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if not e.sysmon(SYSMON_REGISTRY_SET):
                continue
            target = e.target_object
            if not any_substring(target, self.config.run_key_markers):
                continue
            details = e.get("Details")
            findings.append(
                Finding(
                    rule_id="EVTX-PERSIST-RUNKEY-01",
                    title="Run/RunOnce registry key modified",
                    tactic="Persistence",
                    severity="high",
                    confidence="medium",
                    description=(
                        f"'{e.image}' set '{target}' to "
                        f"'{details or '(value not captured)'}' (Sysmon "
                        f"event 13) -- a Run-key entry runs on every "
                        f"logon for that user, functionally identical to "
                        f"a Startup folder drop, just configured via the "
                        f"registry instead."
                    ),
                    events=[e.index],
                    evidence={"set_by": e.image, "key": target, "value": details},
                    recommendation="Remove the registry value if unexpected; check what process set it.",
                )
            )
        return findings
