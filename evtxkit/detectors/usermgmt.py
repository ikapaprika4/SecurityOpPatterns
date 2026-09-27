"""User management detection (Windows Logging for SOC, Task 3; Windows
Threat Detection 2, Task 3's "Detecting Backdoored Users"). The room is
explicit that a suspicious *name* is not the signal to rely on -- instead
investigate who created the account, the creator's own logon (source IP,
time), and what else happened in that creator's session. `NewUserCreatedDetector`
below does exactly that correlation via Logon ID wherever the creating
session's own 4624 is present in the same event set.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import SENSITIVE_GROUPS
from ..models import (
    EVT_GROUP_MEMBER_ADDED,
    EVT_LOGON_SUCCESS,
    EVT_PASSWORD_RESET,
    EVT_USER_CREATED,
    EventRecord,
    Finding,
    norm_logon_id,
)
from ..processtree import ProcessTree
from .base import Detector, register


def _find_creator_logon(events: list[EventRecord], logon_id: str) -> EventRecord | None:
    want = norm_logon_id(logon_id)
    if not want:
        return None
    for e in events:
        if e.event_id == EVT_LOGON_SUCCESS and e.logon_id == want:
            return e
    return None


@register
class NewUserCreatedDetector(Detector):
    id = "EVTX-USER-NEW"
    title = "New local user account created"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if e.event_id != EVT_USER_CREATED:
                continue
            creator_logon_id = e.get("SubjectLogonId")
            creator_logon = _find_creator_logon(events, creator_logon_id)
            evidence = {
                "new_user": e.target_user,
                "created_by": e.subject_user,
                "creator_logon_id": creator_logon_id,
            }
            note = "creator's own logon event was not found in this log set -- can't confirm source IP/time."
            if creator_logon is not None:
                evidence["creator_source_ip"] = creator_logon.source_ip
                evidence["creator_logon_type"] = creator_logon.logon_type
                note = (
                    f"creator '{e.subject_user}' logged on from "
                    f"{creator_logon.source_ip or 'an unrecorded source'} "
                    f"(logon type {creator_logon.logon_type}) -- confirm "
                    f"with them whether this account creation is expected."
                )
            findings.append(
                Finding(
                    rule_id="EVTX-USER-NEW-01",
                    title="New local user account created",
                    tactic="Persistence",
                    severity="low",
                    confidence="low",
                    description=(
                        f"Account '{e.target_user}' was created by "
                        f"'{e.subject_user}' (event 4720). Per the room's "
                        f"own guidance, a suspicious *name* is not the "
                        f"signal to chase -- {note}"
                    ),
                    events=[e.index] + ([creator_logon.index] if creator_logon else []),
                    evidence=evidence,
                    recommendation="Confirm with the creator; if unexpected, treat as a likely backdoor account.",
                )
            )
        return findings


@register
class BackdooredAdminUserDetector(Detector):
    """The strong signal: a brand-new account immediately made privileged."""

    id = "EVTX-USER-BACKDOOR-ADMIN"
    title = "New user created and added to a privileged group"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        creations: dict[str, EventRecord] = {}
        for e in events:
            if e.event_id == EVT_USER_CREATED and e.target_user:
                creations[e.target_user.lower()] = e

        findings = []
        for e in events:
            if e.event_id != EVT_GROUP_MEMBER_ADDED:
                continue
            group = e.get("TargetUserName", "GroupName")
            member = e.get("MemberName", "MemberSid")
            if not any(g.lower() == group.lower() for g in self.config.sensitive_groups):
                continue
            created = creations.get(member.lower().lstrip("\\").split("\\")[-1]) if member else None
            # MemberName in 4732 is often "%{domain}\\username" or a full DN;
            # fall back to substring containment against known new usernames.
            if created is None and member:
                for uname, cev in creations.items():
                    if uname and uname in member.lower():
                        created = cev
                        break
            if created is None:
                continue
            if not (created.ts <= e.ts <= created.ts + self.config.backdoor_privilege_window_s):
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-USER-BACKDOOR-ADMIN-01",
                    title="Backdoored privileged account",
                    tactic="Persistence",
                    severity="critical",
                    confidence="high",
                    description=(
                        f"'{created.target_user}' was created by "
                        f"'{created.subject_user}' and added to "
                        f"'{group}' within "
                        f"{e.ts - created.ts:.0f}s -- a brand-new account "
                        f"made privileged almost immediately is exactly "
                        f"the T1136/T1098 backdoor pattern the room "
                        f"describes, not routine onboarding."
                    ),
                    events=[created.index, e.index],
                    evidence={"new_user": created.target_user, "group": group, "created_by": created.subject_user},
                    recommendation="Disable the account immediately and investigate the creating session in full.",
                )
            )
        return findings


@register
class PrivilegedGroupModificationDetector(Detector):
    id = "EVTX-USER-GROUP"
    title = "Account added to a privileged group"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if e.event_id != EVT_GROUP_MEMBER_ADDED:
                continue
            group = e.get("TargetUserName", "GroupName")
            if not any(g.lower() == group.lower() for g in self.config.sensitive_groups):
                continue
            member = e.get("MemberName", "MemberSid")
            findings.append(
                Finding(
                    rule_id="EVTX-USER-GROUP-01",
                    title="Account added to a privileged group",
                    tactic="Persistence",
                    severity="medium",
                    confidence="medium",
                    description=(
                        f"'{member}' was added to '{group}' by "
                        f"'{e.subject_user}' (event 4732). The most "
                        f"commonly exploited groups are Administrators "
                        f"and Remote Desktop Users -- confirm this "
                        f"addition was expected."
                    ),
                    events=[e.index],
                    evidence={"member": member, "group": group, "added_by": e.subject_user},
                    recommendation="Verify with the account owner/creator; remove membership if unexpected.",
                )
            )
        return findings


@register
class PasswordResetDetector(Detector):
    id = "EVTX-USER-PWRESET"
    title = "Account password was reset"
    tactic = "Persistence"

    def run(self, events: list[EventRecord], tree: ProcessTree) -> list[Finding]:
        findings = []
        for e in events:
            if e.event_id != EVT_PASSWORD_RESET:
                continue
            findings.append(
                Finding(
                    rule_id="EVTX-USER-PWRESET-01",
                    title="Account password reset",
                    tactic="Persistence",
                    severity="medium",
                    confidence="low",
                    description=(
                        f"'{e.subject_user}' reset the password for "
                        f"'{e.target_user}' (event 4724). This log alone "
                        f"can't establish whether '{e.target_user}' was a "
                        f"dormant/unused account being repurposed, which "
                        f"is the room's own stated attacker pattern -- "
                        f"that needs a baseline of normal account "
                        f"activity this toolkit doesn't have."
                    ),
                    events=[e.index],
                    evidence={"target_user": e.target_user, "reset_by": e.subject_user},
                    recommendation="Check the account's last-logon history; if it was dormant before this reset, treat as likely persistence.",
                )
            )
        return findings
