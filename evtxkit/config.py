"""All tunable thresholds and reference lists in one place -- no magic
numbers or hardcoded command lists inside detector code. Defaults follow
the rooms' own worked numbers where they give one (e.g. "around 100
attempts" for the RDP brute force case), and otherwise reasonable SOC
triage defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Remote/network-facing logon types (Windows Logging for SOC / Windows
# Threat Detection 1): 3 = Network, 10 = RemoteInteractive (RDP).
REMOTE_LOGON_TYPES = (3, 10)
INTERACTIVE_LOGON_TYPES = (2, 11)   # 2 = Interactive, 11 = CachedInteractive

# Groups that turn a backdoored account into something actually useful to
# an attacker (Windows Threat Detection 2, "Making Users Privileged").
SENSITIVE_GROUPS = ("Administrators", "Remote Desktop Users", "Domain Admins",
                      "Enterprise Admins", "Backup Operators")


@dataclass
class Config:
    # ---- logon / brute force (Windows Threat Detection 1, Task 2) ---------
    brute_force_window_s: float = 300.0             # 5 minutes
    brute_force_attempts_threshold: int = 15         # failed 4625s, one source IP, remote logon types
    successful_logon_correlation_window_s: float = 3600.0  # 1h -- "after around 100 attempts" could span a while
    external_ip_only: bool = True                    # only count brute force from non-private source IPs

    # ---- user management / persistence via backdoored users (WTD2) --------
    backdoor_privilege_window_s: float = 3600.0       # new user -> added to a sensitive group within 1h
    sensitive_groups: tuple[str, ...] = SENSITIVE_GROUPS

    # ---- persistence: services / scheduled tasks (WTD2, Task 4) -----------
    suspicious_persistence_dirs: tuple[str, ...] = (
        "c:\\temp", "c:\\programdata", "c:\\users\\public",
        "\\appdata\\local\\temp", "\\appdata\\roaming", "c:\\windows\\tasks",
        "c:\\perflogs",
    )
    legitimate_service_dirs: tuple[str, ...] = (
        "c:\\windows\\system32", "c:\\program files", "c:\\program files (x86)",
    )

    # ---- persistence: startup folder / run keys (WTD2, Task 5) ------------
    startup_folder_markers: tuple[str, ...] = (
        "\\start menu\\programs\\startup\\",
    )
    run_key_markers: tuple[str, ...] = (
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
    )

    # ---- execution / phishing chains (WTD1, Tasks 2-4) ---------------------
    download_dir_markers: tuple[str, ...] = ("\\downloads\\",)
    archive_extensions: tuple[str, ...] = (".zip", ".rar", ".7z", ".cab")
    executable_extensions: tuple[str, ...] = (
        ".exe", ".com", ".scr", ".cpl", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".ps1", ".hta", ".msi",
    )
    lnk_extension: str = ".lnk"
    lnk_to_execution_window_s: float = 120.0          # LNK file appears in Downloads, then explorer launches its target within this window
    archive_to_execution_window_s: float = 600.0      # archive drop -> extracted double-ext binary execution
    removable_drive_letters: tuple[str, ...] = tuple("DEFGHIJKLMNOPQRSTUVWXYZ")

    # ---- discovery (WTD3, Task 2) -------------------------------------------
    # substrings matched case-insensitively against Image + CommandLine;
    # grouped by purpose purely for readable evidence, not different logic.
    discovery_commands: dict[str, tuple[str, ...]] = field(default_factory=lambda: {
        "files": ("dir ", "get-childitem", "type ", "get-content"),
        "users": ("whoami", "net user", "net localgroup", "query user", "get-localuser", "get-localgroup"),
        "system": ("tasklist", "systeminfo", "wmic product get", "get-service", "wmic computersystem"),
        "network": ("ipconfig", "netstat", "netsh advfirewall"),
        "antivirus": ("securitycenter2", "get-mppreference"),
    })
    discovery_window_s: float = 300.0                 # 5 minutes
    discovery_min_distinct_commands: int = 3
    discovery_min_categories: int = 2                  # e.g. "users" + "network" together is a stronger signal than 3 file listings

    # ---- collection / credential access / staging (WTD3, Tasks 3-4) --------
    sensitive_data_paths: tuple[str, ...] = (
        "\\appdata\\roaming\\signal", "wallet.dat", "\\.ssh\\",
        "\\appdata\\local\\google\\chrome\\user data", "\\microsoft sql server\\",
        "\\appdata\\roaming\\telegram", "\\appdata\\roaming\\discord",
    )
    archive_staging_commands: tuple[str, ...] = ("compress-archive", "7za.exe", "7z.exe", "rar.exe", "winrar")
    credential_keyword_commands: tuple[str, ...] = ("findstr password", "findstr /i password", "select-string password")
    stealer_distinct_category_threshold: int = 3       # one non-shell process touching >= N sensitive-data categories via file events
    stealer_window_s: float = 60.0

    # ---- ingress tool transfer / C2 (WTD2 Task 2, WTD3 Task 6) -------------
    tool_transfer_patterns: tuple[str, ...] = (
        "certutil.exe", "-urlcache", "curl.exe ", "invoke-webrequest",
        " iwr ", "downloadfile(", "downloadstring(", "bitsadmin",
    )
    known_browser_images: tuple[str, ...] = (
        "\\msedge.exe", "\\chrome.exe", "\\firefox.exe", "\\iexplore.exe",
    )
    known_benign_network_images: tuple[str, ...] = (
        "\\svchost.exe", "\\msedge.exe", "\\chrome.exe", "\\firefox.exe",
        "\\onedrive.exe", "\\searchapp.exe", "\\backgroundtaskhost.exe",
    )
    suspicious_network_process_dirs: tuple[str, ...] = (
        "\\appdata\\local\\temp", "\\appdata\\roaming", "c:\\programdata",
        "c:\\temp", "c:\\users\\public",
    )
    transfer_to_network_window_s: float = 30.0          # correlate a certutil/curl/IWR launch with a Sysmon 3/22 event from the same PID

    # ---- offensive PowerShell (script blocks 4104, command lines, history) ----
    # Any one "strong" marker is offensive tooling by name; "weak" markers are
    # ordinary on their own and only fire in combination.
    powershell_strong_markers: tuple[str, ...] = (
        "amsiutils", "amsiinitfailed", "amsiscanbuffer", "invoke-mimikatz", "sekurlsa::",
        "lsadump::", "kerberos::golden", "invoke-kerberoast", "invoke-bloodhound",
        "sharphound", "invoke-shellcode", "invoke-reflectivepeinjection", "out-minidump",
        "get-gpppassword", "powersploit", "invoke-smbexec", "invoke-wmiexec",
        "invoke-thehash", "invoke-rubeus", "invoke-powerdump", "get-keystrokes",
        "invoke-dcsync", "invoke-tokenmanipulation",
    )
    powershell_weak_markers: tuple[str, ...] = (
        "invoke-expression", "iex(", "iex (", "frombase64string", "downloadstring",
        "downloadfile", "net.webclient", "virtualalloc", "-bxor", "reflection.assembly]::load",
        "-windowstyle hidden", "-w hidden", "-noprofile", "-nop ", "bypass",
        "start-bitstransfer", "[char[]]", "gzipstream", "-encodedcommand",
    )
    powershell_weak_marker_threshold: int = 3

    # ---- misc -----------------------------------------------------------------
    max_evidence_events: int = 25
