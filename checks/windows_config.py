"""Comprehensive Windows security configuration checks."""

import subprocess
import json
import os
import platform
from typing import Any


def check_windows_config() -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []

    findings: list[dict[str, Any]] = []
    findings.extend(_check_smb_v1())
    findings.extend(_check_uac())
    findings.extend(_check_autoplay())
    findings.extend(_check_winrm())
    findings.extend(_check_rdp_nla())
    findings.extend(_check_unquoted_service_paths())
    findings.extend(_check_shared_folders())
    findings.extend(_check_bitlocker())
    findings.extend(_check_windows_update_service())
    findings.extend(_check_screen_lock())
    findings.extend(_check_llmnr_netbios())
    findings.extend(_check_powershell_execution_policy())
    findings.extend(_check_event_log())
    return findings


def _ps(cmd: str, timeout: int = 20) -> str:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _check_smb_v1() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "try { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } "
        "catch { 'Unknown' }"
    )
    if raw == "Enabled":
        findings.append({
            "id": "WIN001",
            "title": "SMBv1 Protocol is Enabled",
            "severity": "Critical",
            "score_deduction": 15,
            "description": (
                "SMBv1 is a legacy, insecure file-sharing protocol. It was exploited by "
                "WannaCry and NotPetya ransomware and has known unauthenticated remote code "
                "execution vulnerabilities."
            ),
            "evidence": "Get-WindowsOptionalFeature SMB1Protocol = Enabled",
            "recommendation": "Disable SMBv1 immediately — it has no legitimate modern use.",
            "fix": "Run (as Admin): Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
            "category": "Windows Config",
        })
    elif raw == "Disabled":
        findings.append({
            "id": "WIN001",
            "title": "SMBv1 Disabled",
            "severity": "Info",
            "score_deduction": 0,
            "description": "SMBv1 is correctly disabled on this system.",
            "evidence": "SMB1Protocol feature state: Disabled",
            "recommendation": "No action required.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_uac() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "| Select-Object EnableLUA, ConsentPromptBehaviorAdmin | ConvertTo-Json -Compress"
    )
    if not raw:
        return findings
    try:
        data = json.loads(raw)
        lua = data.get("EnableLUA", 1)
        consent = data.get("ConsentPromptBehaviorAdmin", 5)

        if str(lua) == "0":
            findings.append({
                "id": "WIN002",
                "title": "UAC (User Account Control) is Disabled",
                "severity": "High",
                "score_deduction": 10,
                "description": (
                    "User Account Control is disabled. UAC prevents unauthorized applications "
                    "from making system changes. Without it, malware can silently elevate privileges."
                ),
                "evidence": "HKLM\\...\\Policies\\System\\EnableLUA = 0",
                "recommendation": "Enable UAC immediately.",
                "fix": "Open: Control Panel > User Accounts > Change UAC settings > slide to top",
                "category": "Windows Config",
            })
        elif str(consent) == "0":
            findings.append({
                "id": "WIN002B",
                "title": "UAC Set to Never Notify (Lowest Level)",
                "severity": "Medium",
                "score_deduction": 5,
                "description": (
                    "UAC is set to 'Never notify', the lowest security level. "
                    "Applications can make system changes without prompting."
                ),
                "evidence": f"ConsentPromptBehaviorAdmin = {consent}",
                "recommendation": "Set UAC to at least 'Notify me only when apps try to make changes'.",
                "fix": "Open: Control Panel > User Accounts > Change UAC settings > raise slider",
                "category": "Windows Config",
            })
        else:
            findings.append({
                "id": "WIN002",
                "title": "UAC is Enabled",
                "severity": "Info",
                "score_deduction": 0,
                "description": f"User Account Control is active (EnableLUA={lua}, ConsentPrompt={consent}).",
                "evidence": f"EnableLUA={lua}, ConsentPromptBehaviorAdmin={consent}",
                "recommendation": "No action required.",
                "fix": "No action required.",
                "category": "Windows Config",
            })
    except Exception:
        pass
    return findings


def _check_autoplay() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "try { (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "-ErrorAction Stop).NoDriveTypeAutoRun } catch { $null }"
    )
    # 255 (0xFF) = disabled for all, 0x91 = disabled for removable
    if raw in ("", "0", None):
        findings.append({
            "id": "WIN003",
            "title": "AutoPlay / AutoRun Not Fully Disabled",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "AutoPlay is not disabled for all drive types. Malicious USB drives and "
                "optical media can execute code automatically when inserted."
            ),
            "evidence": f"NoDriveTypeAutoRun = {raw or 'not set'}",
            "recommendation": "Disable AutoRun for all drive types via Group Policy.",
            "fix": "Run: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f",
            "category": "Windows Config",
        })
    else:
        findings.append({
            "id": "WIN003",
            "title": "AutoPlay / AutoRun Restricted",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"AutoRun is restricted (NoDriveTypeAutoRun = {raw}).",
            "evidence": f"NoDriveTypeAutoRun = {raw}",
            "recommendation": "No action required.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_winrm() -> list[dict[str, Any]]:
    findings = []
    raw = _ps("(Get-Service WinRM -ErrorAction SilentlyContinue).Status")
    if raw.lower() == "running":
        findings.append({
            "id": "WIN004",
            "title": "Windows Remote Management (WinRM) is Running",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "WinRM (Windows Remote Management) service is active. "
                "This allows remote PowerShell execution and can be exploited if not "
                "properly restricted with authentication and firewall rules."
            ),
            "evidence": "WinRM service status: Running",
            "recommendation": "Disable WinRM if not required, or restrict access via firewall.",
            "fix": "Run (as Admin): Stop-Service WinRM; Set-Service WinRM -StartupType Disabled",
            "category": "Windows Config",
        })
    else:
        findings.append({
            "id": "WIN004",
            "title": "WinRM Not Running",
            "severity": "Info",
            "score_deduction": 0,
            "description": "Windows Remote Management service is not running.",
            "evidence": f"WinRM status: {raw or 'Stopped/Not Found'}",
            "recommendation": "No action required.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_rdp_nla() -> list[dict[str, Any]]:
    findings = []
    # Check if RDP is even enabled
    raw_rdp = _ps(
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-ErrorAction SilentlyContinue).fDenyTSConnections"
    )
    if raw_rdp == "0":
        # RDP enabled — check NLA
        raw_nla = _ps(
            "(Get-ItemProperty "
            "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "-ErrorAction SilentlyContinue).UserAuthenticationRequired"
        )
        if raw_nla != "1":
            findings.append({
                "id": "WIN005",
                "title": "RDP Enabled Without Network Level Authentication",
                "severity": "High",
                "score_deduction": 10,
                "description": (
                    "Remote Desktop is enabled but Network Level Authentication (NLA) is off. "
                    "Without NLA, anyone can reach the login screen without pre-authenticating, "
                    "exposing the system to credential brute-force and BlueKeep-style attacks."
                ),
                "evidence": f"fDenyTSConnections=0, UserAuthenticationRequired={raw_nla}",
                "recommendation": "Enable NLA for RDP or disable RDP entirely.",
                "fix": (
                    "System Properties > Remote > check 'Allow connections only from computers "
                    "running Remote Desktop with NLA'"
                ),
                "category": "Windows Config",
            })
        else:
            findings.append({
                "id": "WIN005",
                "title": "RDP Enabled With NLA (Network Level Authentication)",
                "severity": "Medium",
                "score_deduction": 5,
                "description": "RDP is active but NLA is enabled, reducing exposure. Still a risk if internet-facing.",
                "evidence": "fDenyTSConnections=0, UserAuthenticationRequired=1",
                "recommendation": "Ensure RDP is firewalled to trusted IPs only.",
                "fix": "Add inbound firewall rule limiting RDP to specific source IPs.",
                "category": "Windows Config",
            })
    return findings


def _check_unquoted_service_paths() -> list[dict[str, Any]]:
    findings = []
    try:
        out = subprocess.run(
            ["wmic", "service", "get", "Name,PathName,StartMode"],
            capture_output=True, text=True, timeout=30
        )
        unquoted = []
        for line in out.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            # Path has spaces, not quoted with ", not in system32
            if " " in line and '"' not in line:
                # extract path portion (last 2 tokens are Name and StartMode)
                parts = line.rsplit(None, 2)
                path_part = parts[0] if len(parts) >= 1 else ""
                if " " in path_part and not path_part.startswith('"') and "system32" not in path_part.lower():
                    unquoted.append(path_part[:80])

        if unquoted:
            findings.append({
                "id": "WIN006",
                "title": f"Unquoted Service Paths Found ({len(unquoted)})",
                "severity": "Medium",
                "score_deduction": 5,
                "description": (
                    "Services with unquoted executable paths containing spaces can allow "
                    "privilege escalation — Windows may execute a malicious binary placed "
                    "in a parent directory."
                ),
                "evidence": "; ".join(unquoted[:3]),
                "recommendation": "Quote all service executable paths.",
                "fix": 'Use: sc config <ServiceName> binpath= "\\"C:\\path with spaces\\service.exe\\"" ',
                "category": "Windows Config",
            })
    except Exception:
        pass
    return findings


def _check_shared_folders() -> list[dict[str, Any]]:
    findings = []
    try:
        out = subprocess.run(
            ["net", "share"], capture_output=True, text=True, timeout=15
        )
        shares = []
        default_shares = {"C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$"}
        non_default = []
        for line in out.stdout.splitlines()[3:]:
            line = line.strip()
            if line and "The command" not in line:
                share_name = line.split()[0]
                shares.append(share_name)
                if share_name.upper() not in default_shares:
                    non_default.append(share_name)

        if non_default:
            findings.append({
                "id": "WIN007",
                "title": f"Non-Default Shared Folders Found ({len(non_default)})",
                "severity": "Medium",
                "score_deduction": 5,
                "description": (
                    f"Network shares beyond Windows defaults were found: {', '.join(non_default)}. "
                    "Shared folders increase exposure if not properly permission-controlled."
                ),
                "evidence": f"Shares: {', '.join(non_default)}",
                "recommendation": "Review each share and remove any that are no longer needed.",
                "fix": "Run: net share <sharename> /delete",
                "category": "Windows Config",
            })
        if shares:
            findings.append({
                "id": "WIN007B",
                "title": f"Windows Default Admin Shares Active ({len(shares)} total shares)",
                "severity": "Info",
                "score_deduction": 0,
                "description": f"Active shares: {', '.join(shares)}. Default admin shares (C$, ADMIN$, IPC$) are normal.",
                "evidence": f"All shares: {', '.join(shares)}",
                "recommendation": "Ensure admin shares are firewall-restricted.",
                "fix": "Block SMB ports 139/445 from external access via firewall.",
                "category": "Windows Config",
            })
    except Exception:
        pass
    return findings


def _check_bitlocker() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "try { "
        "  $bl = manage-bde -status C: 2>&1; "
        "  if ($bl -match 'Protection On') { 'On' } "
        "  elseif ($bl -match 'Protection Off') { 'Off' } "
        "  else { 'Unknown' } "
        "} catch { 'Unknown' }"
    )
    if raw == "Off":
        findings.append({
            "id": "WIN008",
            "title": "BitLocker Disk Encryption Not Active on C:",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "Drive C: is not protected by BitLocker. If the device is lost or stolen, "
                "data can be read by anyone with physical access."
            ),
            "evidence": "manage-bde -status C: = Protection Off",
            "recommendation": "Enable BitLocker on all drives, especially the system drive.",
            "fix": "Search: 'Manage BitLocker' > Turn on BitLocker for drive C:",
            "category": "Windows Config",
        })
    elif raw == "On":
        findings.append({
            "id": "WIN008",
            "title": "BitLocker Active on C:",
            "severity": "Info",
            "score_deduction": 0,
            "description": "BitLocker disk encryption is protecting drive C:.",
            "evidence": "manage-bde -status C: = Protection On",
            "recommendation": "Ensure recovery keys are securely backed up.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_windows_update_service() -> list[dict[str, Any]]:
    findings = []
    raw = _ps("(Get-Service wuauserv -ErrorAction SilentlyContinue).StartType")
    if raw.lower() == "disabled":
        findings.append({
            "id": "WIN009",
            "title": "Windows Update Service is Disabled",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "The Windows Update service (wuauserv) is disabled. Security patches "
                "will not be installed automatically, leaving known vulnerabilities unpatched."
            ),
            "evidence": "wuauserv StartType = Disabled",
            "recommendation": "Re-enable the Windows Update service.",
            "fix": "Run: Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv",
            "category": "Windows Config",
        })
    else:
        findings.append({
            "id": "WIN009",
            "title": "Windows Update Service Enabled",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"Windows Update service is configured as: {raw or 'Automatic/Manual'}.",
            "evidence": f"wuauserv StartType = {raw}",
            "recommendation": "Ensure automatic updates are enabled.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_screen_lock() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "try { "
        "  (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction Stop).ScreenSaveTimeOut "
        "} catch { $null }"
    )
    active = _ps(
        "try { "
        "  (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' -ErrorAction Stop).ScreenSaverIsSecure "
        "} catch { $null }"
    )
    try:
        timeout_sec = int(raw) if raw else 0
        is_secure = str(active).strip() == "1"

        if timeout_sec == 0:
            findings.append({
                "id": "WIN010",
                "title": "Screen Lock / Screen Saver Not Configured",
                "severity": "Medium",
                "score_deduction": 5,
                "description": (
                    "No screen saver or lock timeout is configured. An unattended machine "
                    "can be accessed by anyone with physical presence."
                ),
                "evidence": "ScreenSaveTimeOut = 0 (disabled)",
                "recommendation": "Enable screen lock with a timeout of 5 minutes or less.",
                "fix": "Settings > Accounts > Sign-in options > Require sign-in: set to 'When PC wakes from sleep'",
                "category": "Windows Config",
            })
        elif timeout_sec > 600:
            findings.append({
                "id": "WIN010",
                "title": f"Screen Lock Timeout Too Long ({timeout_sec // 60} minutes)",
                "severity": "Low",
                "score_deduction": 2,
                "description": f"Screen saver timeout is {timeout_sec // 60} minutes — too long. Reduces physical security.",
                "evidence": f"ScreenSaveTimeOut = {timeout_sec}s",
                "recommendation": "Set screen saver timeout to 5 minutes or less.",
                "fix": "Settings > Personalization > Lock screen > Screen saver settings > set timeout",
                "category": "Windows Config",
            })
        elif not is_secure:
            findings.append({
                "id": "WIN010B",
                "title": "Screen Saver Does Not Require Password",
                "severity": "Medium",
                "score_deduction": 5,
                "description": "Screen saver is set but does not require a password to unlock. Physical access bypasses login.",
                "evidence": "ScreenSaverIsSecure = 0",
                "recommendation": "Enable 'On resume, display logon screen' in screen saver settings.",
                "fix": "Control Panel > Appearance > Screen Saver > check 'On resume, display logon screen'",
                "category": "Windows Config",
            })
        else:
            findings.append({
                "id": "WIN010",
                "title": f"Screen Lock Configured ({timeout_sec // 60}m timeout, password-protected)",
                "severity": "Info",
                "score_deduction": 0,
                "description": f"Screen lock is configured with a {timeout_sec // 60}-minute timeout.",
                "evidence": f"ScreenSaveTimeOut={timeout_sec}, ScreenSaverIsSecure={active}",
                "recommendation": "No action required.",
                "fix": "No action required.",
                "category": "Windows Config",
            })
    except Exception:
        pass
    return findings


def _check_llmnr_netbios() -> list[dict[str, Any]]:
    findings = []

    # LLMNR
    raw_llmnr = _ps(
        "try { "
        "  (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "  -ErrorAction Stop).EnableMulticast "
        "} catch { $null }"
    )
    if raw_llmnr != "0":
        findings.append({
            "id": "WIN011",
            "title": "LLMNR (Link-Local Multicast Name Resolution) Enabled",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "LLMNR is enabled. Attackers on the local network can use LLMNR poisoning "
                "(Responder tool) to intercept credentials when a name resolution fails."
            ),
            "evidence": f"EnableMulticast policy = {raw_llmnr or 'not set (enabled by default)'}",
            "recommendation": "Disable LLMNR via Group Policy.",
            "fix": (
                "gpedit.msc > Computer Config > Admin Templates > Network > DNS Client > "
                "Turn off multicast name resolution = Enabled"
            ),
            "category": "Windows Config",
        })
    else:
        findings.append({
            "id": "WIN011",
            "title": "LLMNR Disabled",
            "severity": "Info",
            "score_deduction": 0,
            "description": "LLMNR multicast name resolution is disabled.",
            "evidence": "EnableMulticast = 0",
            "recommendation": "No action required.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_powershell_execution_policy() -> list[dict[str, Any]]:
    findings = []
    raw = _ps("Get-ExecutionPolicy -Scope LocalMachine")
    policy = raw.strip().lower()
    if policy == "unrestricted":
        findings.append({
            "id": "WIN012",
            "title": "PowerShell Execution Policy: Unrestricted",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "PowerShell execution policy is set to Unrestricted — any script can run "
                "without warnings or signatures. Attackers and malware use PowerShell heavily."
            ),
            "evidence": "Get-ExecutionPolicy LocalMachine = Unrestricted",
            "recommendation": "Set execution policy to RemoteSigned or Restricted.",
            "fix": "Run: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            "category": "Windows Config",
        })
    elif policy == "bypass":
        findings.append({
            "id": "WIN012",
            "title": "PowerShell Execution Policy: Bypass",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "PowerShell execution policy is set to Bypass — nothing is blocked, no "
                "warnings shown. This is the most permissive and risky setting."
            ),
            "evidence": "Get-ExecutionPolicy LocalMachine = Bypass",
            "recommendation": "Change to RemoteSigned immediately.",
            "fix": "Run: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
            "category": "Windows Config",
        })
    elif policy in ("remotesigned", "allsigned", "restricted"):
        findings.append({
            "id": "WIN012",
            "title": f"PowerShell Execution Policy: {raw.strip()} (Good)",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"PowerShell execution policy is {raw.strip()} — a reasonable setting.",
            "evidence": f"Get-ExecutionPolicy LocalMachine = {raw.strip()}",
            "recommendation": "No action required.",
            "fix": "No action required.",
            "category": "Windows Config",
        })
    return findings


def _check_event_log() -> list[dict[str, Any]]:
    findings = []
    raw = _ps(
        "Get-EventLog -List | Where-Object { $_.Log -in 'Security','System','Application' } | "
        "Select-Object Log, MaximumKilobytes | ConvertTo-Json -Compress"
    )
    if not raw:
        return findings
    try:
        logs = json.loads(raw)
        if isinstance(logs, dict):
            logs = [logs]
        small_logs = [l for l in logs if (l.get("MaximumKilobytes") or 0) < 20480]
        if small_logs:
            names = ", ".join(l.get("Log", "") for l in small_logs)
            findings.append({
                "id": "WIN013",
                "title": f"Event Log Size Too Small ({names})",
                "severity": "Low",
                "score_deduction": 2,
                "description": (
                    f"Event log(s) {names} are smaller than 20 MB. Small logs overwrite "
                    "forensic evidence quickly, limiting incident response capability."
                ),
                "evidence": str([{"log": l["Log"], "maxKB": l["MaximumKilobytes"]} for l in small_logs]),
                "recommendation": "Increase event log size to at least 20 MB.",
                "fix": "Event Viewer > right-click log > Properties > set Max log size to 20480 KB",
                "category": "Windows Config",
            })
    except Exception:
        pass
    return findings
