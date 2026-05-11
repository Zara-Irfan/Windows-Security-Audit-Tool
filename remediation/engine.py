"""Auto-remediation engine — applies verified fixes to detected findings."""

import subprocess
import platform
import ctypes
import os
from datetime import datetime

WINDOWS = platform.system() == "Windows"


def is_admin() -> bool:
    """Return True if the current process has admin/root privileges."""
    if WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _ps(cmd: str, timeout: int = 30) -> tuple[bool, str]:
    """Run a PowerShell command. Returns (success, output)."""
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


# ── Fix registry ──────────────────────────────────────────────────────────────

_FIXABLE: dict[str, dict] = {}


def _reg(fid: str, label: str, desc: str, needs_admin: bool = True):
    def decorator(fn):
        _FIXABLE[fid] = {
            "label":       label,
            "desc":        desc,
            "needs_admin": needs_admin,
            "fn":          fn,
        }
        return fn
    return decorator


def can_fix(finding: dict) -> bool:
    return finding.get("id") in _FIXABLE


def get_fix_meta(fid: str) -> dict | None:
    info = _FIXABLE.get(fid)
    if not info:
        return None
    return {"label": info["label"], "desc": info["desc"], "needs_admin": info["needs_admin"]}


def apply_fix(finding: dict) -> dict:
    """
    Apply the auto-fix for a finding.
    Returns a result dict with keys: success, message, detail, id, title, severity, timestamp.
    """
    fid   = finding.get("id", "")
    entry = _FIXABLE.get(fid)
    if not entry:
        result = {"success": False, "message": "No auto-fix available for this finding.", "detail": ""}
    else:
        try:
            result = entry["fn"](finding)
        except Exception as e:
            result = {"success": False, "message": f"Unexpected error: {e}", "detail": str(e)}

    result["id"]        = fid
    result["title"]     = finding.get("title", fid)
    result["severity"]  = finding.get("severity", "")
    result["timestamp"] = datetime.now().strftime("%H:%M:%S")
    return result


# ── Individual fix implementations ───────────────────────────────────────────

@_reg("WIN001", "Disable SMBv1",
      "Disables the SMBv1 protocol exploited by WannaCry and NotPetya ransomware.")
def _fix_smb1(f):
    # Primary: Windows Optional Feature
    ok, out = _ps(
        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
        "-NoRestart -ErrorAction SilentlyContinue"
    )
    if ok or "RestartNeeded" in out:
        return {"success": True,
                "message": "SMBv1 disabled. A restart may be required to complete the change.",
                "detail":  out}
    # Fallback: SmbServerConfiguration
    ok2, out2 = _ps(
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop"
    )
    if ok2:
        return {"success": True, "message": "SMBv1 disabled via SmbServerConfiguration.", "detail": out2}
    return {"success": False, "message": "Run as Administrator to disable SMBv1.", "detail": out}


@_reg("WIN002", "Enable UAC",
      "Re-enables User Account Control to block silent privilege escalation by malware.")
def _fix_uac(f):
    ok, out = _ps(
        "Set-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name EnableLUA -Value 1 -Type DWord -Force"
    )
    if ok:
        return {"success": True, "message": "UAC enabled. Restart required to take effect.", "detail": out}
    return {"success": False, "message": "Run as Administrator to enable UAC.", "detail": out}


@_reg("WIN002B", "Raise UAC Notification Level",
      "Sets UAC to notify when apps try to make changes (default recommended level).")
def _fix_uac_level(f):
    ok, out = _ps(
        "Set-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force"
    )
    if ok:
        return {"success": True, "message": "UAC notification level set to 'Notify on app changes'.", "detail": out}
    return {"success": False, "message": "Run as Administrator to change UAC level.", "detail": out}


@_reg("WIN003", "Disable AutoPlay / AutoRun",
      "Sets NoDriveTypeAutoRun=255 to prevent USB/optical drives from executing code automatically.")
def _fix_autoplay(f):
    ok, out = _ps(
        "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "-Force -ErrorAction SilentlyContinue | Out-Null; "
        "Set-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "-Name NoDriveTypeAutoRun -Value 255 -Type DWord -Force"
    )
    if ok:
        return {"success": True,
                "message": "AutoPlay disabled for all drive types (NoDriveTypeAutoRun = 255).",
                "detail":  out}
    return {"success": False, "message": "Run as Administrator to disable AutoPlay.", "detail": out}


@_reg("WIN004", "Disable WinRM Service",
      "Stops and disables Windows Remote Management to close the remote PowerShell attack surface.")
def _fix_winrm(f):
    ok, out = _ps(
        "Stop-Service WinRM -Force -ErrorAction SilentlyContinue; "
        "Set-Service WinRM -StartupType Disabled -ErrorAction Stop"
    )
    if ok:
        return {"success": True, "message": "WinRM service stopped and disabled.", "detail": out}
    return {"success": False, "message": "Run as Administrator to disable WinRM.", "detail": out}


@_reg("WIN005", "Enable RDP Network Level Authentication",
      "Requires pre-authentication before the login screen appears, blocking BlueKeep-style attacks.")
def _fix_rdp_nla(f):
    ok, out = _ps(
        "Set-ItemProperty "
        "-Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name UserAuthenticationRequired -Value 1 -Type DWord -Force"
    )
    if ok:
        return {"success": True, "message": "RDP NLA enabled — pre-authentication now required.", "detail": out}
    return {"success": False, "message": "Run as Administrator to enable RDP NLA.", "detail": out}


@_reg("WIN009", "Re-enable Windows Update Service",
      "Restores automatic security patch delivery so the system stays protected against known CVEs.")
def _fix_windows_update(f):
    ok, out = _ps(
        "Set-Service wuauserv -StartupType Automatic -ErrorAction Stop; "
        "Start-Service wuauserv -ErrorAction SilentlyContinue"
    )
    if ok:
        return {"success": True, "message": "Windows Update service set to Automatic and started.", "detail": out}
    return {"success": False, "message": "Run as Administrator to re-enable Windows Update.", "detail": out}


@_reg("WIN010", "Enable Screen Lock (5-minute timeout)",
      "Activates screen saver lock after 5 minutes of inactivity with password required on resume.",
      needs_admin=False)
def _fix_screen_lock(f):
    ok, out = _ps(
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value '300' -Force; "
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -Value '1' -Force; "
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveActive   -Value '1' -Force"
    )
    if ok:
        return {"success": True,
                "message": "Screen lock configured: 5-minute timeout with password required.",
                "detail":  out}
    return {"success": False, "message": "Failed to configure screen lock.", "detail": out}


@_reg("WIN010B", "Require Password on Screen Lock Resume",
      "Ensures the screen saver demands a password when the session resumes.",
      needs_admin=False)
def _fix_screen_lock_pw(f):
    ok, out = _ps(
        "Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -Value '1' -Force"
    )
    if ok:
        return {"success": True, "message": "Password-on-resume enabled for screen saver.", "detail": out}
    return {"success": False, "message": "Failed to set screen lock password requirement.", "detail": out}


@_reg("WIN011", "Disable LLMNR",
      "Disables LLMNR multicast name resolution, removing the attack vector used by Responder to steal credentials.")
def _fix_llmnr(f):
    ok, out = _ps(
        "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "-Force -ErrorAction SilentlyContinue | Out-Null; "
        "Set-ItemProperty "
        "-Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "-Name EnableMulticast -Value 0 -Type DWord -Force"
    )
    if ok:
        return {"success": True, "message": "LLMNR disabled via Group Policy registry key.", "detail": out}
    return {"success": False, "message": "Run as Administrator to disable LLMNR.", "detail": out}


@_reg("WIN012", "Restrict PowerShell Execution Policy",
      "Changes execution policy from Unrestricted/Bypass to RemoteSigned, blocking unsigned attack scripts.")
def _fix_ps_policy(f):
    ok, out = _ps(
        "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned "
        "-Scope LocalMachine -Force -ErrorAction Stop"
    )
    if ok:
        return {"success": True, "message": "PowerShell execution policy set to RemoteSigned.", "detail": out}
    return {"success": False, "message": "Run as Administrator to change execution policy.", "detail": out}


@_reg("WIN013", "Expand Event Log Size to 200 MB",
      "Increases Security, System, and Application logs to 200 MB to preserve forensic evidence longer.")
def _fix_event_log(f):
    all_ok  = True
    results = []
    for log in ["Security", "System", "Application"]:
        ok, out = _ps(f"wevtutil sl {log} /ms:209715200")
        if not ok:
            all_ok = False
        results.append(f"{log}: {'OK' if ok else out[:60]}")
    detail = "\n".join(results)
    if all_ok:
        return {"success": True, "message": "Event logs expanded to 200 MB each (Security, System, Application).", "detail": detail}
    return {"success": False, "message": "Some log sizes could not be changed — run as Administrator.", "detail": detail}


@_reg("FW001", "Enable Windows Firewall (All Profiles)",
      "Turns on Windows Defender Firewall for Domain, Private, and Public profiles.")
def _fix_firewall(f):
    ok, out = _ps("netsh advfirewall set allprofiles state on")
    if ok or "Ok." in out:
        return {"success": True, "message": "Windows Firewall enabled on all profiles.", "detail": out}
    return {"success": False, "message": "Run as Administrator to enable the firewall.", "detail": out}


@_reg("AV002", "Enable Windows Defender Real-Time Protection",
      "Turns real-time scanning back on so Defender actively blocks malware as it runs.")
def _fix_av_realtime(f):
    ok, out = _ps("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop")
    if ok:
        return {"success": True, "message": "Windows Defender real-time protection enabled.", "detail": out}
    return {"success": False, "message": "Run as Administrator to enable Defender real-time protection.", "detail": out}


@_reg("AV003", "Update Windows Defender Signatures",
      "Downloads the latest virus definitions so Defender detects current threats.")
def _fix_av_signatures(f):
    ok, out = _ps("Update-MpSignature -ErrorAction Stop", timeout=120)
    if ok:
        return {"success": True, "message": "Windows Defender signatures updated successfully.", "detail": out}
    return {"success": False, "message": "Signature update failed — check network connectivity.", "detail": out}
