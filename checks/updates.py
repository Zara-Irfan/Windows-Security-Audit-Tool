"""Operating system update and patch checks."""

import platform
import subprocess
import json
from typing import Any


def check_updates() -> list[dict[str, Any]]:
    system = platform.system()
    if system == "Windows":
        return _check_windows_updates()
    return _check_linux_updates()


def _check_windows_updates() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Check pending updates via Windows Update COM / PowerShell
    ps_cmd = (
        "$Session = New-Object -ComObject Microsoft.Update.Session; "
        "$Searcher = $Session.CreateUpdateSearcher(); "
        "try { "
        "  $Result = $Searcher.Search('IsInstalled=0 and Type=\\'Software\\''); "
        "  $updates = $Result.Updates | ForEach-Object { "
        "    [PSCustomObject]@{ Title=$_.Title; Severity=if($_.MsrcSeverity){$_.MsrcSeverity}else{'Unknown'} } "
        "  }; "
        "  $updates | ConvertTo-Json -Compress "
        "} catch { Write-Output '[]' }"
    )

    pending_updates: list[dict] = []
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
        raw = out.stdout.strip()
        if raw and raw != "[]":
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            pending_updates = data
    except Exception:
        pass

    if not pending_updates:
        # Fallback: check Windows Update history for last update date
        ps_history = (
            "$Session = New-Object -ComObject Microsoft.Update.Session; "
            "$Searcher = $Session.CreateUpdateSearcher(); "
            "try { "
            "  $count = $Searcher.GetTotalHistoryCount(); "
            "  if ($count -gt 0) { "
            "    $last = $Searcher.QueryHistory(0, 1); "
            "    $last[0].Date.ToString('yyyy-MM-dd') "
            "  } else { 'Unknown' } "
            "} catch { 'Unknown' }"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_history],
                capture_output=True, text=True, timeout=30
            )
            last_date = out.stdout.strip()
            findings.append({
                "id": "OS000",
                "title": "System Appears Up-to-Date",
                "severity": "Info",
                "score_deduction": 0,
                "description": f"No pending updates found. Last update: {last_date}.",
                "evidence": f"Last update date: {last_date}",
                "recommendation": "Continue to apply updates regularly.",
                "fix": "No action required.",
                "category": "Updates",
            })
        except Exception:
            findings.append({
                "id": "OS000",
                "title": "Update Status Unknown",
                "severity": "Info",
                "score_deduction": 0,
                "description": "Could not determine update status (may require elevated permissions).",
                "evidence": "Windows Update COM query returned no data.",
                "recommendation": "Check Windows Update manually.",
                "fix": "Open Settings > Windows Update and check for updates.",
                "category": "Updates",
            })
        return findings

    # Categorize by severity
    critical = [u for u in pending_updates if "Critical" in (u.get("Severity") or "")]
    important = [u for u in pending_updates if "Important" in (u.get("Severity") or "")]
    other = [u for u in pending_updates if u not in critical and u not in important]

    if critical:
        findings.append({
            "id": "OS001",
            "title": f"Critical Security Updates Missing ({len(critical)})",
            "severity": "Critical",
            "score_deduction": 15,
            "description": (
                f"{len(critical)} critical update(s) are pending installation. "
                "Critical patches fix actively exploited vulnerabilities."
            ),
            "evidence": "; ".join(u.get("Title", "") for u in critical[:5]),
            "recommendation": "Install critical updates immediately.",
            "fix": "Run Windows Update or: wuauclt /detectnow /updatenow",
            "category": "Updates",
        })

    if important:
        findings.append({
            "id": "OS002",
            "title": f"Important Updates Pending ({len(important)})",
            "severity": "High",
            "score_deduction": 10,
            "description": f"{len(important)} important update(s) are pending.",
            "evidence": "; ".join(u.get("Title", "") for u in important[:5]),
            "recommendation": "Install important updates soon.",
            "fix": "Open Settings > Windows Update > Check for updates.",
            "category": "Updates",
        })

    if other:
        findings.append({
            "id": "OS003",
            "title": f"Optional Updates Available ({len(other)})",
            "severity": "Low",
            "score_deduction": 2,
            "description": f"{len(other)} optional update(s) are available.",
            "evidence": f"{len(other)} optional updates pending.",
            "recommendation": "Review and install optional updates as appropriate.",
            "fix": "Open Settings > Windows Update > View optional updates.",
            "category": "Updates",
        })

    return findings


def _check_linux_updates() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # apt-based
    try:
        subprocess.run(
            ["apt-get", "-qq", "update"],
            capture_output=True, text=True, timeout=60
        )
        out = subprocess.run(
            ["apt-get", "--simulate", "upgrade"],
            capture_output=True, text=True, timeout=30
        )
        upgradable = [l for l in out.stdout.splitlines() if l.startswith("Inst ")]
        security_updates = [l for l in upgradable if "security" in l.lower()]

        if security_updates:
            findings.append({
                "id": "OS001",
                "title": f"Security Updates Pending ({len(security_updates)})",
                "severity": "High",
                "score_deduction": 10,
                "description": f"{len(security_updates)} security update(s) available.",
                "evidence": "\n".join(security_updates[:5]),
                "recommendation": "Install security updates immediately.",
                "fix": "Run: sudo apt-get upgrade -y",
                "category": "Updates",
            })
        elif upgradable:
            findings.append({
                "id": "OS002",
                "title": f"System Updates Available ({len(upgradable)})",
                "severity": "Medium",
                "score_deduction": 5,
                "description": f"{len(upgradable)} package update(s) available.",
                "evidence": f"{len(upgradable)} packages can be upgraded.",
                "recommendation": "Keep system packages up to date.",
                "fix": "Run: sudo apt-get update && sudo apt-get upgrade",
                "category": "Updates",
            })
        else:
            findings.append({
                "id": "OS000",
                "title": "System Packages Up-to-Date",
                "severity": "Info",
                "score_deduction": 0,
                "description": "All packages are up to date.",
                "evidence": "apt-get simulate upgrade returned no upgradable packages.",
                "recommendation": "Continue updating regularly.",
                "fix": "No action required.",
                "category": "Updates",
            })
    except FileNotFoundError:
        findings.append({
            "id": "OS000",
            "title": "Update Check Not Applicable",
            "severity": "Info",
            "score_deduction": 0,
            "description": "apt-get not found; update check skipped for non-Debian systems.",
            "evidence": "apt-get not in PATH.",
            "recommendation": "Use your system's package manager to check for updates.",
            "fix": "Run your package manager update command.",
            "category": "Updates",
        })
    except Exception as e:
        findings.append({
            "id": "OS000",
            "title": "Update Check Failed",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"Could not check for updates: {e}",
            "evidence": str(e),
            "recommendation": "Check for updates manually.",
            "fix": "Run your system's update command with sudo.",
            "category": "Updates",
        })

    return findings
