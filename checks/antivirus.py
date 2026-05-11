"""Antivirus and security software checks."""

import platform
import subprocess
import json
from typing import Any


def check_antivirus() -> list[dict[str, Any]]:
    system = platform.system()
    if system == "Windows":
        return _check_windows_antivirus()
    return _check_linux_antivirus()


def _check_windows_antivirus() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    av_found = False
    real_time_enabled = False
    signatures_current = True

    # Query Windows Security Center via PowerShell / WMI
    ps_cmd = (
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "-ErrorAction SilentlyContinue | "
        "Select-Object displayName, productState | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20
        )
        raw = out.stdout.strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]

            for av in data:
                name = av.get("displayName", "Unknown AV")
                state = av.get("productState", 0)

                # productState is a hex-encoded integer
                # Bit 12 = real-time protection: 1=on, 0=off
                # Bit 4 = signatures: 0=up-to-date, 1=out-of-date
                if isinstance(state, int):
                    state_hex = f"{state:06x}"
                    real_time_bits = state_hex[2:4]
                    sig_bits = state_hex[4:6]
                    rt_on = real_time_bits in ("10", "11")
                    sigs_ok = sig_bits == "00"
                else:
                    rt_on = True
                    sigs_ok = True

                av_found = True
                if rt_on:
                    real_time_enabled = True
                if not sigs_ok:
                    signatures_current = False

                findings.append({
                    "id": "AV000",
                    "title": f"Antivirus Detected: {name}",
                    "severity": "Info",
                    "score_deduction": 0,
                    "description": (
                        f"{name} is installed. "
                        f"Real-time protection: {'On' if rt_on else 'Off'}. "
                        f"Signatures: {'Current' if sigs_ok else 'Out-of-date'}."
                    ),
                    "evidence": f"productState: {state}",
                    "recommendation": "Keep antivirus updated and real-time protection enabled.",
                    "fix": "No action required." if rt_on and sigs_ok else "Update virus definitions.",
                    "category": "Antivirus",
                })

                if not rt_on:
                    findings.append({
                        "id": "AV002",
                        "title": f"Real-Time Protection Disabled ({name})",
                        "severity": "High",
                        "score_deduction": 10,
                        "description": (
                            f"Real-time protection is disabled for {name}. "
                            "The system is not actively monitoring for malware."
                        ),
                        "evidence": f"productState: {state}",
                        "recommendation": "Enable real-time protection in your antivirus software.",
                        "fix": f"Open {name} and enable real-time/on-access scanning.",
                        "category": "Antivirus",
                    })

                if not sigs_ok:
                    findings.append({
                        "id": "AV003",
                        "title": f"Antivirus Signatures Out-of-Date ({name})",
                        "severity": "Medium",
                        "score_deduction": 5,
                        "description": (
                            f"Virus definitions for {name} are out of date. "
                            "New threats may not be detected."
                        ),
                        "evidence": f"productState signature bits: {state}",
                        "recommendation": "Update virus definitions immediately.",
                        "fix": f"Open {name} and trigger a definition update.",
                        "category": "Antivirus",
                    })

    except Exception:
        pass

    # Windows Defender specific check
    ps_defender = (
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object AMRunningMode, RealTimeProtectionEnabled, AntivirusSignatureAge | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_defender],
            capture_output=True, text=True, timeout=20
        )
        raw = out.stdout.strip()
        if raw:
            defender = json.loads(raw)
            av_found = True
            rt = defender.get("RealTimeProtectionEnabled", True)
            sig_age = defender.get("AntivirusSignatureAge", 0) or 0

            if not rt and not any(f["id"] == "AV002" for f in findings):
                findings.append({
                    "id": "AV002",
                    "title": "Windows Defender Real-Time Protection Disabled",
                    "severity": "High",
                    "score_deduction": 10,
                    "description": "Windows Defender real-time protection is disabled.",
                    "evidence": f"RealTimeProtectionEnabled: {rt}",
                    "recommendation": "Enable real-time protection in Windows Security.",
                    "fix": "Open Windows Security > Virus & threat protection > Manage settings > Enable real-time protection.",
                    "category": "Antivirus",
                })
            if sig_age > 7 and not any(f["id"] == "AV003" for f in findings):
                findings.append({
                    "id": "AV003",
                    "title": "Windows Defender Signatures Outdated",
                    "severity": "Medium",
                    "score_deduction": 5,
                    "description": f"Defender signatures are {sig_age} days old.",
                    "evidence": f"AntivirusSignatureAge: {sig_age} days",
                    "recommendation": "Update Windows Defender definitions.",
                    "fix": "Run: Update-MpSignature in PowerShell, or use Windows Security app.",
                    "category": "Antivirus",
                })
    except Exception:
        pass

    if not av_found:
        findings.append({
            "id": "AV001",
            "title": "No Antivirus Software Detected",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "No antivirus product was found in the Windows Security Center. "
                "The system is unprotected against malware."
            ),
            "evidence": "SecurityCenter2 AntiVirusProduct query returned no results.",
            "recommendation": "Install a reputable antivirus solution immediately.",
            "fix": "Enable Windows Defender or install a third-party antivirus.",
            "category": "Antivirus",
        })

    return findings


def _check_linux_antivirus() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    av_found = False

    for tool in ["clamav", "clamscan", "freshclam", "rkhunter", "chkrootkit"]:
        try:
            out = subprocess.run(
                ["which", tool], capture_output=True, text=True, timeout=5
            )
            if out.returncode == 0:
                av_found = True
                findings.append({
                    "id": "AV000",
                    "title": f"Security Tool Found: {tool}",
                    "severity": "Info",
                    "score_deduction": 0,
                    "description": f"{tool} is installed.",
                    "evidence": out.stdout.strip(),
                    "recommendation": "Keep definitions updated.",
                    "fix": "Run regular scans and keep definitions current.",
                    "category": "Antivirus",
                })
        except Exception:
            pass

    if not av_found:
        findings.append({
            "id": "AV001",
            "title": "No Antivirus / Rootkit Scanner Detected",
            "severity": "High",
            "score_deduction": 10,
            "description": "No antivirus or rootkit detection tool found.",
            "evidence": "clamav, rkhunter, chkrootkit not found in PATH.",
            "recommendation": "Install ClamAV or rkhunter.",
            "fix": "Run: sudo apt install clamav rkhunter",
            "category": "Antivirus",
        })

    return findings
