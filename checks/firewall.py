"""Firewall status checks — Windows and Linux."""

import platform
import subprocess
from typing import Any


def check_firewall() -> list[dict[str, Any]]:
    system = platform.system()
    if system == "Windows":
        return _check_windows_firewall()
    return _check_linux_firewall()


def _check_windows_firewall() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    profiles_disabled: list[str] = []
    profiles_enabled: list[str] = []

    try:
        out = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, text=True, timeout=15
        )
        current_profile = ""
        for line in out.stdout.splitlines():
            line = line.strip()
            if "Profile Settings" in line:
                current_profile = line.split()[0]
            elif "State" in line and current_profile:
                if "OFF" in line.upper():
                    profiles_disabled.append(current_profile)
                elif "ON" in line.upper():
                    profiles_enabled.append(current_profile)
    except Exception as e:
        findings.append({
            "id": "FW000",
            "title": "Firewall Check Failed",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"Could not query firewall status: {e}",
            "evidence": str(e),
            "recommendation": "Run the scan with Administrator privileges.",
            "fix": "Re-run SentinelScan as Administrator.",
            "category": "Firewall",
        })
        return findings

    if profiles_disabled:
        findings.append({
            "id": "FW001",
            "title": "Windows Firewall Disabled",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                f"Windows Firewall is disabled for profile(s): {', '.join(profiles_disabled)}. "
                "This leaves the system exposed to unauthorized network access."
            ),
            "evidence": f"Disabled profiles: {', '.join(profiles_disabled)}",
            "recommendation": "Enable Windows Firewall on all profiles immediately.",
            "fix": "Run: netsh advfirewall set allprofiles state on",
            "category": "Firewall",
        })

    if profiles_enabled:
        findings.append({
            "id": "FW002",
            "title": "Windows Firewall Active",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"Firewall is enabled on: {', '.join(profiles_enabled)}.",
            "evidence": f"Enabled profiles: {', '.join(profiles_enabled)}",
            "recommendation": "Maintain current configuration.",
            "fix": "No action required.",
            "category": "Firewall",
        })

    # Check if any profile has broad inbound allow rules
    try:
        out = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "dir=in", "action=allow"],
            capture_output=True, text=True, timeout=20
        )
        rule_count = out.stdout.count("Rule Name:")
        if rule_count > 100:
            findings.append({
                "id": "FW003",
                "title": "Excessive Inbound Firewall Rules",
                "severity": "Medium",
                "score_deduction": 5,
                "description": (
                    f"Found {rule_count} inbound allow rules. A large number of allow rules "
                    "increases attack surface."
                ),
                "evidence": f"{rule_count} inbound allow rules detected.",
                "recommendation": "Review and prune unnecessary inbound firewall rules.",
                "fix": "Open Windows Defender Firewall > Advanced Settings and review inbound rules.",
                "category": "Firewall",
            })
    except Exception:
        pass

    return findings


def _check_linux_firewall() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    firewall_active = False

    # Check ufw
    try:
        out = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, timeout=10
        )
        if "active" in out.stdout.lower():
            firewall_active = True
            findings.append({
                "id": "FW002",
                "title": "UFW Firewall Active",
                "severity": "Info",
                "score_deduction": 0,
                "description": "UFW firewall is active and running.",
                "evidence": out.stdout.strip(),
                "recommendation": "Maintain current configuration.",
                "fix": "No action required.",
                "category": "Firewall",
            })
    except FileNotFoundError:
        pass

    # Check iptables
    if not firewall_active:
        try:
            out = subprocess.run(
                ["iptables", "-L", "-n"], capture_output=True, text=True, timeout=10
            )
            if "ACCEPT" in out.stdout or "DROP" in out.stdout:
                firewall_active = True
        except Exception:
            pass

    if not firewall_active:
        findings.append({
            "id": "FW001",
            "title": "No Active Firewall Detected",
            "severity": "High",
            "score_deduction": 10,
            "description": "No active firewall (UFW or iptables) was detected on this system.",
            "evidence": "ufw not active; iptables rules empty or not accessible.",
            "recommendation": "Enable and configure a firewall immediately.",
            "fix": "Run: sudo ufw enable && sudo ufw default deny incoming",
            "category": "Firewall",
        })

    return findings
