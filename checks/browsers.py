"""Browser security checks — version detection and risky settings."""

import os
import platform
import json
import subprocess
from pathlib import Path
from typing import Any


BROWSER_PATHS_WINDOWS: dict[str, list[Path]] = {
    "Chrome": [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ],
    "Firefox": [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Mozilla Firefox/firefox.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Mozilla Firefox/firefox.exe",
    ],
    "Edge": [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
    ],
    "Brave": [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "BraveSoftware/Brave-Browser/Application/brave.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/Application/brave.exe",
    ],
    "Opera": [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Opera/opera.exe",
    ],
}

BROWSER_PATHS_LINUX: dict[str, list[str]] = {
    "Chrome": ["/usr/bin/google-chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium"],
    "Firefox": ["/usr/bin/firefox"],
    "Brave": ["/usr/bin/brave-browser"],
}


def check_browsers() -> list[dict[str, Any]]:
    system = platform.system()
    findings: list[dict[str, Any]] = []
    browsers_found: list[dict] = []

    if system == "Windows":
        browsers_found = _detect_browsers_windows()
    else:
        browsers_found = _detect_browsers_linux()

    if not browsers_found:
        findings.append({
            "id": "BR000",
            "title": "No Common Browsers Detected",
            "severity": "Info",
            "score_deduction": 0,
            "description": "No common web browsers were found in standard installation locations.",
            "evidence": "Checked standard browser paths.",
            "recommendation": "Ensure browsers are kept updated manually.",
            "fix": "No action required.",
            "category": "Browser",
        })
        return findings

    for browser in browsers_found:
        name = browser["name"]
        version = browser["version"]
        path = browser["path"]

        findings.append({
            "id": f"BR_INFO_{name[:2].upper()}",
            "title": f"Browser Detected: {name} {version}",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"{name} version {version} is installed at {path}.",
            "evidence": f"Path: {path}",
            "recommendation": "Keep browser updated to the latest version.",
            "fix": "Update via browser menu or system package manager.",
            "category": "Browser",
        })

    # Check Chrome saved passwords flag (Windows — preference file)
    if system == "Windows":
        chrome_prefs = _get_chrome_prefs_windows()
        if chrome_prefs:
            pw_saving = chrome_prefs.get("credentials_enable_service", True)
            if pw_saving:
                findings.append({
                    "id": "BR002",
                    "title": "Chrome Password Saving Enabled",
                    "severity": "Low",
                    "score_deduction": 2,
                    "description": (
                        "Chrome is configured to save passwords. "
                        "Saved passwords can be extracted by malware or unauthorized users."
                    ),
                    "evidence": "credentials_enable_service: true in Chrome Preferences",
                    "recommendation": "Use a dedicated password manager instead.",
                    "fix": "Chrome > Settings > Autofill > Passwords > Disable 'Offer to save passwords'.",
                    "category": "Browser",
                })

            # Check for dangerous flags
            autocomplete_off = chrome_prefs.get("profile", {}).get("password_manager_leak_detection", False)
            if not autocomplete_off:
                pass  # Normal state, not a finding

    return findings


def _detect_browsers_windows() -> list[dict]:
    found: list[dict] = []
    for browser_name, paths in BROWSER_PATHS_WINDOWS.items():
        for p in paths:
            if p.exists():
                version = _get_file_version_windows(str(p))
                found.append({"name": browser_name, "version": version, "path": str(p)})
                break
    return found


def _get_file_version_windows(path: str) -> str:
    try:
        ps_cmd = (
            f"(Get-Item '{path}' -ErrorAction SilentlyContinue).VersionInfo.FileVersion"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        version = out.stdout.strip()
        return version if version else "Unknown"
    except Exception:
        return "Unknown"


def _detect_browsers_linux() -> list[dict]:
    found: list[dict] = []
    for browser_name, paths in BROWSER_PATHS_LINUX.items():
        for path in paths:
            if os.path.exists(path):
                try:
                    out = subprocess.run(
                        [path, "--version"], capture_output=True, text=True, timeout=10
                    )
                    version = out.stdout.strip().split()[-1] if out.stdout.strip() else "Unknown"
                except Exception:
                    version = "Unknown"
                found.append({"name": browser_name, "version": version, "path": path})
                break
    return found


def _get_chrome_prefs_windows() -> dict | None:
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    prefs_path = Path(local_app_data) / "Google/Chrome/User Data/Default/Preferences"
    if not prefs_path.exists():
        return None
    try:
        with open(prefs_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
