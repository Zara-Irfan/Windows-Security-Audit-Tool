"""Installed software and startup applications collector."""

import platform
import subprocess
import json
from typing import Any


UNSUPPORTED_SOFTWARE: list[str] = [
    "Windows XP", "Windows Vista", "Windows 7", "Windows 8",
    "Internet Explorer", "Flash Player", "Silverlight", "Java 6", "Java 7",
    "Python 2", "OpenSSL 1.0",
]

DUPLICATE_SECURITY_TOOLS: list[str] = [
    "Norton", "McAfee", "Kaspersky", "Avast", "AVG", "Bitdefender",
    "Malwarebytes", "Windows Defender", "Sophos", "ESET",
]


def collect_software() -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _collect_windows_software()
    return _collect_unix_software()


def _collect_windows_software() -> dict[str, Any]:
    result: dict[str, Any] = {
        "installed": [],
        "startup_apps": [],
        "flagged_unsupported": [],
        "security_tools_found": [],
        "duplicate_security_warning": False,
    }

    # Installed programs via PowerShell (faster than wmic)
    ps_cmd = (
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "-ErrorAction SilentlyContinue | "
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation | "
        "Where-Object { $_.DisplayName -ne $null } | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
        raw = out.stdout.strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            installed = []
            for item in data:
                name = item.get("DisplayName") or ""
                version = item.get("DisplayVersion") or "Unknown"
                publisher = item.get("Publisher") or "Unknown"
                location = item.get("InstallLocation") or ""
                installed.append({
                    "name": name,
                    "version": version,
                    "publisher": publisher,
                    "location": location,
                })
            result["installed"] = installed
    except Exception:
        pass

    # Startup apps via wmic
    try:
        out = subprocess.run(
            ["wmic", "startup", "get", "Caption,Command,Location"],
            capture_output=True, text=True, timeout=20
        )
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        if len(lines) > 1:
            startup = []
            for line in lines[1:]:
                parts = line.split(None, 2)
                if parts:
                    startup.append({"caption": parts[0], "command": parts[-1] if len(parts) > 1 else ""})
            result["startup_apps"] = startup
    except Exception:
        pass

    # Flag unsupported software
    installed_names = [s["name"].lower() for s in result["installed"]]
    for bad in UNSUPPORTED_SOFTWARE:
        if any(bad.lower() in name for name in installed_names):
            result["flagged_unsupported"].append(bad)

    # Security tools count
    found_tools = []
    for tool in DUPLICATE_SECURITY_TOOLS:
        if any(tool.lower() in name for name in installed_names):
            found_tools.append(tool)
    result["security_tools_found"] = found_tools
    result["duplicate_security_warning"] = len(found_tools) > 2

    return result


def _collect_unix_software() -> dict[str, Any]:
    result: dict[str, Any] = {
        "installed": [],
        "startup_apps": [],
        "flagged_unsupported": [],
        "security_tools_found": [],
        "duplicate_security_warning": False,
    }

    # dpkg / rpm
    try:
        out = subprocess.run(
            ["dpkg", "-l"], capture_output=True, text=True, timeout=30
        )
        installed = []
        for line in out.stdout.splitlines():
            if line.startswith("ii"):
                parts = line.split()
                if len(parts) >= 3:
                    installed.append({"name": parts[1], "version": parts[2], "publisher": "", "location": ""})
        result["installed"] = installed
    except FileNotFoundError:
        try:
            out = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
                capture_output=True, text=True, timeout=30
            )
            installed = []
            for line in out.stdout.splitlines():
                parts = line.split()
                if parts:
                    installed.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "", "publisher": "", "location": ""})
            result["installed"] = installed
        except Exception:
            pass
    except Exception:
        pass

    return result
