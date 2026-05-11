"""Startup entry and running process audit — detection only, no termination."""

import platform
import subprocess
import json
import os
from typing import Any

import psutil


SUSPICIOUS_KEYWORDS: list[str] = [
    "mimikatz", "meterpreter", "empire", "cobalt", "beacon", "payload",
    "nc.exe", "netcat", "ncat", "psexec", "wce.exe", "fgdump", "pwdump",
    "keylogger", "keylog", "inject", "shellcode", "cryptominer", "miner",
    "xmrig", "torrent", "rat.exe", "trojan", "backdoor",
]

SUSPICIOUS_LOCATIONS: list[str] = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\desktop\\",
]


def check_startup() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    system = platform.system()

    startup_entries = _get_startup_entries(system)
    suspicious_startup = _flag_suspicious_entries(startup_entries)

    if suspicious_startup:
        findings.append({
            "id": "STARTUP001",
            "title": f"Suspicious Startup Entries Detected ({len(suspicious_startup)})",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "One or more startup entries contain suspicious keywords or run from "
                "unusual locations. These should be investigated immediately."
            ),
            "evidence": "; ".join(
                f"{e.get('name','?')} → {e.get('command','?')}" for e in suspicious_startup[:3]
            ),
            "recommendation": "Investigate and remove any unknown or suspicious startup items.",
            "fix": "Use Task Manager > Startup tab or Autoruns (Sysinternals) to review entries.",
            "category": "Startup",
        })

    if startup_entries and not suspicious_startup:
        findings.append({
            "id": "STARTUP000",
            "title": f"Startup Entries Reviewed ({len(startup_entries)} found)",
            "severity": "Info",
            "score_deduction": 0,
            "description": f"{len(startup_entries)} startup entries found; no obviously suspicious items detected.",
            "evidence": f"Startup count: {len(startup_entries)}",
            "recommendation": "Periodically review startup programs to keep the list minimal.",
            "fix": "Remove unnecessary startup programs via Task Manager > Startup.",
            "category": "Startup",
        })

    # Scheduled tasks audit (Windows)
    if system == "Windows":
        task_findings = _check_scheduled_tasks()
        findings.extend(task_findings)

    # Running processes audit
    process_findings = _audit_processes()
    findings.extend(process_findings)

    return findings


def _get_startup_entries(system: str) -> list[dict]:
    entries: list[dict] = []

    if system == "Windows":
        # Registry run keys via PowerShell
        ps_cmd = (
            "$paths = @("
            "  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "  'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'"
            "); "
            "$result = @(); "
            "foreach ($p in $paths) { "
            "  if (Test-Path $p) { "
            "    $props = Get-ItemProperty $p -ErrorAction SilentlyContinue; "
            "    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | "
            "    ForEach-Object { $result += [PSCustomObject]@{Name=$_.Name; Command=$_.Value; Location=$p} } "
            "  } "
            "}; "
            "$result | ConvertTo-Json -Compress"
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
                entries = [{"name": d.get("Name", ""), "command": d.get("Command", ""), "location": d.get("Location", "")} for d in data]
        except Exception:
            pass

        # Startup folder
        startup_dirs = [
            os.path.join(os.environ.get("APPDATA", ""), "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            os.path.join(os.environ.get("PROGRAMDATA", ""), "Microsoft\\Windows\\Start Menu\\Programs\\StartUp"),
        ]
        for sd in startup_dirs:
            if os.path.isdir(sd):
                try:
                    for item in os.listdir(sd):
                        if not item.startswith("."):
                            entries.append({"name": item, "command": os.path.join(sd, item), "location": sd})
                except Exception:
                    pass
    else:
        # systemd services
        try:
            out = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=enabled", "--no-pager", "--plain"],
                capture_output=True, text=True, timeout=15
            )
            for line in out.stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(".service"):
                    entries.append({"name": parts[0], "command": "", "location": "systemd"})
        except Exception:
            pass

    return entries


def _flag_suspicious_entries(entries: list[dict]) -> list[dict]:
    suspicious: list[dict] = []
    for entry in entries:
        cmd_lower = (entry.get("command") or "").lower()
        name_lower = (entry.get("name") or "").lower()
        combined = cmd_lower + " " + name_lower

        if any(kw in combined for kw in SUSPICIOUS_KEYWORDS):
            suspicious.append(entry)
            continue

        if any(loc in cmd_lower for loc in SUSPICIOUS_LOCATIONS):
            suspicious.append(entry)

    return suspicious


def _check_scheduled_tasks() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    ps_cmd = (
        "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | "
        "Select-Object TaskName, TaskPath, @{N='Actions';E={$_.Actions.Execute -join ';'}} | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        raw = out.stdout.strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]

            suspicious_tasks = []
            for task in data:
                actions = (task.get("Actions") or "").lower()
                name = (task.get("TaskName") or "").lower()
                if any(kw in actions or kw in name for kw in SUSPICIOUS_KEYWORDS):
                    suspicious_tasks.append(task)
                elif any(loc in actions for loc in SUSPICIOUS_LOCATIONS):
                    suspicious_tasks.append(task)

            if suspicious_tasks:
                findings.append({
                    "id": "TASK001",
                    "title": f"Suspicious Scheduled Tasks ({len(suspicious_tasks)})",
                    "severity": "High",
                    "score_deduction": 10,
                    "description": "Scheduled tasks with suspicious names or actions detected.",
                    "evidence": "; ".join(t.get("TaskName", "") for t in suspicious_tasks[:3]),
                    "recommendation": "Review and disable suspicious scheduled tasks.",
                    "fix": "Open Task Scheduler and investigate flagged tasks.",
                    "category": "Startup",
                })
    except Exception:
        pass

    return findings


def _audit_processes() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    suspicious_procs: list[str] = []

    try:
        for proc in psutil.process_iter(["name", "exe", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                exe = (proc.info.get("exe") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                combined = f"{name} {exe} {cmdline}"

                if any(kw in combined for kw in SUSPICIOUS_KEYWORDS):
                    suspicious_procs.append(proc.info.get("name", "unknown"))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass

    if suspicious_procs:
        findings.append({
            "id": "PROC001",
            "title": f"Suspicious Running Processes ({len(suspicious_procs)})",
            "severity": "Critical",
            "score_deduction": 15,
            "description": (
                "Running processes matching known malicious tool names were detected. "
                "Investigate immediately — do NOT terminate without forensic recording."
            ),
            "evidence": f"Processes: {', '.join(set(suspicious_procs[:5]))}",
            "recommendation": "Investigate flagged processes. Do not terminate before recording evidence.",
            "fix": "Document process details (PID, path, parent) before taking action.",
            "category": "Processes",
        })
    else:
        findings.append({
            "id": "PROC000",
            "title": "No Suspicious Processes Detected",
            "severity": "Info",
            "score_deduction": 0,
            "description": "Running processes were scanned; no matches for known malicious tool names.",
            "evidence": f"Scanned {sum(1 for _ in psutil.process_iter())} running processes.",
            "recommendation": "Continue periodic process monitoring.",
            "fix": "No action required.",
            "category": "Processes",
        })

    return findings
