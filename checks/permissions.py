"""File system permissions audit — world-writable files, insecure directories."""

import os
import platform
import stat
from pathlib import Path
from typing import Any


SENSITIVE_DIRS_WINDOWS: list[str] = [
    os.environ.get("SYSTEMROOT", "C:\\Windows"),
    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
    os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
]

SENSITIVE_DIRS_LINUX: list[str] = [
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/tmp",
    "/var/tmp",
]

SSH_CONFIG_FILES_LINUX: list[str] = [
    "/etc/ssh/sshd_config",
    os.path.expanduser("~/.ssh/authorized_keys"),
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.ssh/id_ed25519"),
]


def check_permissions() -> list[dict[str, Any]]:
    system = platform.system()
    if system == "Windows":
        return _check_windows_permissions()
    return _check_linux_permissions()


def _check_windows_permissions() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Check for world-writable directories in ProgramData / Temp
    world_writable: list[str] = []
    check_dirs = [
        os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
        os.environ.get("TEMP", "C:\\Windows\\Temp"),
        os.environ.get("SYSTEMROOT", "C:\\Windows") + "\\Temp",
    ]

    for check_dir in check_dirs:
        if not os.path.isdir(check_dir):
            continue
        try:
            for entry in os.scandir(check_dir):
                if entry.is_dir(follow_symlinks=False):
                    test_file = os.path.join(entry.path, ".sentinel_write_test")
                    try:
                        with open(test_file, "w") as f:
                            f.write("test")
                        world_writable.append(entry.path)
                    except (PermissionError, OSError):
                        pass
                    finally:
                        try:
                            os.remove(test_file)
                        except OSError:
                            pass
        except (PermissionError, OSError):
            continue

    if world_writable:
        findings.append({
            "id": "PERM001",
            "title": f"World-Writable Directories Found ({len(world_writable)})",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "Directories writable by any user were found in sensitive locations. "
                "These can be used for privilege escalation or malware staging."
            ),
            "evidence": "; ".join(world_writable[:5]),
            "recommendation": "Review and restrict permissions on sensitive directories.",
            "fix": "Use icacls to remove excessive write permissions.",
            "category": "Permissions",
        })

    # Check if temp directories are executable
    temp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")
    if os.path.isdir(temp_dir):
        findings.append({
            "id": "PERM002",
            "title": "Temp Directory Execution Policy",
            "severity": "Info",
            "score_deduction": 0,
            "description": (
                "Verify that execution of binaries from Temp directories is restricted "
                "via Software Restriction Policies or AppLocker."
            ),
            "evidence": f"Temp directory: {temp_dir}",
            "recommendation": "Configure AppLocker to block execution from Temp.",
            "fix": "Open Local Security Policy > Software Restriction Policies or configure AppLocker.",
            "category": "Permissions",
        })

    if not world_writable:
        findings.append({
            "id": "PERM000",
            "title": "No World-Writable Directories Found",
            "severity": "Info",
            "score_deduction": 0,
            "description": "Checked key directories — no obviously world-writable directories found.",
            "evidence": f"Checked: {', '.join(check_dirs)}",
            "recommendation": "Continue regular permission audits.",
            "fix": "No action required.",
            "category": "Permissions",
        })

    return findings


def _check_linux_permissions() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    world_writable: list[str] = []

    for check_dir in SENSITIVE_DIRS_LINUX:
        if not os.path.isdir(check_dir):
            continue
        try:
            for root, dirs, files in os.walk(check_dir, followlinks=False):
                for fname in files[:100]:  # cap scan depth
                    fpath = os.path.join(root, fname)
                    try:
                        file_stat = os.stat(fpath)
                        mode = file_stat.st_mode
                        if mode & stat.S_IWOTH:
                            world_writable.append(fpath)
                    except (OSError, PermissionError):
                        continue
                break  # Only scan top level
        except (OSError, PermissionError):
            continue

    if world_writable:
        findings.append({
            "id": "PERM001",
            "title": f"World-Writable Files Found ({len(world_writable)})",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "Files writable by all users were found in sensitive system directories. "
                "These are potential vectors for privilege escalation."
            ),
            "evidence": "; ".join(world_writable[:5]),
            "recommendation": "Remove world-write permissions from sensitive files.",
            "fix": f"Run: chmod o-w {' '.join(world_writable[:3])}",
            "category": "Permissions",
        })

    # SSH config checks
    ssh_issues: list[str] = []
    for ssh_file in SSH_CONFIG_FILES_LINUX:
        if not os.path.exists(ssh_file):
            continue
        try:
            file_stat = os.stat(ssh_file)
            mode = file_stat.st_mode
            if "id_rsa" in ssh_file or "id_ed25519" in ssh_file:
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    ssh_issues.append(f"{ssh_file} is group/world readable (should be 600)")
            if "authorized_keys" in ssh_file:
                if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                    ssh_issues.append(f"{ssh_file} has group/world write permissions")
        except (OSError, PermissionError):
            continue

    if ssh_issues:
        findings.append({
            "id": "PERM003",
            "title": f"Insecure SSH File Permissions ({len(ssh_issues)})",
            "severity": "High",
            "score_deduction": 10,
            "description": "SSH key files have overly permissive file modes.",
            "evidence": "; ".join(ssh_issues),
            "recommendation": "Fix SSH file permissions immediately.",
            "fix": "chmod 600 ~/.ssh/id_rsa && chmod 700 ~/.ssh",
            "category": "Permissions",
        })

    # /tmp sticky bit check
    try:
        tmp_stat = os.stat("/tmp")
        if not (tmp_stat.st_mode & stat.S_ISVTX):
            findings.append({
                "id": "PERM004",
                "title": "/tmp Missing Sticky Bit",
                "severity": "Medium",
                "score_deduction": 5,
                "description": "/tmp does not have the sticky bit set. Users can delete each other's files.",
                "evidence": f"/tmp mode: {oct(tmp_stat.st_mode)}",
                "recommendation": "Set sticky bit on /tmp.",
                "fix": "Run: chmod +t /tmp",
                "category": "Permissions",
            })
    except Exception:
        pass

    if not findings:
        findings.append({
            "id": "PERM000",
            "title": "No Critical Permission Issues Found",
            "severity": "Info",
            "score_deduction": 0,
            "description": "No obvious world-writable or insecure SSH file permissions detected.",
            "evidence": f"Scanned: {', '.join(SENSITIVE_DIRS_LINUX)}",
            "recommendation": "Run periodic permission audits with tools like Lynis.",
            "fix": "No action required.",
            "category": "Permissions",
        })

    return findings
