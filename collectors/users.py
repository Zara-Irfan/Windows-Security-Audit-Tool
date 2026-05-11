"""User and account information collector."""

import platform
import subprocess
from typing import Any


def collect_users() -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _collect_windows_users()
    return _collect_unix_users()


def _collect_windows_users() -> dict[str, Any]:
    result: dict[str, Any] = {
        "local_users": [],
        "admin_users": [],
        "guest_enabled": False,
        "password_policy": {},
        "inactive_accounts": [],
    }

    # Local users via net user
    try:
        out = subprocess.run(
            ["net", "user"], capture_output=True, text=True, timeout=15
        )
        lines = out.stdout.splitlines()
        users: list[str] = []
        collecting = False
        for line in lines:
            if "---" in line:
                collecting = True
                continue
            if collecting and line.strip() and "The command" not in line:
                users.extend(line.split())
        result["local_users"] = [u for u in users if u]
    except Exception:
        pass

    # Admin group members
    try:
        out = subprocess.run(
            ["net", "localgroup", "Administrators"],
            capture_output=True, text=True, timeout=15
        )
        admins: list[str] = []
        collecting = False
        for line in out.stdout.splitlines():
            if "---" in line:
                collecting = True
                continue
            if collecting and line.strip() and "The command" not in line:
                admins.append(line.strip())
        result["admin_users"] = [a for a in admins if a]
    except Exception:
        pass

    # Guest account status
    try:
        out = subprocess.run(
            ["net", "user", "Guest"], capture_output=True, text=True, timeout=10
        )
        result["guest_enabled"] = "Account active               Yes" in out.stdout
    except Exception:
        pass

    # Password policy via net accounts
    try:
        out = subprocess.run(
            ["net", "accounts"], capture_output=True, text=True, timeout=10
        )
        policy: dict[str, str] = {}
        for line in out.stdout.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                policy[key.strip()] = val.strip()
        result["password_policy"] = policy
    except Exception:
        pass

    # Inactive accounts (never logged in or disabled) via PowerShell
    try:
        ps_cmd = (
            "Get-LocalUser | Select-Object Name,Enabled,LastLogon | "
            "ConvertTo-Json -Compress"
        )
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20
        )
        import json
        raw = out.stdout.strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            inactive = [
                u["Name"] for u in data
                if not u.get("Enabled") or u.get("LastLogon") is None
            ]
            result["inactive_accounts"] = inactive
    except Exception:
        pass

    return result


def _collect_unix_users() -> dict[str, Any]:
    import pwd
    import grp

    result: dict[str, Any] = {
        "local_users": [],
        "admin_users": [],
        "guest_enabled": False,
        "password_policy": {},
        "inactive_accounts": [],
    }

    try:
        all_users = [p.pw_name for p in pwd.getpwall() if p.pw_uid >= 1000 or p.pw_name == "root"]
        result["local_users"] = all_users
    except Exception:
        pass

    try:
        sudo_group = grp.getgrnam("sudo")
        result["admin_users"] = list(sudo_group.gr_mem)
    except Exception:
        try:
            wheel_group = grp.getgrnam("wheel")
            result["admin_users"] = list(wheel_group.gr_mem)
        except Exception:
            pass

    try:
        guest = pwd.getpwnam("guest")
        result["guest_enabled"] = True
    except KeyError:
        result["guest_enabled"] = False
    except Exception:
        pass

    return result
