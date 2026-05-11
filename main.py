"""Main scan orchestrator — runs all collectors and checks sequentially."""

from __future__ import annotations

import time
from typing import Any, Callable

from collectors import system as sys_collector
from collectors import users as usr_collector
from collectors import software as sw_collector
from collectors import network as net_collector

from checks import firewall, antivirus, updates, ports, browsers, permissions, startup, windows_config
from scoring.engine import calculate_score, count_by_severity, get_priority_fixes
from reporting.history import init_db, save_scan


SCAN_STEPS: list[tuple[str, str]] = [
    ("init",        "Initializing SentinelScan..."),
    ("system",      "Collecting system information..."),
    ("users",       "Analyzing user accounts & password policy..."),
    ("software",    "Scanning installed software..."),
    ("network",     "Checking network configuration..."),
    ("firewall",    "Auditing firewall settings..."),
    ("antivirus",   "Checking antivirus protection..."),
    ("updates",     "Scanning for OS updates..."),
    ("browsers",    "Analyzing browser security..."),
    ("permissions", "Auditing file permissions..."),
    ("startup",     "Reviewing startup & processes..."),
    ("winconfig",   "Auditing Windows security configuration..."),
    ("report",      "Generating security report..."),
]


def run_full_scan(
    progress_callback: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    """
    Execute all scan modules and return a results dict.
    progress_callback(fraction, step_label) is called after each step.
    """
    init_db()

    def _progress(step_idx: int, label: str) -> None:
        if progress_callback:
            fraction = step_idx / (len(SCAN_STEPS) - 1)
            progress_callback(fraction, label)

    results: dict[str, Any] = {
        "system_info": {},
        "users": {},
        "software": {},
        "network": {},
        "findings": [],
        "score": 100,
        "counts": {},
        "priority_fixes": {},
        "scan_id": None,
        "duration_seconds": 0,
    }

    t_start = time.time()
    all_findings: list[dict[str, Any]] = []

    # Step 0 — init
    _progress(0, SCAN_STEPS[0][1])
    time.sleep(0.3)

    # Step 1 — system info
    _progress(1, SCAN_STEPS[1][1])
    try:
        results["system_info"] = sys_collector.collect_system_info()
    except Exception as e:
        _append_error(all_findings, "SYS001", "System Collection Error", str(e))

    # Step 2 — users
    _progress(2, SCAN_STEPS[2][1])
    try:
        results["users"] = usr_collector.collect_users()
        user_findings = _analyze_users(results["users"])
        all_findings.extend(user_findings)
    except Exception as e:
        _append_error(all_findings, "USR000", "User Collection Error", str(e))

    # Step 3 — software
    _progress(3, SCAN_STEPS[3][1])
    try:
        results["software"] = sw_collector.collect_software()
        sw_findings = _analyze_software(results["software"])
        all_findings.extend(sw_findings)
    except Exception as e:
        _append_error(all_findings, "SW000", "Software Collection Error", str(e))

    # Step 4 — network
    _progress(4, SCAN_STEPS[4][1])
    try:
        results["network"] = net_collector.collect_network()
    except Exception as e:
        results["network"] = {}
        _append_error(all_findings, "NET000", "Network Collection Error", str(e))

    # Step 5 — firewall
    _progress(5, SCAN_STEPS[5][1])
    try:
        all_findings.extend(firewall.check_firewall())
    except Exception as e:
        _append_error(all_findings, "FW000", "Firewall Check Error", str(e))

    # Step 6 — antivirus
    _progress(6, SCAN_STEPS[6][1])
    try:
        all_findings.extend(antivirus.check_antivirus())
    except Exception as e:
        _append_error(all_findings, "AV000", "Antivirus Check Error", str(e))

    # Step 7 — updates
    _progress(7, SCAN_STEPS[7][1])
    try:
        all_findings.extend(updates.check_updates())
    except Exception as e:
        _append_error(all_findings, "OS000", "Update Check Error", str(e))

    # Step 8 — browsers
    _progress(8, SCAN_STEPS[8][1])
    try:
        all_findings.extend(browsers.check_browsers())
    except Exception as e:
        _append_error(all_findings, "BR000", "Browser Check Error", str(e))

    # Step 9 — permissions
    _progress(9, SCAN_STEPS[9][1])
    try:
        all_findings.extend(permissions.check_permissions())
    except Exception as e:
        _append_error(all_findings, "PERM000", "Permissions Check Error", str(e))

    # Step 10 — startup / processes
    _progress(10, SCAN_STEPS[10][1])
    try:
        all_findings.extend(startup.check_startup())
    except Exception as e:
        _append_error(all_findings, "STARTUP000", "Startup Check Error", str(e))

    # Step 11 — Windows configuration audit
    _progress(11, SCAN_STEPS[11][1])
    try:
        all_findings.extend(windows_config.check_windows_config())
    except Exception as e:
        _append_error(all_findings, "WIN000", "Windows Config Check Error", str(e))

    # Step 11b — port analysis (uses already-collected network data)
    try:
        all_findings.extend(ports.check_ports(results["network"]))
    except Exception as e:
        _append_error(all_findings, "PORT000", "Port Check Error", str(e))

    # Step 12 — finalize
    _progress(12, SCAN_STEPS[12][1])

    # Filter out pure Info findings from scoring but keep them in results
    results["findings"] = all_findings
    results["score"] = calculate_score(all_findings)
    results["counts"] = count_by_severity(all_findings)
    results["priority_fixes"] = get_priority_fixes(all_findings)
    results["duration_seconds"] = round(time.time() - t_start, 1)

    # Save to DB
    try:
        scan_id = save_scan(results["score"], all_findings, results["system_info"])
        results["scan_id"] = scan_id
    except Exception:
        pass

    return results


# ─────────────────────────────────────────────────────────────────────────────
# QUICK SCAN — essential checks only (~15-25 sec)
# ─────────────────────────────────────────────────────────────────────────────
QUICK_STEPS: list[tuple[str, str]] = [
    ("init",      "Initializing..."),
    ("system",    "Collecting system information..."),
    ("users",     "Checking user accounts..."),
    ("network",   "Scanning network & ports..."),
    ("firewall",  "Auditing firewall..."),
    ("antivirus", "Checking antivirus..."),
    ("winconfig", "Windows configuration check..."),
    ("report",    "Generating report..."),
]

# Re-export so app.py can import SCAN_STEPS and still get the full list
# (app uses SCAN_STEPS for the step display)


def run_quick_scan(
    progress_callback: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    init_db()
    t_start = time.time()
    all_findings: list[dict[str, Any]] = []
    results: dict[str, Any] = {
        "system_info": {}, "users": {}, "software": {}, "network": {},
        "findings": [], "score": 100, "counts": {}, "priority_fixes": {},
        "scan_id": None, "duration_seconds": 0,
    }

    steps = QUICK_STEPS
    total = len(steps) - 1

    def _p(idx: int, label: str) -> None:
        if progress_callback:
            progress_callback(idx / total, label)

    _p(0, steps[0][1])
    time.sleep(0.2)

    _p(1, steps[1][1])
    try: results["system_info"] = sys_collector.collect_system_info()
    except Exception as e: _append_error(all_findings, "SYS001", "System Error", str(e))

    _p(2, steps[2][1])
    try:
        results["users"] = usr_collector.collect_users()
        all_findings.extend(_analyze_users(results["users"]))
    except Exception as e: _append_error(all_findings, "USR000", "User Error", str(e))

    _p(3, steps[3][1])
    try: results["network"] = net_collector.collect_network()
    except Exception: results["network"] = {}

    _p(4, steps[4][1])
    try: all_findings.extend(firewall.check_firewall())
    except Exception as e: _append_error(all_findings, "FW000", "Firewall Error", str(e))

    _p(5, steps[5][1])
    try: all_findings.extend(antivirus.check_antivirus())
    except Exception as e: _append_error(all_findings, "AV000", "AV Error", str(e))

    try: all_findings.extend(ports.check_ports(results["network"]))
    except Exception: pass

    _p(6, steps[6][1])
    try: all_findings.extend(windows_config.check_windows_config())
    except Exception as e: _append_error(all_findings, "WIN000", "WinConfig Error", str(e))

    _p(7, steps[7][1])
    results["findings"]       = all_findings
    results["score"]          = calculate_score(all_findings)
    results["counts"]         = count_by_severity(all_findings)
    results["priority_fixes"] = get_priority_fixes(all_findings)
    results["duration_seconds"] = round(time.time() - t_start, 1)
    try:
        results["scan_id"] = save_scan(results["score"], all_findings, results["system_info"])
    except Exception:
        pass
    return results


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK SCAN — ports, firewall, connections (~10-15 sec)
# ─────────────────────────────────────────────────────────────────────────────
NETWORK_STEPS: list[tuple[str, str]] = [
    ("init",     "Initializing..."),
    ("network",  "Scanning network adapters..."),
    ("ports",    "Checking open ports..."),
    ("firewall", "Auditing firewall..."),
    ("report",   "Generating report..."),
]


def run_network_scan(
    progress_callback: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    init_db()
    t_start = time.time()
    all_findings: list[dict[str, Any]] = []
    results: dict[str, Any] = {
        "system_info": {}, "users": {}, "software": {}, "network": {},
        "findings": [], "score": 100, "counts": {}, "priority_fixes": {},
        "scan_id": None, "duration_seconds": 0,
    }

    steps = NETWORK_STEPS
    total = len(steps) - 1

    def _p(idx: int, label: str) -> None:
        if progress_callback:
            progress_callback(idx / total, label)

    _p(0, steps[0][1])
    time.sleep(0.2)

    _p(1, steps[1][1])
    try: results["network"] = net_collector.collect_network()
    except Exception: results["network"] = {}

    _p(2, steps[2][1])
    try: all_findings.extend(ports.check_ports(results["network"]))
    except Exception as e: _append_error(all_findings, "PORT000", "Port Error", str(e))

    _p(3, steps[3][1])
    try: all_findings.extend(firewall.check_firewall())
    except Exception as e: _append_error(all_findings, "FW000", "Firewall Error", str(e))

    _p(4, steps[4][1])
    try: results["system_info"] = sys_collector.collect_system_info()
    except Exception: pass

    results["findings"]         = all_findings
    results["score"]            = calculate_score(all_findings)
    results["counts"]           = count_by_severity(all_findings)
    results["priority_fixes"]   = get_priority_fixes(all_findings)
    results["duration_seconds"] = round(time.time() - t_start, 1)
    try:
        results["scan_id"] = save_scan(results["score"], all_findings, results["system_info"])
    except Exception:
        pass
    return results


def _analyze_users(user_data: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if user_data.get("guest_enabled"):
        findings.append({
            "id": "USR001",
            "title": "Guest Account Enabled",
            "severity": "Medium",
            "score_deduction": 5,
            "description": "The Guest account is enabled, allowing unauthenticated network access.",
            "evidence": "Guest account active: Yes",
            "recommendation": "Disable the Guest account.",
            "fix": "Run: net user guest /active:no",
            "category": "User Accounts",
        })

    admin_users = user_data.get("admin_users", [])
    # Filter out built-in system accounts
    real_admins = [a for a in admin_users if a.lower() not in ("administrator",)]
    if len(real_admins) > 2:
        findings.append({
            "id": "USR002",
            "title": f"Multiple Admin Accounts ({len(real_admins)} non-built-in)",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                f"{len(admin_users)} accounts have Administrator privileges: {', '.join(admin_users[:5])}. "
                "Each admin account is an additional attack target. Use least-privilege."
            ),
            "evidence": f"Administrators group: {', '.join(admin_users[:5])}",
            "recommendation": "Remove users from Administrators who don't need full admin rights.",
            "fix": "Run: net localgroup Administrators <username> /delete",
            "category": "User Accounts",
        })

    policy = user_data.get("password_policy", {})

    # Minimum password length
    min_len_raw = policy.get("Minimum password length", "0")
    try:
        min_len = int(str(min_len_raw).strip())
        if min_len == 0:
            findings.append({
                "id": "USR003",
                "title": "No Minimum Password Length Enforced",
                "severity": "High",
                "score_deduction": 10,
                "description": (
                    "Minimum password length is 0 — users can set empty or trivially short passwords. "
                    "This is one of the most critical account security failures."
                ),
                "evidence": f"Minimum password length: {min_len}",
                "recommendation": "Set minimum password length to at least 12 characters.",
                "fix": "Run: net accounts /minpwlen:12",
                "category": "User Accounts",
            })
        elif min_len < 8:
            findings.append({
                "id": "USR003",
                "title": f"Password Minimum Length Too Short ({min_len} chars)",
                "severity": "Medium",
                "score_deduction": 5,
                "description": f"Minimum password length is {min_len}. NIST SP 800-63 recommends at least 8 (ideally 12+).",
                "evidence": f"Minimum password length: {min_len}",
                "recommendation": "Set minimum password length to at least 12 characters.",
                "fix": "Run: net accounts /minpwlen:12",
                "category": "User Accounts",
            })
    except (ValueError, TypeError):
        pass

    # Account lockout threshold
    lockout_raw = policy.get("Lockout threshold", "Never")
    if str(lockout_raw).strip().lower() in ("0", "never", ""):
        findings.append({
            "id": "USR005",
            "title": "No Account Lockout Policy Configured",
            "severity": "High",
            "score_deduction": 10,
            "description": (
                "Account lockout threshold is 'Never' — there is no limit on failed login attempts. "
                "This allows unlimited brute-force attacks against local accounts."
            ),
            "evidence": f"Lockout threshold: {lockout_raw}",
            "recommendation": "Set account lockout after 5–10 failed attempts.",
            "fix": "Run: net accounts /lockoutthreshold:5",
            "category": "User Accounts",
        })

    # Password history
    history_raw = policy.get("Length of password history maintained", "None")
    if str(history_raw).strip().lower() in ("0", "none", ""):
        findings.append({
            "id": "USR006",
            "title": "No Password History Enforced",
            "severity": "Medium",
            "score_deduction": 5,
            "description": (
                "Password history is not maintained. Users can immediately reuse old passwords, "
                "undermining any password change policy."
            ),
            "evidence": f"Password history: {history_raw}",
            "recommendation": "Set password history to remember at least 10 previous passwords.",
            "fix": "Run: net accounts /uniquepw:10",
            "category": "User Accounts",
        })

    # Max password age
    max_age_raw = policy.get("Maximum password age (days)", "0")
    try:
        max_age = int(str(max_age_raw).strip())
        if max_age == 0:
            findings.append({
                "id": "USR007",
                "title": "Passwords Never Expire",
                "severity": "Low",
                "score_deduction": 2,
                "description": "Maximum password age is 0 (never expires). Old credentials increase long-term risk.",
                "evidence": f"Maximum password age: {max_age} days",
                "recommendation": "Set password expiration to 90 days.",
                "fix": "Run: net accounts /maxpwage:90",
                "category": "User Accounts",
            })
    except (ValueError, TypeError):
        pass

    inactive = user_data.get("inactive_accounts", [])
    if inactive:
        findings.append({
            "id": "USR004",
            "title": f"Inactive / Disabled Accounts Found ({len(inactive)})",
            "severity": "Low",
            "score_deduction": 2,
            "description": "Inactive or disabled accounts increase attack surface if accidentally re-enabled.",
            "evidence": f"Accounts: {', '.join(inactive[:5])}",
            "recommendation": "Remove accounts that are no longer needed.",
            "fix": "Run: net user <username> /active:no",
            "category": "User Accounts",
        })

    return findings


def _analyze_software(sw_data: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    unsupported = sw_data.get("flagged_unsupported", [])
    if unsupported:
        findings.append({
            "id": "SW001",
            "title": f"Unsupported Software Detected ({len(unsupported)})",
            "severity": "High",
            "score_deduction": 10,
            "description": f"End-of-life or unsupported software found: {', '.join(unsupported)}. No security patches are available.",
            "evidence": ", ".join(unsupported),
            "recommendation": "Remove or upgrade unsupported software immediately.",
            "fix": "Uninstall via Control Panel > Programs > Uninstall a program.",
            "category": "Software",
        })

    if sw_data.get("duplicate_security_warning"):
        tools = sw_data.get("security_tools_found", [])
        findings.append({
            "id": "SW002",
            "title": "Multiple Competing Security Tools Detected",
            "severity": "Low",
            "score_deduction": 2,
            "description": f"Multiple antivirus/security tools detected ({', '.join(tools)}). Conflicts can degrade protection.",
            "evidence": f"Security tools found: {', '.join(tools)}",
            "recommendation": "Use a single primary antivirus solution.",
            "fix": "Uninstall redundant security products to prevent conflicts.",
            "category": "Software",
        })

    return findings


def _append_error(findings: list, fid: str, title: str, error: str) -> None:
    findings.append({
        "id": fid,
        "title": f"{title} (Error)",
        "severity": "Info",
        "score_deduction": 0,
        "description": f"This check encountered an error and was skipped: {error}",
        "evidence": error,
        "recommendation": "Try running as Administrator for full scan results.",
        "fix": "Re-run with elevated privileges.",
        "category": "Scan Error",
    })
