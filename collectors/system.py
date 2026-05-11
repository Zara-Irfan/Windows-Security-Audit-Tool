"""System information collector — gathers OS, hardware, and environment details."""

import platform
import socket
import os
import subprocess
from datetime import datetime, timedelta
from typing import Any

import psutil


def collect_system_info() -> dict[str, Any]:
    info: dict[str, Any] = {}

    # Basic OS
    info["os"] = platform.system()
    info["os_version"] = platform.version()
    info["os_release"] = platform.release()
    info["architecture"] = platform.machine()
    info["hostname"] = socket.gethostname()
    info["platform_detail"] = platform.platform()

    # CPU
    info["cpu_name"] = platform.processor()
    info["cpu_cores_physical"] = psutil.cpu_count(logical=False) or 0
    info["cpu_cores_logical"] = psutil.cpu_count(logical=True) or 0
    info["cpu_percent"] = psutil.cpu_percent(interval=0.5)

    # RAM
    mem = psutil.virtual_memory()
    info["ram_total_gb"] = round(mem.total / (1024 ** 3), 2)
    info["ram_used_gb"] = round(mem.used / (1024 ** 3), 2)
    info["ram_percent"] = mem.percent

    # Disk
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "percent": usage.percent,
            })
        except (PermissionError, OSError):
            continue
    info["partitions"] = partitions

    # Uptime
    boot_time = psutil.boot_time()
    boot_dt = datetime.fromtimestamp(boot_time)
    uptime_delta = datetime.now() - boot_dt
    info["boot_time"] = boot_dt.strftime("%Y-%m-%d %H:%M:%S")
    info["uptime_seconds"] = int(uptime_delta.total_seconds())
    info["uptime_human"] = _format_uptime(uptime_delta)

    # BIOS / firmware (Windows only)
    info["bios_version"] = _get_bios_version()

    return info


def _format_uptime(delta: timedelta) -> str:
    total_seconds = int(delta.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    return f"{days}d {hours}h {minutes}m"


def _get_bios_version() -> str:
    if platform.system() != "Windows":
        try:
            with open("/sys/class/dmi/id/bios_version") as f:
                return f.read().strip()
        except Exception:
            return "N/A"

    try:
        result = subprocess.run(
            ["wmic", "bios", "get", "SMBIOSBIOSVersion"],
            capture_output=True, text=True, timeout=10
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception:
        pass
    return "N/A"
