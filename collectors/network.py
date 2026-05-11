"""Network information collector — IPs, adapters, DNS, ports, connections."""

import platform
import socket
import subprocess
from typing import Any

import psutil


DANGEROUS_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh/syslog",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt",
    27017: "MongoDB",
}

HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 3389, 4444, 5900}


def collect_network() -> dict[str, Any]:
    result: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "adapters": [],
        "dns_servers": [],
        "default_gateway": "",
        "listening_ports": [],
        "active_connections": [],
        "dangerous_open_ports": [],
        "rdp_enabled": False,
        "ftp_enabled": False,
        "telnet_enabled": False,
        "smb_exposure": False,
    }

    # Network interfaces
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        adapters = []
        for iface, addr_list in addrs.items():
            iface_info: dict[str, Any] = {"name": iface, "addresses": [], "is_up": False, "speed_mbps": 0}
            if iface in stats:
                iface_info["is_up"] = stats[iface].isup
                iface_info["speed_mbps"] = stats[iface].speed
            for addr in addr_list:
                iface_info["addresses"].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask or "",
                })
            adapters.append(iface_info)
        result["adapters"] = adapters
    except Exception:
        pass

    # DNS and gateway (Windows)
    if platform.system() == "Windows":
        try:
            out = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=15
            )
            dns_servers: list[str] = []
            gateway = ""
            for line in out.stdout.splitlines():
                if "DNS Servers" in line or "DNS Server" in line:
                    _, _, val = line.partition(":")
                    val = val.strip()
                    if val:
                        dns_servers.append(val)
                elif "Default Gateway" in line:
                    _, _, val = line.partition(":")
                    val = val.strip()
                    if val and val != " ":
                        gateway = val
            result["dns_servers"] = dns_servers
            result["default_gateway"] = gateway
        except Exception:
            pass
    else:
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        result["dns_servers"].append(line.split()[1])
        except Exception:
            pass

    # Listening ports and connections
    try:
        connections = psutil.net_connections(kind="inet")
        listening: list[dict] = []
        active: list[dict] = []
        dangerous: list[dict] = []

        for conn in connections:
            if conn.laddr:
                port_info = {
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "local_port": conn.laddr.port,
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "pid": conn.pid,
                }

                if conn.status == "LISTEN":
                    service = DANGEROUS_PORTS.get(conn.laddr.port, "Unknown")
                    port_info["service"] = service
                    listening.append(port_info)

                    if conn.laddr.port in DANGEROUS_PORTS:
                        risk = "High" if conn.laddr.port in HIGH_RISK_PORTS else "Medium"
                        dangerous.append({
                            "port": conn.laddr.port,
                            "service": service,
                            "risk": risk,
                        })
                elif conn.raddr:
                    active.append(port_info)

        result["listening_ports"] = listening
        result["active_connections"] = active[:50]  # cap for display
        result["dangerous_open_ports"] = dangerous
    except Exception:
        pass

    # Specific service checks
    open_ports = {p["local_port"] for p in result["listening_ports"]}
    result["rdp_enabled"] = 3389 in open_ports
    result["ftp_enabled"] = 21 in open_ports
    result["telnet_enabled"] = 23 in open_ports
    result["smb_exposure"] = bool(open_ports & {139, 445})

    return result
