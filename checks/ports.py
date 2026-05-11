"""Dangerous open port checks and network exposure analysis."""

from typing import Any
from collectors.network import collect_network, DANGEROUS_PORTS, HIGH_RISK_PORTS


PORT_DESCRIPTIONS: dict[int, dict] = {
    21: {
        "service": "FTP",
        "why": "FTP transmits data and credentials in cleartext. Easily intercepted.",
        "severity": "High",
        "fix": "Disable FTP. Use SFTP (port 22) or FTPS instead.",
    },
    23: {
        "service": "Telnet",
        "why": "Telnet transmits all data including passwords in cleartext.",
        "severity": "Critical",
        "fix": "Disable Telnet immediately. Use SSH instead.",
    },
    135: {
        "service": "RPC Endpoint Mapper",
        "why": "Windows RPC exposure enables remote code execution vulnerabilities.",
        "severity": "High",
        "fix": "Block port 135 in firewall if not required for internal services.",
    },
    139: {
        "service": "NetBIOS Session",
        "why": "NetBIOS exposure can allow credential harvesting and lateral movement.",
        "severity": "High",
        "fix": "Disable NetBIOS over TCP/IP in network adapter settings.",
    },
    445: {
        "service": "SMB",
        "why": "SMB exposure is exploited by ransomware (WannaCry, NotPetya). High risk.",
        "severity": "Critical",
        "fix": "Block SMB on public-facing interfaces. Disable SMBv1 via PowerShell.",
    },
    3389: {
        "service": "RDP",
        "why": "Remote Desktop increases brute-force and exploitation exposure (BlueKeep).",
        "severity": "High",
        "fix": "Disable RDP if not required, or restrict to VPN/specific IPs only.",
    },
    4444: {
        "service": "Metasploit Default",
        "why": "Port 4444 is the default Metasploit listener — may indicate compromise.",
        "severity": "Critical",
        "fix": "Immediately investigate any process listening on this port.",
    },
    5900: {
        "service": "VNC",
        "why": "VNC remote access is often poorly secured and targeted by attackers.",
        "severity": "High",
        "fix": "Disable VNC or restrict access with strong authentication and firewall rules.",
    },
    22: {
        "service": "SSH",
        "why": "SSH exposed to all interfaces allows brute-force attacks.",
        "severity": "Medium",
        "fix": "Restrict SSH to specific IPs, disable root login, use key-based auth.",
    },
    5432: {
        "service": "PostgreSQL",
        "why": "Database exposed on network interface allows direct database attacks.",
        "severity": "High",
        "fix": "Bind database to 127.0.0.1 only. Use firewall to block external access.",
    },
    3306: {
        "service": "MySQL",
        "why": "MySQL exposed on network allows unauthorized database access.",
        "severity": "High",
        "fix": "Bind MySQL to localhost. Block port 3306 in firewall.",
    },
    27017: {
        "service": "MongoDB",
        "why": "MongoDB historically exposes data without authentication by default.",
        "severity": "Critical",
        "fix": "Enable MongoDB authentication and bind to 127.0.0.1.",
    },
    6379: {
        "service": "Redis",
        "why": "Redis has no authentication by default and is frequently exploited.",
        "severity": "Critical",
        "fix": "Set Redis requirepass and bind to 127.0.0.1 only.",
    },
}


def check_ports(network_data: dict | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if network_data is None:
        network_data = collect_network()

    listening_ports = network_data.get("listening_ports", [])
    open_port_numbers = {p["local_port"] for p in listening_ports}

    # RDP-specific finding
    if network_data.get("rdp_enabled"):
        desc = PORT_DESCRIPTIONS.get(3389, {})
        findings.append({
            "id": "NET001",
            "title": "RDP (Remote Desktop) is Enabled",
            "severity": "High",
            "score_deduction": 10,
            "description": desc.get("why", "RDP port 3389 is open."),
            "evidence": "Port 3389 is in LISTEN state.",
            "recommendation": "Disable RDP if not required or restrict via firewall.",
            "fix": desc.get("fix", "Disable RDP in System Properties > Remote."),
            "category": "Network",
        })

    if network_data.get("telnet_enabled"):
        findings.append({
            "id": "NET002",
            "title": "Telnet Service Detected (Port 23)",
            "severity": "Critical",
            "score_deduction": 15,
            "description": PORT_DESCRIPTIONS[23]["why"],
            "evidence": "Port 23 is in LISTEN state.",
            "recommendation": "Disable Telnet immediately.",
            "fix": PORT_DESCRIPTIONS[23]["fix"],
            "category": "Network",
        })

    if network_data.get("ftp_enabled"):
        findings.append({
            "id": "NET003",
            "title": "FTP Service Detected (Port 21)",
            "severity": "High",
            "score_deduction": 10,
            "description": PORT_DESCRIPTIONS[21]["why"],
            "evidence": "Port 21 is in LISTEN state.",
            "recommendation": "Replace FTP with SFTP or FTPS.",
            "fix": PORT_DESCRIPTIONS[21]["fix"],
            "category": "Network",
        })

    if network_data.get("smb_exposure"):
        findings.append({
            "id": "NET004",
            "title": "SMB Ports Exposed (139/445)",
            "severity": "Critical",
            "score_deduction": 15,
            "description": PORT_DESCRIPTIONS[445]["why"],
            "evidence": f"Open ports: {open_port_numbers & {139, 445}}",
            "recommendation": "Block SMB ports in firewall.",
            "fix": PORT_DESCRIPTIONS[445]["fix"],
            "category": "Network",
        })

    # Check other dangerous ports
    checked_ports = {21, 23, 139, 445, 3389}
    for port, desc in PORT_DESCRIPTIONS.items():
        if port in checked_ports:
            continue
        if port in open_port_numbers:
            sev = desc["severity"]
            deduction = {"Critical": 15, "High": 10, "Medium": 5, "Low": 2}.get(sev, 0)
            findings.append({
                "id": f"NET{port:04d}",
                "title": f"{desc['service']} Port Open ({port})",
                "severity": sev,
                "score_deduction": deduction,
                "description": desc["why"],
                "evidence": f"Port {port} ({desc['service']}) is in LISTEN state.",
                "recommendation": f"Review need for {desc['service']}.",
                "fix": desc["fix"],
                "category": "Network",
            })

    if not findings:
        findings.append({
            "id": "NET000",
            "title": "No High-Risk Ports Detected",
            "severity": "Info",
            "score_deduction": 0,
            "description": "No obviously dangerous open ports were found.",
            "evidence": f"Open ports scanned: {sorted(open_port_numbers)}",
            "recommendation": "Continue monitoring open ports regularly.",
            "fix": "No action required.",
            "category": "Network",
        })

    return findings
