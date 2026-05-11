# 🛡️ SentinelScan — Windows Security Audit Tool

A professional, fully local Windows security auditing platform. Scans your machine for vulnerabilities, scores your security posture, and automatically fixes many issues — all without sending any data anywhere.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What It Does

SentinelScan audits your Windows machine across 15 security categories, gives you a score out of 100, and lets you fix the most common vulnerabilities with a single click — no manual steps required.

**Everything runs locally. No internet required. No data leaves your machine.**

---

## Screenshots

> Run the app and visit `http://localhost:8501` to see the full UI.

- **Dashboard** — Security score, grade (A–F), charts, top vulnerabilities
- **Run Scan** — Animated live progress, choose Full / Quick / Network scan
- **Results** — Full findings table, priority buckets, network info, export
- **Auto-Fix** — One-click fixes for 15 security issues
- **History** — Score trend over time, compare two scans side-by-side
- **Live Monitor** — Real-time CPU, RAM, Disk gauges and process list

---

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or higher
- Administrator privileges (for most auto-fixes)

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/Zara-Irfan/Windows-Security-Audit-Tool.git
cd Windows-Security-Audit-Tool
```

**2. Create a virtual environment (recommended)**

```bash
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Run the app**

Double-click `run.bat`, or run manually:

```bash
streamlit run app.py
```

Then open your browser to: **http://localhost:8501**

> **Tip:** Right-click your terminal and choose **Run as Administrator** before starting — this unlocks all 15 auto-fixes.

---

## Scan Types

| Scan | What it covers | Time |
|------|---------------|------|
| **Full Scan** | All 11 security modules | ~60–90 seconds |
| **Quick Scan** | Firewall, AV, ports, Windows config, permissions, startup | ~15–25 seconds |
| **Network Scan** | Open ports, dangerous services, firewall, active connections | ~10–15 seconds |

---

## What Gets Checked

| Module | Checks |
|--------|--------|
| **System Info** | OS version, architecture, CPU, RAM, disk, BIOS, uptime |
| **User Accounts** | Guest account status, admin count, password length policy, lockout policy, password age, complexity |
| **Installed Software** | All programs from Windows registry |
| **Network** | Adapters, DNS servers, gateway, listening ports, dangerous open ports, active connections |
| **Firewall** | Windows Firewall state on Domain, Private, and Public profiles |
| **Antivirus** | AV software detected, real-time protection on/off, signature freshness |
| **OS Updates** | Pending updates by severity (Critical / Important / Optional), last update date |
| **Browsers** | Chrome, Firefox, Edge — outdated version detection |
| **Permissions** | World-writable directories in sensitive locations |
| **Startup / Processes** | Programs at startup, suspicious process names |
| **Windows Config** | SMBv1, UAC, AutoPlay, WinRM, RDP NLA, unquoted service paths, shared folders, BitLocker, Windows Update service, screen lock, LLMNR, PowerShell execution policy, event log sizes |

---

## Auto-Fix Engine

15 fixes that actually run — no manual steps required.

| ID | Fix | Requires Admin |
|----|-----|---------------|
| WIN001 | Disable SMBv1 (WannaCry / NotPetya vector) | Yes |
| WIN002 | Re-enable UAC | Yes |
| WIN002B | Raise UAC notification level | Yes |
| WIN003 | Disable AutoPlay / AutoRun for all drive types | Yes |
| WIN004 | Stop and disable WinRM service | Yes |
| WIN005 | Enable RDP Network Level Authentication | Yes |
| WIN009 | Re-enable Windows Update service | Yes |
| WIN010 | Configure screen lock (5-minute timeout) | No |
| WIN010B | Require password on screen lock resume | No |
| WIN011 | Disable LLMNR (Responder credential theft vector) | Yes |
| WIN012 | Set PowerShell execution policy to RemoteSigned | Yes |
| WIN013 | Expand Security/System/Application event logs to 200 MB | Yes |
| FW001 | Enable Windows Firewall on all profiles | Yes |
| AV002 | Enable Windows Defender real-time protection | Yes |
| AV003 | Update Windows Defender signatures | Yes |

---

## Scoring System

| Score | Grade | Label |
|-------|-------|-------|
| 90–100 | A | Excellent |
| 80–89 | B | Good |
| 70–79 | C | Fair |
| 60–69 | D | Poor |
| 0–59 | F | Critical Risk |

Scoring deductions: Critical −15, High −10, Medium −5, Low −2, Info −0.

---

## Export Formats

| Format | Description |
|--------|-------------|
| **JSON** | Full findings, score, system info, timestamp — importable into SIEM tools |
| **CSV** | All findings with ID, title, severity, category, evidence, recommendation, fix steps |
| **HTML** | Styled dark-theme report, opens in any browser, shareable offline |

---

## Project Structure

```
├── app.py                  # Streamlit UI — all 6 pages and routing
├── main.py                 # Scan orchestrator — runs all modules
├── requirements.txt        # Python dependencies
├── run.bat                 # One-click launcher
│
├── checks/
│   ├── antivirus.py        # AV and Defender checks
│   ├── browsers.py         # Browser version checks
│   ├── firewall.py         # Firewall state
│   ├── permissions.py      # World-writable directory audit
│   ├── ports.py            # Port and service risk checks
│   ├── startup.py          # Startup programs and processes
│   ├── updates.py          # Windows Update status
│   └── windows_config.py   # 13 Windows security configuration checks
│
├── collectors/
│   ├── network.py          # Network interfaces, DNS, connections
│   ├── software.py         # Installed programs from registry
│   ├── system.py           # OS, CPU, RAM, disk info
│   └── users.py            # Local users, admins, password policy
│
├── remediation/
│   └── engine.py           # 15 auto-fix implementations via PowerShell
│
├── reporting/
│   ├── exporter.py         # JSON / CSV / HTML export
│   └── history.py          # SQLite save and load
│
├── scoring/
│   └── engine.py           # Score calculation and grading
│
└── .streamlit/
    └── config.toml         # Theme colors, port 8501, localhost-only
```

---

## Privacy & Security

- **No telemetry** — Streamlit usage stats are disabled in `config.toml`
- **No network calls** — The app never connects to external servers
- **Localhost only** — The web server binds to `127.0.0.1` only
- **Local database** — Scan history is stored in `database/scans.db` on your machine
- **CORS disabled** — No cross-origin requests accepted

---

## Dependencies

```
streamlit
psutil
pandas
plotly
```

Install with: `pip install -r requirements.txt`

---

## License

MIT License — free to use, modify, and distribute.

---

*Built for personal and professional Windows security hardening. Not a replacement for enterprise security tools.*
