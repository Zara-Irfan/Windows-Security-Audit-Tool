"""SentinelScan — Professional Local Security Auditing Dashboard."""

from __future__ import annotations
import sys, os, time, json
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st
import pandas as pd

ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SentinelScan",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

/* ── Base ── */
html, body, [class*="css"] { font-family: 'Inter', -apple-system, sans-serif !important; }
#MainMenu, footer, header { visibility: hidden; }

/* ── Sidebar collapse / expand button ── */
[data-testid="collapsedControl"] {
    display: flex !important;
    visibility: visible !important;
    opacity: 1 !important;
    background: #0f2040 !important;
    border: 1px solid #1a3a5c !important;
    border-radius: 0 8px 8px 0 !important;
    color: #4f8ef7 !important;
    width: 24px !important;
    box-shadow: 2px 0 8px rgba(0,0,0,0.4) !important;
}
[data-testid="collapsedControl"]:hover {
    background: #1a3a5c !important;
    color: #7ab3ff !important;
}
.block-container { padding: 1.5rem 2rem 2rem !important; max-width: 1400px; }

/* ── App Background ── */
.stApp {
    background: #0d1b2a;
    background-image:
        radial-gradient(ellipse 80% 50% at 0% 0%,   rgba(31,77,163,0.18) 0%, transparent 70%),
        radial-gradient(ellipse 60% 40% at 100% 100%, rgba(0,120,200,0.12) 0%, transparent 70%);
    min-height: 100vh;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #070e1c 0%, #0a1628 40%, #0d1e30 100%) !important;
    border-right: 1px solid #1a3352;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0 !important; }

/* ── Sidebar top accent stripe ── */
.ss-logo-block {
    background: linear-gradient(135deg, #0f2848 0%, #122d52 100%);
    border-bottom: 1px solid #1a3a5c;
    padding: 1.4rem 1.2rem 1.2rem;
    margin-bottom: 0.5rem;
}
.ss-logo-title {
    font-size: 1.4rem; font-weight: 800; letter-spacing: -0.03em;
    background: linear-gradient(90deg, #4f8ef7, #00ccff);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    margin: 0;
}
.ss-logo-sub { color: #5a7fa0; font-size: 0.72rem; margin-top: 0.15rem; letter-spacing: 0.05em; text-transform: uppercase; }
.ss-shield { font-size: 2rem; line-height: 1; }

/* ── Nav buttons ── */
.ss-nav-label { color: #3a6080; font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: 0.1em; padding: 0.6rem 1rem 0.3rem; }
div[data-testid="stSidebar"] .stButton > button {
    width: 100% !important; text-align: left !important; justify-content: flex-start !important;
    background: transparent !important; border: none !important; border-radius: 8px !important;
    color: #7a9ab8 !important; font-size: 0.9rem !important; font-weight: 500 !important;
    padding: 0.55rem 1rem !important; margin: 1px 0 !important;
    transition: all 0.15s ease !important;
}
div[data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(79,142,247,0.12) !important; color: #c8d8f0 !important;
    transform: translateX(3px) !important;
}
div[data-testid="stSidebar"] .stButton.nav-active > button {
    background: linear-gradient(90deg, rgba(79,142,247,0.22), rgba(79,142,247,0.05)) !important;
    color: #4f8ef7 !important; border-left: 3px solid #4f8ef7 !important;
    padding-left: calc(1rem - 3px) !important;
}

/* ── Sidebar divider ── */
.ss-divider { border: none; border-top: 1px solid #1a3352; margin: 0.6rem 0; }

/* ── Sidebar system card ── */
.ss-sys-card {
    background: rgba(255,255,255,0.03); border: 1px solid #1a3352;
    border-radius: 8px; padding: 0.8rem 1rem; margin: 0.5rem 0;
}
.ss-sys-row { display: flex; justify-content: space-between; align-items: center;
              padding: 0.2rem 0; font-size: 0.78rem; }
.ss-sys-key { color: #3a6080; }
.ss-sys-val { color: #a0c0e0; font-weight: 600; }

/* ── Page heading ── */
.ss-page-header {
    display: flex; align-items: center; gap: 1rem;
    padding-bottom: 1rem; border-bottom: 1px solid #1a3352; margin-bottom: 1.5rem;
}
.ss-page-title { font-size: 1.6rem; font-weight: 800; color: #e0ecff; margin: 0; line-height: 1.1; }
.ss-page-sub   { font-size: 0.82rem; color: #4a7090; margin: 0; }

/* ── KPI Cards ── */
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
.kpi-card {
    background: linear-gradient(135deg, #111f35 0%, #0f1c2e 100%);
    border: 1px solid #1a3352; border-radius: 14px; padding: 1.2rem 1.4rem;
    position: relative; overflow: hidden; transition: border-color 0.2s, transform 0.15s;
}
.kpi-card:hover { border-color: #2a5080; transform: translateY(-2px); }
.kpi-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent, linear-gradient(90deg, #4f8ef7, #00ccff));
}
.kpi-label { color: #3a6080; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
.kpi-value { font-size: 2.4rem; font-weight: 900; color: var(--val-color, #e0ecff);
             line-height: 1.1; margin: 0.3rem 0 0.1rem; letter-spacing: -0.03em; }
.kpi-sub   { color: #3a5c78; font-size: 0.75rem; }
.kpi-icon  { position: absolute; right: 1rem; top: 50%; transform: translateY(-50%);
             font-size: 2.2rem; opacity: 0.1; }

/* ── Score ring ── */
.score-ring-wrap { text-align: center; padding: 0.5rem; }
.score-ring {
    width: 150px; height: 150px; border-radius: 50%; border: 8px solid;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    margin: 0 auto 0.5rem; box-shadow: 0 0 30px var(--ring-shadow, rgba(79,142,247,0.3));
}
.score-num   { font-size: 2.8rem; font-weight: 900; line-height: 1; }
.score-grade { font-size: 1rem; font-weight: 700; opacity: 0.9; }
.score-lbl   { font-size: 0.9rem; color: #5a7fa0; }

/* ── Section heading ── */
.ss-section {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em;
    color: #3a6080; border-bottom: 1px solid #1a3352; padding-bottom: 0.4rem; margin-bottom: 0.8rem;
}

/* ── Severity badges ── */
.badge {
    display: inline-block; padding: 0.18rem 0.65rem; border-radius: 20px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
}
.badge-critical { background: #3d0a0a; color: #ff5566; border: 1px solid #6b1515; }
.badge-high     { background: #3d1a0a; color: #ff7744; border: 1px solid #6b3010; }
.badge-medium   { background: #3d300a; color: #ffbb33; border: 1px solid #6b5510; }
.badge-low      { background: #1a3020; color: #44cc88; border: 1px solid #1e5030; }
.badge-info     { background: #0a1e3d; color: #4f8ef7; border: 1px solid #1a3a6b; }

/* ── Finding cards ── */
.finding-card {
    background: linear-gradient(135deg, #0e1c2e 0%, #0c1826 100%);
    border: 1px solid #1a3352; border-left: 4px solid; border-radius: 10px;
    padding: 1rem 1.2rem; margin-bottom: 0.65rem;
    transition: border-color 0.15s, box-shadow 0.15s;
}
.finding-card:hover { box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
.finding-title { font-weight: 700; color: #c8d8f0; font-size: 0.95rem; margin-bottom: 0.3rem; }
.finding-desc  { color: #5a7fa0; font-size: 0.84rem; line-height: 1.5; }
.finding-evidence {
    background: #060e1a; border-left: 3px solid; border-radius: 0 6px 6px 0;
    padding: 0.35rem 0.8rem; margin: 0.5rem 0;
    font-family: 'Courier New', monospace; font-size: 0.78rem; color: #4f8ef7;
}
.finding-fix {
    display: inline-block; background: #060e1a; border: 1px solid #1a3352;
    border-radius: 6px; padding: 0.3rem 0.8rem;
    font-family: 'Courier New', monospace; font-size: 0.78rem; color: #00cc8a;
    margin-top: 0.4rem;
}

/* ── Scan type cards ── */
.scan-type-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
.scan-type-card {
    background: linear-gradient(135deg, #0e1c2e, #0c1826); border: 2px solid #1a3352;
    border-radius: 14px; padding: 1.4rem; text-align: center; cursor: pointer;
    transition: all 0.2s;
}
.scan-type-card.selected { border-color: #4f8ef7; background: linear-gradient(135deg, #111f38, #0e1830);
                            box-shadow: 0 0 20px rgba(79,142,247,0.2); }
.scan-type-card:hover     { border-color: #2a5070; transform: translateY(-3px); }
.scan-type-icon  { font-size: 2.4rem; margin-bottom: 0.6rem; }
.scan-type-title { font-weight: 700; color: #c8d8f0; font-size: 1rem; margin-bottom: 0.3rem; }
.scan-type-desc  { color: #3a6080; font-size: 0.8rem; line-height: 1.5; }
.scan-type-time  { display: inline-block; margin-top: 0.6rem; padding: 0.2rem 0.7rem;
                   background: rgba(79,142,247,0.1); border: 1px solid #1a3a6b;
                   border-radius: 20px; font-size: 0.72rem; color: #4f8ef7; }

/* ── Scan progress ── */
.scan-step-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin: 1rem 0; }
.scan-step {
    background: #0c1826; border: 1px solid #1a3352; border-radius: 10px;
    padding: 0.7rem 0.9rem; display: flex; align-items: center; gap: 0.6rem;
    font-size: 0.82rem;
}
.scan-step.done    { border-color: #1e5030; background: #081810; color: #44cc88; }
.scan-step.active  { border-color: #4f8ef7; background: #0a1828;
                     box-shadow: 0 0 12px rgba(79,142,247,0.25); color: #4f8ef7; }
.scan-step.pending { color: #2a4060; }
.step-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.step-dot.done    { background: #44cc88; }
.step-dot.active  { background: #4f8ef7; animation: pulse-dot 1.2s infinite; }
.step-dot.pending { background: #1a3352; }
@keyframes pulse-dot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(1.4)} }

/* ── Scan complete banner ── */
.scan-complete {
    background: linear-gradient(135deg, #071a0f 0%, #0a2415 100%);
    border: 1px solid #1e5030; border-radius: 12px; text-align: center;
    padding: 1.2rem 2rem; margin: 1rem 0;
    box-shadow: 0 0 30px rgba(0,180,100,0.15);
}
.scan-complete-title { color: #44cc88; font-size: 1.4rem; font-weight: 800; }
.scan-complete-sub   { color: #2a6040; font-size: 0.85rem; margin-top: 0.3rem; }

/* ── Primary action buttons (all pages) ── */
[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #1d4ed8 0%, #3b82f6 100%) !important;
    color: #fff !important; border: none !important; border-radius: 10px !important;
    font-weight: 700 !important; font-size: 0.95rem !important;
    box-shadow: 0 4px 18px rgba(59,130,246,0.35) !important;
    transition: transform 0.15s, box-shadow 0.15s !important;
}
[data-testid="baseButton-primary"]:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 24px rgba(59,130,246,0.55) !important;
}
/* Keep sidebar buttons transparent even if primary */
div[data-testid="stSidebar"] [data-testid="baseButton-primary"] {
    background: transparent !important; color: #7a9ab8 !important;
    box-shadow: none !important; border: none !important;
}
/* Secondary buttons in main area */
[data-testid="baseButton-secondary"] {
    background: #0e1c2e !important; color: #a0c0e0 !important;
    border: 1px solid #1a3352 !important; border-radius: 8px !important;
    font-weight: 500 !important; transition: all 0.15s !important;
}
[data-testid="baseButton-secondary"]:hover {
    background: #111f35 !important; border-color: #2a5080 !important; color: #c8d8f0 !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: transparent !important; gap: 0.5rem;
    border-bottom: 1px solid #1a3352 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important; color: #3a6080 !important;
    border: none !important; border-bottom: 2px solid transparent !important;
    font-weight: 600 !important; font-size: 0.85rem !important;
    padding: 0.5rem 1rem !important; border-radius: 0 !important;
    transition: all 0.15s !important;
}
.stTabs [aria-selected="true"] {
    color: #4f8ef7 !important; border-bottom-color: #4f8ef7 !important;
    background: transparent !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #a0c0e0 !important; }
.stTabs [data-baseweb="tab-panel"] { padding-top: 1.2rem !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }
[data-testid="stDataFrame"] thead tr th {
    background: #0a1628 !important; color: #3a6080 !important;
    font-size: 0.72rem !important; text-transform: uppercase !important; letter-spacing: 0.08em !important;
}
[data-testid="stDataFrame"] tbody tr:hover td { background: rgba(79,142,247,0.06) !important; }

/* ── Metrics ── */
[data-testid="stMetric"] { background: #0e1c2e; border: 1px solid #1a3352; border-radius: 10px; padding: 0.8rem 1rem; }
[data-testid="stMetricLabel"]  { color: #3a6080 !important; font-size: 0.72rem !important; text-transform: uppercase; letter-spacing: 0.08em; }
[data-testid="stMetricValue"]  { color: #c8d8f0 !important; font-size: 1.6rem !important; }
[data-testid="stMetricDelta"]  { font-size: 0.8rem !important; }

/* ── Expander ── */
[data-testid="stExpander"] { background: #0e1c2e !important; border: 1px solid #1a3352 !important; border-radius: 10px !important; }
.streamlit-expanderHeader { color: #a0c0e0 !important; }

/* ── Progress bar ── */
.stProgress > div > div { background-color: #4f8ef7 !important; border-radius: 4px; }
.stProgress { background: #0a1628 !important; border-radius: 4px; }

/* ── Alerts ── */
.stAlert { border-radius: 10px !important; border-left-width: 4px !important; }

/* ── Selectbox / multiselect ── */
[data-baseweb="select"] { background: #0e1c2e !important; }
[data-baseweb="popover"] { background: #0e1c2e !important; border: 1px solid #1a3352 !important; }

/* ── Download button ── */
.stDownloadButton > button {
    background: #0e1c2e !important; border: 1px solid #1a3352 !important;
    color: #4f8ef7 !important; border-radius: 8px !important; font-weight: 600 !important;
    transition: all 0.15s !important;
}
.stDownloadButton > button:hover { background: #111f35 !important; border-color: #4f8ef7 !important; }

/* ── Monitor gauges ── */
.mon-gauge-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
.mon-bar-wrap { background: #0a1628; border-radius: 6px; height: 8px; overflow: hidden; margin-top: 0.4rem; }
.mon-bar      { height: 100%; border-radius: 6px; transition: width 0.5s; }

/* ── History diff ── */
.diff-better { color: #44cc88; font-weight: 700; }
.diff-worse  { color: #ff5566; font-weight: 700; }
.diff-same   { color: #5a7fa0; }

/* ── Checkbox ── */
[data-testid="stCheckbox"] label { color: #7a9ab8 !important; font-size: 0.88rem !important; }

/* ── Spinner ── */
.stSpinner > div { border-top-color: #4f8ef7 !important; }

/* ── Info box ── */
.stInfo    { background: rgba(79,142,247,0.1)  !important; border-left-color: #4f8ef7  !important; color: #a0c0e0 !important; }
.stWarning { background: rgba(255,170,0,0.1)   !important; border-left-color: #ffaa00  !important; color: #c0a060 !important; }
.stSuccess { background: rgba(68,200,136,0.1)  !important; border-left-color: #44cc88  !important; color: #60c090 !important; }
.stError   { background: rgba(255,60,60,0.1)   !important; border-left-color: #ff4040  !important; color: #c07070 !important; }
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────
import psutil

SEV_COLORS = {"Critical":"#ff5566","High":"#ff7744","Medium":"#ffbb33","Low":"#44cc88","Info":"#4f8ef7"}
SEV_ORDER  = ["Critical","High","Medium","Low","Info"]
SEV_BG     = {"Critical":"#3d0a0a","High":"#3d1a0a","Medium":"#3d300a","Low":"#1a3020","Info":"#0a1e3d"}

PAGES = [
    ("🏠", "Dashboard"),
    ("🔍", "Run Scan"),
    ("📊", "Results"),
    ("📅", "History"),
    ("💻", "Live Monitor"),
    ("🔧", "Auto-Fix"),
]

# ── Session state ─────────────────────────────────────────────────────────────
defaults = {
    "page": "Dashboard",
    "scan_results": None,
    "scan_type": "Full Scan",
    "remediated": set(),
    "fix_log": [],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Helpers ───────────────────────────────────────────────────────────────────
def _badge(sev: str) -> str:
    return f'<span class="badge badge-{sev.lower()}">{sev}</span>'

def _score_color(s: int) -> str:
    if s >= 80: return "#44cc88"
    if s >= 60: return "#ffbb33"
    if s >= 40: return "#ff7744"
    return "#ff5566"

def _score_grade(s: int) -> str:
    if s >= 90: return "A"
    if s >= 80: return "B"
    if s >= 70: return "C"
    if s >= 60: return "D"
    return "F"

def _score_label(s: int) -> str:
    if s >= 90: return "Excellent"
    if s >= 80: return "Good"
    if s >= 70: return "Fair"
    if s >= 60: return "Poor"
    return "Critical Risk"

def _nav_to(page: str) -> None:
    st.session_state.page = page
    st.rerun()

def _can_fix(f: dict) -> bool:
    try:
        from remediation.engine import can_fix
        return can_fix(f)
    except Exception:
        return False

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="ss-logo-block">
      <div style="display:flex;align-items:center;gap:0.8rem">
        <div class="ss-shield">🛡️</div>
        <div>
          <div class="ss-logo-title">SentinelScan</div>
          <div class="ss-logo-sub">Security Audit Platform</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    st.markdown('<div class="ss-nav-label">Navigation</div>', unsafe_allow_html=True)

    for icon, page_name in PAGES:
        disabled = (page_name == "Results" and st.session_state.scan_results is None)
        label = f"{icon}  {page_name}"
        if disabled:
            st.markdown(f'<div style="padding:0.55rem 1rem;color:#1e3040;font-size:0.9rem">{label}</div>', unsafe_allow_html=True)
        else:
            is_active = st.session_state.page == page_name
            if is_active:
                st.markdown(f"""
                <div style="background:linear-gradient(90deg,rgba(79,142,247,0.22),rgba(79,142,247,0.05));
                     border-left:3px solid #4f8ef7;border-radius:0 8px 8px 0;
                     padding:0.55rem 1rem;color:#4f8ef7;font-size:0.9rem;font-weight:600;
                     margin:1px 0">{label}</div>""", unsafe_allow_html=True)
            else:
                if st.button(label, key=f"nav_{page_name}", use_container_width=True):
                    st.session_state.page = page_name
                    st.rerun()

    st.markdown('<hr class="ss-divider">', unsafe_allow_html=True)

    # System quick stats
    try:
        cpu  = psutil.cpu_percent(interval=0.1)
        mem  = psutil.virtual_memory()
        _disk_path = Path(os.getcwd()).anchor  # "C:\\" on Win, "/" on Linux
        disk = psutil.disk_usage(_disk_path)
        boot = datetime.fromtimestamp(psutil.boot_time())
        uptime_h = int((datetime.now() - boot).total_seconds() // 3600)
        import platform, socket
        os_name = f"{platform.system()} {platform.release()}"
        hostname = socket.gethostname()

        cpu_color  = "#44cc88" if cpu  < 70 else "#ffbb33" if cpu  < 90 else "#ff5566"
        mem_color  = "#44cc88" if mem.percent  < 70 else "#ffbb33" if mem.percent  < 90 else "#ff5566"
        disk_color = "#44cc88" if disk.percent < 70 else "#ffbb33" if disk.percent < 90 else "#ff5566"

        st.markdown(f"""
        <div class="ss-nav-label">System Status</div>
        <div class="ss-sys-card">
          <div class="ss-sys-row"><span class="ss-sys-key">Host</span><span class="ss-sys-val">{hostname[:14]}</span></div>
          <div class="ss-sys-row"><span class="ss-sys-key">OS</span><span class="ss-sys-val">{os_name[:16]}</span></div>
          <div class="ss-sys-row">
            <span class="ss-sys-key">CPU</span>
            <span style="color:{cpu_color};font-weight:700;font-size:0.78rem">{cpu:.0f}%</span>
          </div>
          <div class="ss-sys-row">
            <span class="ss-sys-key">RAM</span>
            <span style="color:{mem_color};font-weight:700;font-size:0.78rem">{mem.percent:.0f}%</span>
          </div>
          <div class="ss-sys-row">
            <span class="ss-sys-key">Disk</span>
            <span style="color:{disk_color};font-weight:700;font-size:0.78rem">{disk.percent:.0f}%</span>
          </div>
          <div class="ss-sys-row"><span class="ss-sys-key">Uptime</span><span class="ss-sys-val">{uptime_h}h</span></div>
        </div>""", unsafe_allow_html=True)
    except Exception:
        pass

    # Last scan badge
    try:
        from reporting.history import get_scan_history, init_db
        init_db()
        history = get_scan_history(20)
    except Exception:
        history = []

    if history:
        last = history[0]
        sc   = last["score"]
        col  = _score_color(sc)
        st.markdown(f"""
        <hr class="ss-divider">
        <div class="ss-nav-label">Last Scan</div>
        <div class="ss-sys-card">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div style="color:#3a6080;font-size:0.7rem">{last['timestamp'][:10]}</div>
              <div style="color:#5a7fa0;font-size:0.7rem">{last['findings_count']} findings</div>
            </div>
            <div style="font-size:1.6rem;font-weight:900;color:{col}">{sc}</div>
          </div>
        </div>""", unsafe_allow_html=True)

    st.markdown("""
    <hr class="ss-divider">
    <div style="color:#1e3040;font-size:0.68rem;text-align:center;padding:0.5rem 0">
      v1.0.0 &nbsp;·&nbsp; localhost only &nbsp;·&nbsp; no telemetry
    </div>""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _page_header(icon: str, title: str, subtitle: str = "") -> None:
    st.markdown(f"""
    <div class="ss-page-header">
      <div style="font-size:2rem;line-height:1">{icon}</div>
      <div>
        <div class="ss-page-title">{title}</div>
        {"<div class='ss-page-sub'>" + subtitle + "</div>" if subtitle else ""}
      </div>
    </div>""", unsafe_allow_html=True)


def _kpi_card(label: str, value: str, sub: str, icon: str, accent: str, val_color: str = "#e0ecff") -> str:
    return f"""
    <div class="kpi-card" style="--accent:linear-gradient(90deg,{accent},transparent);--val-color:{val_color}">
      <div class="kpi-icon">{icon}</div>
      <div class="kpi-label">{label}</div>
      <div class="kpi-value">{value}</div>
      <div class="kpi-sub">{sub}</div>
    </div>"""


def _gauge_chart(score: int, height: int = 280):
    import plotly.graph_objects as go
    color = _score_color(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"font": {"size": 52, "color": color, "family": "Inter"}, "suffix": ""},
        domain={"x": [0, 1], "y": [0, 1]},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#1a3352",
                     "tickfont": {"color": "#3a6080", "size": 11}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  40], "color": "rgba(255,60,60,0.1)"},
                {"range": [40, 70], "color": "rgba(255,187,51,0.1)"},
                {"range": [70, 90], "color": "rgba(68,200,136,0.1)"},
                {"range": [90,100], "color": "rgba(68,200,136,0.15)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.85, "value": score},
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#c8d8f0", "family": "Inter"},
        margin={"t": 20, "b": 10, "l": 20, "r": 20}, height=height,
    )
    return fig


def _severity_donut(counts: dict, height: int = 260):
    import plotly.graph_objects as go
    labels  = [s for s in SEV_ORDER if s != "Info" and counts.get(s, 0) > 0]
    values  = [counts[s] for s in labels]
    colors  = [SEV_COLORS[s] for s in labels]
    if not values:
        return None
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.62,
        marker={"colors": colors, "line": {"color": "#0d1b2a", "width": 2}},
        textfont={"color": "#c8d8f0", "size": 12},
        hovertemplate="%{label}: <b>%{value}</b><extra></extra>",
    ))
    total = sum(values)
    fig.add_annotation(text=f"<b>{total}</b>", x=0.5, y=0.55, showarrow=False,
                       font={"size": 28, "color": "#c8d8f0"})
    fig.add_annotation(text="issues", x=0.5, y=0.42, showarrow=False,
                       font={"size": 12, "color": "#3a6080"})
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#c8d8f0"}, margin={"t": 10, "b": 10, "l": 10, "r": 10},
        height=height, showlegend=True,
        legend={"font": {"color": "#7a9ab8", "size": 12}, "bgcolor": "rgba(0,0,0,0)"},
    )
    return fig


def _category_bar(findings: list, height: int = 280):
    import plotly.graph_objects as go
    from collections import defaultdict
    cat_sev: dict[str, dict[str, int]] = defaultdict(lambda: {s: 0 for s in SEV_ORDER})
    for f in findings:
        sev = f.get("severity", "Info")
        cat = f.get("category", "Other")
        if sev != "Info":
            cat_sev[cat][sev] += 1
    cats = sorted(cat_sev.keys(), key=lambda c: -sum(cat_sev[c].values()))
    if not cats:
        return None
    fig = go.Figure()
    for sev in ["Critical", "High", "Medium", "Low"]:
        vals = [cat_sev[c][sev] for c in cats]
        if any(v > 0 for v in vals):
            fig.add_trace(go.Bar(
                name=sev, y=cats, x=vals, orientation="h",
                marker_color=SEV_COLORS[sev],
                hovertemplate=f"{sev}: %{{x}}<extra></extra>",
            ))
    fig.update_layout(
        barmode="stack", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#c8d8f0", "family": "Inter"},
        xaxis={"gridcolor": "#1a3352", "tickfont": {"color": "#3a6080"}},
        yaxis={"gridcolor": "#1a3352", "tickfont": {"color": "#a0c0e0"}, "categoryorder": "total ascending"},
        margin={"t": 10, "b": 10, "l": 10, "r": 10}, height=height,
        legend={"font": {"color": "#7a9ab8", "size": 11}, "bgcolor": "rgba(0,0,0,0)"},
    )
    return fig


def _render_fixable_row(f: dict) -> None:
    """Render a finding card with an inline Fix button if auto-fix is available."""
    from remediation.engine import apply_fix, can_fix
    fixable = can_fix(f)
    already = fixable and any(
        e.get("id") == f.get("id") and e.get("success")
        for e in st.session_state.fix_log
    )

    if fixable and not already:
        col_card, col_btn = st.columns([5, 1])
    else:
        col_card = st.container()
        col_btn  = None

    with col_card:
        _render_finding_card(f, fix_available=fixable and not already)

    if col_btn is not None:
        with col_btn:
            st.markdown("<div style='margin-top:0.5rem'></div>", unsafe_allow_html=True)
            fid = f.get("id", "")
            if st.button("🔧 Fix Now", key=f"pf_{fid}_{id(f)}", type="primary", use_container_width=True):
                with st.spinner(f"Applying fix…"):
                    result = apply_fix(f)
                st.session_state.fix_log.append(result)
                st.rerun()
    elif already:
        st.markdown(
            '<div style="color:#44cc88;font-size:0.78rem;margin:-0.4rem 0 0.5rem 0.5rem">'
            '✅ Fixed this session</div>',
            unsafe_allow_html=True,
        )


def _render_finding_card(f: dict, show_evidence: bool = True, show_why: bool = True, fix_available: bool = False) -> None:
    sev   = f.get("severity", "Info")
    color = SEV_COLORS.get(sev, "#4f8ef7")
    ev_html = ""
    if show_evidence and f.get("evidence"):
        ev_html = (f'<div class="finding-evidence" style="border-left-color:{color}">'
                   f'Evidence: {f["evidence"]}</div>')
    fix_html = f'<div class="finding-fix">&gt; {f.get("fix","")}</div>' if f.get("fix") else ""
    why_html = ""
    if show_why and f.get("recommendation"):
        why_html = (f'<div style="font-size:0.8rem;color:#3a6080;margin-top:0.4rem">'
                    f'<span style="color:#5a7fa0;font-weight:600">Why it matters:</span> '
                    f'{f["recommendation"]}</div>')
    autofix_badge = (
        '<span style="margin-left:auto;background:#1a2e1a;border:1px solid #2a5a2a;border-radius:4px;'
        'padding:0.1rem 0.45rem;font-size:0.68rem;color:#44cc88;font-weight:600">🔧 Auto-Fix Available</span>'
        if fix_available else ""
    )
    st.markdown(f"""
    <div class="finding-card" style="border-left-color:{color}">
      <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.25rem">
        {_badge(sev)}
        <span class="finding-title">{f.get("title","")}</span>
        {autofix_badge}
      </div>
      <div class="finding-desc">{f.get("description","")}</div>
      {ev_html}{why_html}{fix_html}
    </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
def page_dashboard():
    _page_header("🏠", "Security Dashboard", "Your system's security posture at a glance")

    res = st.session_state.scan_results
    last = history[0] if history else None

    score        = res["score"]       if res else (last["score"]          if last else None)
    findings     = res["findings"]    if res else []
    counts       = res["counts"]      if res else {}
    total_issues = sum(counts.get(s, 0) for s in ["Critical","High","Medium","Low"]) if counts else (last["findings_count"] if last else 0)
    crit_high    = counts.get("Critical",0)+counts.get("High",0) if counts else (((last or {}).get("critical_count",0)+(last or {}).get("high_count",0)) if last else 0)
    last_date    = (last["timestamp"][:10] if last else "Never")

    # ── KPI row ──
    sc_color  = _score_color(score) if score is not None else "#3a6080"
    sc_str    = f"{score}" if score is not None else "—"
    sc_grade  = _score_grade(score) if score is not None else "?"
    sc_lbl    = _score_label(score) if score is not None else "No scan yet"

    st.markdown(f"""
    <div class="kpi-grid">
      {_kpi_card("Security Score", sc_str+"/100", sc_lbl, "🛡️", sc_color, sc_color)}
      {_kpi_card("Total Issues", str(total_issues), "findings detected", "🔎", "#ff7744", "#ff7744" if total_issues>5 else "#44cc88")}
      {_kpi_card("Critical & High", str(crit_high), "need immediate action", "⚠️", "#ff5566", "#ff5566" if crit_high>0 else "#44cc88")}
      {_kpi_card("Last Scan", last_date, f"{len(history)} scan(s) on record", "📅", "#4f8ef7")}
    </div>""", unsafe_allow_html=True)

    if score is None:
        st.markdown("""
        <div style="text-align:center;padding:4rem 2rem;background:linear-gradient(135deg,#0e1c2e,#0c1826);
                    border:1px dashed #1a3352;border-radius:16px">
          <div style="font-size:4rem;margin-bottom:1rem">🛡️</div>
          <div style="color:#c8d8f0;font-size:1.4rem;font-weight:700;margin-bottom:0.5rem">No Scan Data Yet</div>
          <div style="color:#3a6080;font-size:0.9rem;margin-bottom:1.5rem">
            Run your first security scan to see your system's vulnerability report
          </div>
        </div>""", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("▶  Run First Scan Now", use_container_width=False, type="primary"):
            _nav_to("Run Scan")
        return

    # ── Charts row ──
    col_gauge, col_donut, col_bar = st.columns([1, 1, 1.5])
    with col_gauge:
        st.markdown('<div class="ss-section">Security Score</div>', unsafe_allow_html=True)
        st.plotly_chart(_gauge_chart(score, 240), use_container_width=True, key="dash_gauge")
        st.markdown(f'<div style="text-align:center;color:{sc_color};font-weight:700;font-size:1rem">Grade {sc_grade} — {sc_lbl}</div>', unsafe_allow_html=True)

    with col_donut:
        st.markdown('<div class="ss-section">Issue Breakdown</div>', unsafe_allow_html=True)
        fig = _severity_donut(counts, 240)
        if fig:
            st.plotly_chart(fig, use_container_width=True, key="dash_donut")
        else:
            st.success("No vulnerabilities found in this scan.")

    with col_bar:
        st.markdown('<div class="ss-section">Risk by Category</div>', unsafe_allow_html=True)
        fig2 = _category_bar(findings, 260)
        if fig2:
            st.plotly_chart(fig2, use_container_width=True, key="dash_catbar")
        else:
            st.info("All categories clean.")

    # ── Top findings ──
    st.markdown('<div class="ss-section" style="margin-top:1rem">Top Vulnerabilities</div>', unsafe_allow_html=True)
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    top = sorted([f for f in findings if f.get("severity") not in ("Info",)],
                 key=lambda x: sev_rank.get(x.get("severity","Info"), 9))[:6]

    if top:
        cols = st.columns(2)
        for i, f in enumerate(top):
            with cols[i % 2]:
                sev   = f.get("severity","Info")
                color = SEV_COLORS.get(sev,"#4f8ef7")
                st.markdown(f"""
                <div class="finding-card" style="border-left-color:{color};padding:0.75rem 1rem">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div>
                      {_badge(sev)}
                      <div class="finding-title" style="margin-top:0.3rem">{f.get("title","")}</div>
                    </div>
                    <div style="color:#2a4060;font-size:0.7rem;margin-left:0.5rem;white-space:nowrap">{f.get("category","")}</div>
                  </div>
                  <div class="finding-desc" style="margin-top:0.3rem">{f.get("description","")[:120]}{'…' if len(f.get("description",""))>120 else ""}</div>
                </div>""", unsafe_allow_html=True)
    else:
        st.success("🎉 No active vulnerabilities detected.")

    # ── Auto-fix action bar ──
    try:
        from remediation.engine import apply_fix, can_fix as _cf, is_admin as _ia
        fixable_now = [f for f in findings if _cf(f) and f.get("severity") != "Info"]
        already_fixed_db = {e["id"] for e in st.session_state.fix_log if e.get("success")}
        pending_now = [f for f in fixable_now if f.get("id") not in already_fixed_db]

        if pending_now:
            admin_ok = _ia()
            border_col = "#1a4d1a" if admin_ok else "#6b4f00"
            bg_col     = "#0a1e0a" if admin_ok else "#1a1000"
            icon       = "✅" if admin_ok else "⚠️"
            hint       = ("Click to apply all fixes automatically." if admin_ok
                          else "Running as Administrator required. Right-click terminal → Run as Administrator.")
            fa1, fa2 = st.columns([4, 1])
            with fa1:
                st.markdown(
                    f'<div style="background:{bg_col};border:1px solid {border_col};border-radius:8px;'
                    f'padding:0.6rem 1rem;font-size:0.85rem">'
                    f'{icon} &nbsp;<strong style="color:#c8d8f0">{len(pending_now)} issues can be fixed automatically</strong>'
                    f'<span style="color:#5a7fa0;font-size:0.78rem"> &nbsp;·&nbsp; {hint}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            with fa2:
                if st.button("⚡ Fix All", key="dash_fix_all", type="primary", use_container_width=True):
                    prog = st.progress(0, text="Applying fixes…")
                    for i, f in enumerate(pending_now):
                        prog.progress((i + 1) / len(pending_now), text=f"Fixing {f.get('id','')}…")
                        st.session_state.fix_log.append(apply_fix(f))
                    st.rerun()
        elif fixable_now:
            st.markdown(
                '<div style="background:#0a1e0a;border:1px solid #1a4d1a;border-radius:8px;'
                'padding:0.55rem 1rem;font-size:0.85rem;color:#44cc88">'
                '✅ &nbsp;All auto-fixable issues have been resolved this session.</div>',
                unsafe_allow_html=True,
            )
    except Exception:
        pass

    st.markdown('<hr style="border-color:#1a3352;margin:1.5rem 0">', unsafe_allow_html=True)
    qa, qb, qc = st.columns(3)
    with qa:
        if st.button("▶  Run New Scan",      use_container_width=True, type="primary"):  _nav_to("Run Scan")
    with qb:
        if st.button("📊  View Full Results", use_container_width=True): _nav_to("Results")
    with qc:
        if st.button("📅  Scan History",      use_container_width=True): _nav_to("History")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: RUN SCAN
# ─────────────────────────────────────────────────────────────────────────────
def page_run_scan():
    _page_header("🔍", "Run Security Scan", "Choose a scan type and audit your system")

    # ── Scan type selector ──
    st.markdown('<div class="ss-section">Select Scan Type</div>', unsafe_allow_html=True)
    t1, t2, t3 = st.columns(3)

    scan_types = {
        "Full Scan":     ("🔬", "Deep Security Audit", "All 11 security modules — the most thorough analysis", "~60–90 sec"),
        "Quick Scan":    ("⚡", "Essential Checks",    "Firewall, AV, open ports, Windows config — fast overview", "~15–25 sec"),
        "Network Scan":  ("🌐", "Network & Ports",     "Open ports, dangerous services, firewall, active connections", "~10–15 sec"),
    }
    cols = [t1, t2, t3]
    for col, (stype, (icon, title, desc, est)) in zip(cols, scan_types.items()):
        with col:
            selected_style = "border:2px solid #4f8ef7;background:linear-gradient(135deg,#111f38,#0e1830);box-shadow:0 0 20px rgba(79,142,247,0.2);" if st.session_state.scan_type == stype else "border:2px solid #1a3352;background:linear-gradient(135deg,#0e1c2e,#0c1826);"
            st.markdown(f"""
            <div style="{selected_style}border-radius:14px;padding:1.4rem;text-align:center;margin-bottom:0.5rem">
              <div style="font-size:2.4rem;margin-bottom:0.6rem">{icon}</div>
              <div style="font-weight:700;color:#c8d8f0;font-size:1rem;margin-bottom:0.3rem">{title}</div>
              <div style="color:#3a6080;font-size:0.8rem;line-height:1.5;margin-bottom:0.6rem">{desc}</div>
              <div style="display:inline-block;padding:0.2rem 0.7rem;background:rgba(79,142,247,0.1);
                          border:1px solid #1a3a6b;border-radius:20px;font-size:0.72rem;color:#4f8ef7">
                ⏱ {est}
              </div>
            </div>""", unsafe_allow_html=True)
            if st.button(f"Select {stype}", key=f"sel_{stype}", use_container_width=True):
                st.session_state.scan_type = stype
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Custom module toggle (Full Scan only) ──
    if st.session_state.scan_type == "Full Scan":
        with st.expander("⚙️  Customize modules (optional)", expanded=False):
            st.markdown('<div style="color:#5a7fa0;font-size:0.82rem;margin-bottom:0.8rem">All modules selected by default. Uncheck to skip.</div>', unsafe_allow_html=True)
            module_cols = st.columns(3)
            all_modules = ["System Info","User Accounts","Installed Software","Network","Firewall","Antivirus","OS Updates","Browsers","Permissions","Startup/Processes","Windows Config"]
            selected_modules = {}
            for i, mod in enumerate(all_modules):
                with module_cols[i % 3]:
                    selected_modules[mod] = st.checkbox(mod, value=True, key=f"mod_{mod}")
            if "custom_modules" not in st.session_state:
                st.session_state.custom_modules = all_modules
            st.session_state.custom_modules = [m for m, v in selected_modules.items() if v]

    # ── Run button ──
    st.markdown('<hr style="border-color:#1a3352;margin:1rem 0">', unsafe_allow_html=True)
    scan_type = st.session_state.scan_type
    col_btn, col_desc = st.columns([1, 3])
    with col_btn:
        run_clicked = st.button(f"▶  Start {scan_type}", use_container_width=True, key="run_btn", type="primary")
    with col_desc:
        st.markdown(f'<div style="color:#3a6080;padding-top:0.7rem;font-size:0.85rem">Running as <strong style="color:#a0c0e0">{scan_type}</strong> — results stored locally in SQLite. No data leaves this machine.</div>', unsafe_allow_html=True)

    # ── Scan execution ──
    if run_clicked:
        from main import run_full_scan, run_quick_scan, run_network_scan, SCAN_STEPS, QUICK_STEPS, NETWORK_STEPS

        scan_fn_map = {
            "Full Scan":    run_full_scan,
            "Quick Scan":   run_quick_scan,
            "Network Scan": run_network_scan,
        }
        scan_fn = scan_fn_map.get(scan_type, run_full_scan)

        # Determine steps to show based on scan type
        _steps_map = {"Full Scan": SCAN_STEPS, "Quick Scan": QUICK_STEPS, "Network Scan": NETWORK_STEPS}
        step_labels = [s[1] for s in _steps_map.get(scan_type, SCAN_STEPS)]

        st.markdown('<div class="ss-section" style="margin-top:1rem">Scan Progress</div>', unsafe_allow_html=True)
        progress_bar  = st.progress(0)
        status_text   = st.empty()
        steps_area    = st.empty()
        def _update(fraction: float, label: str) -> None:
            progress_bar.progress(min(fraction, 1.0))
            status_text.markdown(
                f'<div style="color:#4f8ef7;font-size:0.9rem;margin:0.3rem 0">⟳ &nbsp;{label}</div>',
                unsafe_allow_html=True,
            )
            n = len(step_labels)
            active_idx = min(int(fraction * n), n - 1)

            html = '<div class="scan-step-grid">'
            for i, s in enumerate(step_labels):
                short = s.replace("...", "").strip()[:28]
                if i < active_idx:
                    html += f'<div class="scan-step done"><div class="step-dot done"></div>{short}</div>'
                elif i == active_idx:
                    html += f'<div class="scan-step active"><div class="step-dot active"></div>{short}</div>'
                else:
                    html += f'<div class="scan-step pending"><div class="step-dot pending"></div>{short}</div>'
            html += "</div>"
            steps_area.markdown(html, unsafe_allow_html=True)

        result_area = st.empty()
        with st.spinner(""):
            try:
                results = scan_fn(progress_callback=_update)
                st.session_state.scan_results = results
            except Exception as e:
                st.error(f"Scan error: {e}")
                st.stop()

        progress_bar.progress(1.0)
        status_text.empty()
        steps_area.empty()
        dur = results.get("duration_seconds", "?")
        sc  = results["score"]
        cnt = sum(results["counts"].get(s,0) for s in ["Critical","High","Medium","Low"])
        result_area.markdown(f"""
        <div class="scan-complete">
          <div class="scan-complete-title">✅ &nbsp; Scan Complete</div>
          <div class="scan-complete-sub">
            Score: <strong style="color:#44cc88">{sc}/100</strong> &nbsp;·&nbsp;
            {cnt} issues found &nbsp;·&nbsp;
            Completed in {dur}s
          </div>
        </div>""", unsafe_allow_html=True)

        time.sleep(1.5)
        st.session_state.page = "Results"
        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: RESULTS
# ─────────────────────────────────────────────────────────────────────────────
def page_results():
    res = st.session_state.scan_results
    if not res:
        st.info("No scan results available. Run a scan first.")
        if st.button("▶ Run Scan"): _nav_to("Run Scan")
        return

    findings: list[dict]  = res["findings"]
    score:    int          = res["score"]
    counts:   dict         = res["counts"]
    priority: dict         = res["priority_fixes"]
    si:       dict         = res.get("system_info", {})
    net_data: dict         = res.get("network", {})
    scan_id                = res.get("scan_id", "")

    sc_color = _score_color(score)
    _page_header("📊", "Scan Results", f"Scan #{scan_id} · {findings and len(findings) or 0} total findings · Duration: {res.get('duration_seconds','?')}s")

    # ── Summary KPI row ──
    st.markdown(f"""
    <div class="kpi-grid">
      {_kpi_card("Security Score", f"{score}/100", _score_label(score), "🛡️", sc_color, sc_color)}
      {_kpi_card("Critical", str(counts.get("Critical",0)), "findings", "🚨", "#ff5566", "#ff5566" if counts.get("Critical",0) else "#44cc88")}
      {_kpi_card("High", str(counts.get("High",0)), "findings", "⚠️", "#ff7744", "#ff7744" if counts.get("High",0) else "#44cc88")}
      {_kpi_card("Medium + Low", str(counts.get("Medium",0)+counts.get("Low",0)), "findings", "📋", "#ffbb33")}
    </div>""", unsafe_allow_html=True)

    # ── Tabs ──
    tab_overview, tab_findings, tab_priority, tab_network, tab_system, tab_export = st.tabs([
        "📈 Overview", "📋 All Findings", "🎯 Priority Fixes", "🌐 Network", "💻 System Info", "📥 Export"
    ])

    # ── Tab: Overview ──
    with tab_overview:
        col_g, col_d, col_c = st.columns([1, 1, 1.5])
        with col_g:
            st.markdown('<div class="ss-section">Security Score</div>', unsafe_allow_html=True)
            st.plotly_chart(_gauge_chart(score, 260), use_container_width=True, key="res_gauge")
            st.markdown(f'<div style="text-align:center;color:{sc_color};font-weight:800;font-size:1.1rem">Grade {_score_grade(score)}</div>', unsafe_allow_html=True)

        with col_d:
            st.markdown('<div class="ss-section">Severity Breakdown</div>', unsafe_allow_html=True)
            fig = _severity_donut(counts, 260)
            if fig: st.plotly_chart(fig, use_container_width=True, key="res_donut")
            else:   st.success("No vulnerabilities.")

        with col_c:
            st.markdown('<div class="ss-section">Issues by Category</div>', unsafe_allow_html=True)
            fig2 = _category_bar(findings, 280)
            if fig2: st.plotly_chart(fig2, use_container_width=True, key="res_catbar")
            else:    st.success("All categories clean.")

        # Severity count cards
        st.markdown('<br><div class="ss-section">Count by Severity</div>', unsafe_allow_html=True)
        bc1,bc2,bc3,bc4,bc5 = st.columns(5)
        for col, sev in zip([bc1,bc2,bc3,bc4,bc5], SEV_ORDER):
            n = counts.get(sev, 0)
            c = SEV_COLORS[sev]
            with col:
                st.markdown(f"""
                <div style="background:{SEV_BG[sev]};border:1px solid {c}33;border-radius:12px;
                            padding:1rem;text-align:center">
                  <div style="color:{c};font-weight:900;font-size:2rem">{n}</div>
                  <div style="color:{c};font-size:0.75rem;font-weight:700;text-transform:uppercase">{sev}</div>
                </div>""", unsafe_allow_html=True)

    # ── Tab: All Findings ──
    with tab_findings:
        f1, f2, f3 = st.columns([2, 2, 1])
        with f1:
            sev_filter = st.multiselect("Severity", SEV_ORDER, default=SEV_ORDER, key="res_sev")
        with f2:
            cats = sorted(set(f.get("category","Other") for f in findings))
            cat_filter = st.multiselect("Category", cats, default=cats, key="res_cat")
        with f3:
            hide_info = st.checkbox("Hide Info", value=False, key="res_hide_info")

        active_sev = [s for s in sev_filter if s != "Info"] if hide_info else sev_filter
        filtered = sorted(
            [f for f in findings if f.get("severity") in active_sev and f.get("category") in cat_filter],
            key=lambda x: {s:i for i,s in enumerate(SEV_ORDER)}.get(x.get("severity","Info"), 9)
        )

        st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

        if filtered:
            df = pd.DataFrame([{
                "Severity": f.get("severity",""),
                "ID":       f.get("id",""),
                "Issue":    f.get("title",""),
                "Category": f.get("category",""),
                "Description": f.get("description",""),
                "Evidence": f.get("evidence",""),
                "Fix":      f.get("fix",""),
            } for f in filtered])
            st.dataframe(df, use_container_width=True, hide_index=True,
                         height=min(60 + len(filtered)*36, 550))
        else:
            st.info("No findings match the selected filters.")

    # ── Tab: Priority Fixes ──
    with tab_priority:
        from remediation.engine import apply_fix, can_fix as _engine_can_fix, is_admin as _engine_is_admin

        fix_imm  = priority.get("fix_immediately", [])
        recmd    = priority.get("recommended", [])
        optional = priority.get("optional", [])

        if not fix_imm and not recmd and not optional:
            st.success("🎉 No actionable vulnerabilities. Your system is in great shape!")
        else:
            already_fixed = {e["id"] for e in st.session_state.fix_log if e.get("success")}
            all_fixable   = [f for f in fix_imm + recmd if _engine_can_fix(f)
                             and f.get("id") not in already_fixed]

            # ── Admin warning / Fix All bar ──
            if not _engine_is_admin():
                st.markdown("""
                <div style="background:#1a1000;border:1px solid #6b4f00;border-radius:8px;
                            padding:0.55rem 1rem;margin-bottom:0.8rem;font-size:0.82rem;color:#ffbb33">
                  ⚠️ &nbsp;<strong>Run app as Administrator</strong> for fixes to apply.
                  Right-click terminal → <em>Run as Administrator</em>, then restart.
                </div>""", unsafe_allow_html=True)

            if all_fixable:
                fa_col1, fa_col2 = st.columns([4, 1])
                with fa_col1:
                    st.markdown(
                        f'<div style="color:#5a7fa0;font-size:0.82rem;padding-top:0.5rem">'
                        f'<strong style="color:#4f8ef7">{len(all_fixable)}</strong> issues can be fixed automatically'
                        f'{"  ·  " + str(len(already_fixed)) + " already fixed this session" if already_fixed else ""}'
                        f'</div>', unsafe_allow_html=True)
                with fa_col2:
                    if st.button("⚡ Fix All", key="pf_fix_all", type="primary", use_container_width=True):
                        prog = st.progress(0, text="Applying fixes…")
                        for i, f in enumerate(all_fixable):
                            prog.progress((i + 1) / len(all_fixable),
                                          text=f"Fixing {f.get('id','')}…")
                            st.session_state.fix_log.append(apply_fix(f))
                        st.rerun()

            if fix_imm:
                # Filter out already-fixed items
                pending_imm = [f for f in fix_imm if f.get("id") not in already_fixed]
                fixed_imm   = [f for f in fix_imm if f.get("id") in already_fixed]

                st.markdown(f"""
                <div style="background:#1a0808;border:1px solid #4d1010;border-radius:10px;
                            padding:0.6rem 1rem;margin-bottom:1rem;display:flex;align-items:center;gap:0.6rem">
                  <span style="font-size:1.4rem">🚨</span>
                  <div>
                    <div style="color:#ff5566;font-weight:700">Fix Immediately ({len(fix_imm)} issues)</div>
                    <div style="color:#6a2a2a;font-size:0.8rem">Critical and High severity — address these first</div>
                  </div>
                </div>""", unsafe_allow_html=True)
                for f in fixed_imm:
                    st.markdown(
                        f'<div style="color:#44cc88;font-size:0.82rem;padding:0.15rem 0 0.15rem 0.5rem">'
                        f'✅ &nbsp;<strong>{f.get("id","")}</strong> — {f.get("title","")} — Fixed</div>',
                        unsafe_allow_html=True)
                for f in pending_imm:
                    _render_fixable_row(f)

            if recmd:
                pending_rec = [f for f in recmd if f.get("id") not in already_fixed]
                fixed_rec   = [f for f in recmd if f.get("id") in already_fixed]

                st.markdown(f"""
                <div style="background:#1a1408;border:1px solid #4d3a10;border-radius:10px;
                            padding:0.6rem 1rem;margin:1rem 0;display:flex;align-items:center;gap:0.6rem">
                  <span style="font-size:1.4rem">⚠️</span>
                  <div>
                    <div style="color:#ffbb33;font-weight:700">Recommended ({len(recmd)} issues)</div>
                    <div style="color:#6a5a20;font-size:0.8rem">Medium severity — address soon</div>
                  </div>
                </div>""", unsafe_allow_html=True)
                for f in fixed_rec:
                    st.markdown(
                        f'<div style="color:#44cc88;font-size:0.82rem;padding:0.15rem 0 0.15rem 0.5rem">'
                        f'✅ &nbsp;<strong>{f.get("id","")}</strong> — {f.get("title","")} — Fixed</div>',
                        unsafe_allow_html=True)
                for f in pending_rec:
                    _render_fixable_row(f)

            if optional:
                with st.expander(f"Optional improvements ({len(optional)} items)"):
                    for f in optional:
                        _render_fixable_row(f)

    # ── Tab: Network ──
    with tab_network:
        nc1, nc2 = st.columns(2)
        with nc1:
            st.markdown('<div class="ss-section">Open Ports</div>', unsafe_allow_html=True)
            ports = net_data.get("listening_ports", [])
            if ports:
                port_df = pd.DataFrame([{
                    "Port":    p["local_port"],
                    "Address": p["local_address"],
                    "Service": p.get("service",""),
                    "PID":     p.get("pid",""),
                } for p in ports])
                st.dataframe(port_df, use_container_width=True, hide_index=True)
            else:
                st.info("No listening ports detected.")

        with nc2:
            st.markdown('<div class="ss-section">Dangerous Ports</div>', unsafe_allow_html=True)
            dang = net_data.get("dangerous_open_ports", [])
            if dang:
                for d in dang:
                    risk_color = {"High":"#ff7744","Critical":"#ff5566","Medium":"#ffbb33"}.get(d["risk"],"#4f8ef7")
                    st.markdown(f"""
                    <div style="background:#0e1c2e;border:1px solid #1a3352;border-left:4px solid {risk_color};
                                border-radius:8px;padding:0.6rem 1rem;margin-bottom:0.5rem;
                                display:flex;justify-content:space-between;align-items:center">
                      <div>
                        <span style="color:{risk_color};font-weight:700">Port {d['port']}</span>
                        <span style="color:#3a6080;font-size:0.85rem"> — {d['service']}</span>
                      </div>
                      {_badge(d['risk'])}
                    </div>""", unsafe_allow_html=True)
            else:
                st.success("✅ No high-risk ports detected.")

        st.markdown('<div class="ss-section" style="margin-top:1rem">Active Connections (top 20)</div>', unsafe_allow_html=True)
        conns = net_data.get("active_connections", [])
        if conns:
            conn_df = pd.DataFrame([{
                "Local":  c.get("local_address",""),
                "Remote": c.get("remote_address",""),
                "Status": c.get("status",""),
                "PID":    c.get("pid",""),
            } for c in conns[:20]])
            st.dataframe(conn_df, use_container_width=True, hide_index=True)
        else:
            st.info("No active connections.")

        # Network facts
        st.markdown('<div class="ss-section" style="margin-top:1rem">Quick Facts</div>', unsafe_allow_html=True)
        flags = [
            ("RDP Enabled",      net_data.get("rdp_enabled",False),      "#ff7744"),
            ("FTP Enabled",      net_data.get("ftp_enabled",False),       "#ff7744"),
            ("Telnet Enabled",   net_data.get("telnet_enabled",False),    "#ff5566"),
            ("SMB Exposure",     net_data.get("smb_exposure",False),      "#ff5566"),
        ]
        fcols = st.columns(4)
        for col, (lbl, val, bad_color) in zip(fcols, flags):
            with col:
                color = bad_color if val else "#44cc88"
                icon  = "🔴" if val else "🟢"
                st.markdown(f"""
                <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:10px;
                            padding:0.8rem;text-align:center">
                  <div style="font-size:1.5rem">{icon}</div>
                  <div style="color:{color};font-weight:700;font-size:0.85rem;margin-top:0.3rem">{lbl}</div>
                  <div style="color:#2a4060;font-size:0.75rem">{"Active" if val else "Not detected"}</div>
                </div>""", unsafe_allow_html=True)

    # ── Tab: System Info ──
    with tab_system:
        si_col1, si_col2 = st.columns(2)
        with si_col1:
            st.markdown('<div class="ss-section">Operating System</div>', unsafe_allow_html=True)
            rows = [
                ("OS",           f"{si.get('os','')} {si.get('os_release','')}"),
                ("Architecture", si.get("architecture","")),
                ("Version",      si.get("os_version","")[:60]),
                ("Hostname",     si.get("hostname","")),
                ("Boot Time",    si.get("boot_time","")),
                ("Uptime",       si.get("uptime_human","")),
                ("BIOS",         si.get("bios_version","")),
            ]
            for k, v in rows:
                st.markdown(f"""
                <div style="display:flex;justify-content:space-between;padding:0.45rem 0;
                            border-bottom:1px solid #0f1e2e;font-size:0.85rem">
                  <span style="color:#3a6080">{k}</span>
                  <span style="color:#a0c0e0;font-weight:500">{v}</span>
                </div>""", unsafe_allow_html=True)

        with si_col2:
            st.markdown('<div class="ss-section">Hardware</div>', unsafe_allow_html=True)
            hw_rows = [
                ("CPU",        si.get("cpu_name","")[:40]),
                ("CPU Cores",  f"{si.get('cpu_cores_physical',0)}P / {si.get('cpu_cores_logical',0)}L"),
                ("CPU Usage",  f"{si.get('cpu_percent',0)}%"),
                ("RAM Total",  f"{si.get('ram_total_gb',0)} GB"),
                ("RAM Used",   f"{si.get('ram_used_gb',0)} GB ({si.get('ram_percent',0)}%)"),
            ]
            for k, v in hw_rows:
                st.markdown(f"""
                <div style="display:flex;justify-content:space-between;padding:0.45rem 0;
                            border-bottom:1px solid #0f1e2e;font-size:0.85rem">
                  <span style="color:#3a6080">{k}</span>
                  <span style="color:#a0c0e0;font-weight:500">{v}</span>
                </div>""", unsafe_allow_html=True)
            st.markdown('<div class="ss-section" style="margin-top:0.8rem">Disk Partitions</div>', unsafe_allow_html=True)
            for p in si.get("partitions", []):
                pct = p["percent"]
                bar_color = "#44cc88" if pct < 70 else "#ffbb33" if pct < 90 else "#ff5566"
                st.markdown(f"""
                <div style="margin-bottom:0.7rem">
                  <div style="display:flex;justify-content:space-between;font-size:0.8rem;margin-bottom:0.2rem">
                    <span style="color:#a0c0e0">{p['device']}</span>
                    <span style="color:{bar_color}">{p['used_gb']}/{p['total_gb']} GB ({pct}%)</span>
                  </div>
                  <div class="mon-bar-wrap"><div class="mon-bar" style="width:{pct}%;background:{bar_color}"></div></div>
                </div>""", unsafe_allow_html=True)

    # ── Tab: Export ──
    with tab_export:
        from reporting.exporter import export_json, export_csv, export_html
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        st.markdown('<div class="ss-section">Download Report</div>', unsafe_allow_html=True)
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            st.markdown("""
            <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:12px;padding:1.2rem;text-align:center;margin-bottom:0.8rem">
              <div style="font-size:2rem">{ }</div>
              <div style="color:#c8d8f0;font-weight:700;margin:0.5rem 0">JSON Report</div>
              <div style="color:#3a6080;font-size:0.8rem">Machine-readable, full detail, importable into SIEM tools</div>
            </div>""", unsafe_allow_html=True)
            st.download_button("⬇ Export JSON", export_json(findings, score, si),
                               f"sentinelscan_{ts}.json", "application/json", use_container_width=True)
        with ec2:
            st.markdown("""
            <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:12px;padding:1.2rem;text-align:center;margin-bottom:0.8rem">
              <div style="font-size:2rem">📊</div>
              <div style="color:#c8d8f0;font-weight:700;margin:0.5rem 0">CSV Report</div>
              <div style="color:#3a6080;font-size:0.8rem">Spreadsheet-compatible, all findings with remediation steps</div>
            </div>""", unsafe_allow_html=True)
            st.download_button("⬇ Export CSV", export_csv(findings),
                               f"sentinelscan_{ts}.csv", "text/csv", use_container_width=True)
        with ec3:
            st.markdown("""
            <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:12px;padding:1.2rem;text-align:center;margin-bottom:0.8rem">
              <div style="font-size:2rem">🌐</div>
              <div style="color:#c8d8f0;font-weight:700;margin:0.5rem 0">HTML Report</div>
              <div style="color:#3a6080;font-size:0.8rem">Styled, shareable report — open in any browser</div>
            </div>""", unsafe_allow_html=True)
            st.download_button("⬇ Export HTML", export_html(findings, score, si),
                               f"sentinelscan_{ts}.html", "text/html", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: HISTORY
# ─────────────────────────────────────────────────────────────────────────────
def page_history():
    _page_header("📅", "Scan History", f"{len(history)} scan(s) on record")

    if not history:
        st.info("No scans on record yet. Run your first scan to start building history.")
        if st.button("▶ Run Scan"): _nav_to("Run Scan")
        return

    # ── Score trend ──
    if len(history) >= 2:
        try:
            import plotly.graph_objects as go
            dates  = [h["timestamp"][:16] for h in reversed(history)]
            scores = [h["score"]          for h in reversed(history)]
            colors = [_score_color(s) for s in scores]

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=dates, y=scores, mode="lines+markers",
                line={"color": "#4f8ef7", "width": 2.5},
                marker={"color": colors, "size": 10, "line": {"color": "#0d1b2a", "width": 2}},
                hovertemplate="<b>%{y}/100</b><br>%{x}<extra></extra>",
                fill="tozeroy", fillcolor="rgba(79,142,247,0.07)",
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color":"#c8d8f0","family":"Inter"},
                xaxis={"gridcolor":"#1a3352","tickfont":{"color":"#3a6080"},"title":""},
                yaxis={"gridcolor":"#1a3352","tickfont":{"color":"#3a6080"},"range":[0,105],"title":"Score"},
                margin={"t":10,"b":10,"l":10,"r":10}, height=220,
            )
            st.markdown('<div class="ss-section">Security Score Trend</div>', unsafe_allow_html=True)
            st.plotly_chart(fig, use_container_width=True, key="hist_trend")
        except Exception:
            pass

    # ── History table ──
    st.markdown('<div class="ss-section">All Scans</div>', unsafe_allow_html=True)
    hist_df = pd.DataFrame([{
        "ID":        h["id"],
        "Date":      h["timestamp"][:16],
        "Score":     h["score"],
        "Total":     h["findings_count"],
        "Critical":  h.get("critical_count",0),
        "High":      h.get("high_count",0),
        "Medium":    h.get("medium_count",0),
        "Low":       h.get("low_count",0),
    } for h in history])
    st.dataframe(hist_df, use_container_width=True, hide_index=True,
                 column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d")})

    st.markdown('<hr style="border-color:#1a3352;margin:1.5rem 0">', unsafe_allow_html=True)

    # ── Scan comparison ──
    st.markdown('<div class="ss-section">Compare Two Scans</div>', unsafe_allow_html=True)
    scan_opts = {f"#{h['id']} — {h['timestamp'][:16]} (Score: {h['score']})": h["id"] for h in history}

    cmp_col1, cmp_col2 = st.columns(2)
    with cmp_col1:
        scan_a_key = st.selectbox("Scan A (older)", list(scan_opts.keys()), index=min(1, len(scan_opts)-1), key="cmp_a")
    with cmp_col2:
        scan_b_key = st.selectbox("Scan B (newer)", list(scan_opts.keys()), index=0, key="cmp_b")

    if st.button("Compare Scans", key="do_compare"):
        from reporting.history import get_scan_by_id
        try:
            sa = get_scan_by_id(scan_opts[scan_a_key])
            sb = get_scan_by_id(scan_opts[scan_b_key])
            if sa and sb:
                d_score = sb["score"] - sa["score"]
                d_color = "#44cc88" if d_score >= 0 else "#ff5566"
                d_arrow = "▲" if d_score > 0 else ("▼" if d_score < 0 else "—")

                st.markdown(f"""
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-top:1rem">
                  <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:12px;padding:1rem;text-align:center">
                    <div style="color:#3a6080;font-size:0.72rem;text-transform:uppercase">Scan A Score</div>
                    <div style="color:{_score_color(sa['score'])};font-size:2rem;font-weight:900">{sa['score']}</div>
                    <div style="color:#2a4060;font-size:0.75rem">{sa['timestamp'][:10]}</div>
                  </div>
                  <div style="background:#0e1c2e;border:1px solid {d_color}44;border-radius:12px;padding:1rem;text-align:center">
                    <div style="color:#3a6080;font-size:0.72rem;text-transform:uppercase">Change</div>
                    <div style="color:{d_color};font-size:2rem;font-weight:900">{d_arrow}{abs(d_score)}</div>
                    <div style="color:#2a4060;font-size:0.75rem">score points</div>
                  </div>
                  <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:12px;padding:1rem;text-align:center">
                    <div style="color:#3a6080;font-size:0.72rem;text-transform:uppercase">Scan B Score</div>
                    <div style="color:{_score_color(sb['score'])};font-size:2rem;font-weight:900">{sb['score']}</div>
                    <div style="color:#2a4060;font-size:0.75rem">{sb['timestamp'][:10]}</div>
                  </div>
                </div>""", unsafe_allow_html=True)

                # Finding diff
                st.markdown('<div class="ss-section" style="margin-top:1rem">Finding Changes</div>', unsafe_allow_html=True)
                ids_a = {f["id"]: f for f in sa.get("findings", [])}
                ids_b = {f["id"]: f for f in sb.get("findings", [])}
                new_issues   = [f for fid, f in ids_b.items() if fid not in ids_a and f.get("severity") != "Info"]
                fixed_issues = [f for fid, f in ids_a.items() if fid not in ids_b and f.get("severity") != "Info"]

                dc1, dc2 = st.columns(2)
                with dc1:
                    st.markdown(f'<div style="color:#ff5566;font-weight:700;margin-bottom:0.5rem">🔴 New Issues ({len(new_issues)})</div>', unsafe_allow_html=True)
                    for f in new_issues[:5]:
                        st.markdown(f'<div style="color:#7a3a3a;font-size:0.82rem;padding:0.3rem 0;border-bottom:1px solid #1a0808">+ {f.get("title","")}</div>', unsafe_allow_html=True)
                    if not new_issues: st.markdown('<div style="color:#1e3040;font-size:0.82rem">None</div>', unsafe_allow_html=True)
                with dc2:
                    st.markdown(f'<div style="color:#44cc88;font-weight:700;margin-bottom:0.5rem">🟢 Resolved Issues ({len(fixed_issues)})</div>', unsafe_allow_html=True)
                    for f in fixed_issues[:5]:
                        st.markdown(f'<div style="color:#1a4a2a;font-size:0.82rem;padding:0.3rem 0;border-bottom:1px solid #081808">✓ {f.get("title","")}</div>', unsafe_allow_html=True)
                    if not fixed_issues: st.markdown('<div style="color:#1e3040;font-size:0.82rem">None</div>', unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Comparison failed: {e}")

    # ── Load historical scan ──
    st.markdown('<hr style="border-color:#1a3352;margin:1.5rem 0">', unsafe_allow_html=True)
    st.markdown('<div class="ss-section">Load Previous Scan</div>', unsafe_allow_html=True)
    load_col1, load_col2 = st.columns([3, 1])
    with load_col1:
        load_key = st.selectbox("Select scan to load", list(scan_opts.keys()), key="load_sel")
    with load_col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Load", key="load_hist_btn", use_container_width=True):
            from reporting.history import get_scan_by_id
            from scoring.engine   import count_by_severity, get_priority_fixes
            detail = get_scan_by_id(scan_opts[load_key])
            if detail:
                st.session_state.scan_results = {
                    "findings":         detail["findings"],
                    "score":            detail["score"],
                    "counts":           count_by_severity(detail["findings"]),
                    "priority_fixes":   get_priority_fixes(detail["findings"]),
                    "system_info":      detail.get("system_info", {}),
                    "network":          {},
                    "duration_seconds": "N/A",
                    "scan_id":          detail["id"],
                }
                _nav_to("Results")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: LIVE MONITOR
# ─────────────────────────────────────────────────────────────────────────────
def page_monitor():
    _page_header("💻", "Live System Monitor", "Real-time hardware and process telemetry")

    # ── Auto-refresh ──
    mc1, mc2 = st.columns([3, 1])
    with mc2:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()
    with mc1:
        auto = st.toggle("Auto-refresh every 5s", value=False, key="mon_auto")

    # ── CPU / RAM / Disk gauges ──
    try:
        import plotly.graph_objects as go
        cpu_pct  = psutil.cpu_percent(interval=0.5)
        mem      = psutil.virtual_memory()
        disk     = psutil.disk_usage(os.getcwd().split(":")[0] + ":\\" if os.name == "nt" else "/")
        cpu_freq = psutil.cpu_freq()

        def _mini_gauge(title: str, val: float, unit: str, color: str) -> go.Figure:
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=val,
                number={"suffix": unit, "font": {"size": 36, "color": color, "family":"Inter"}},
                domain={"x": [0,1], "y": [0,1]},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#1a3352",
                             "tickfont": {"color":"#3a6080","size":9}},
                    "bar": {"color": color, "thickness": 0.28},
                    "bgcolor": "rgba(0,0,0,0)", "borderwidth": 0,
                    "steps": [
                        {"range":[0,60],  "color":"rgba(68,200,136,0.08)"},
                        {"range":[60,85], "color":"rgba(255,187,51,0.08)"},
                        {"range":[85,100],"color":"rgba(255,85,102,0.12)"},
                    ],
                },
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color":"#c8d8f0"}, margin={"t":10,"b":10,"l":10,"r":10}, height=200,
                title={"text":title,"font":{"color":"#3a6080","size":11},"y":0.97,"x":0.5,"xanchor":"center"},
            )
            return fig

        g1, g2, g3, g4 = st.columns(4)
        cpu_color  = "#44cc88" if cpu_pct < 60  else "#ffbb33" if cpu_pct < 85  else "#ff5566"
        mem_color  = "#44cc88" if mem.percent < 60 else "#ffbb33" if mem.percent < 85 else "#ff5566"
        disk_color = "#44cc88" if disk.percent < 60 else "#ffbb33" if disk.percent < 85 else "#ff5566"

        with g1: st.plotly_chart(_mini_gauge("CPU Usage", cpu_pct, "%", cpu_color), use_container_width=True, key="mon_cpu")
        with g2: st.plotly_chart(_mini_gauge("Memory", mem.percent, "%", mem_color), use_container_width=True, key="mon_mem")
        with g3: st.plotly_chart(_mini_gauge("Disk Usage", disk.percent, "%", disk_color), use_container_width=True, key="mon_disk")
        with g4:
            swap = psutil.swap_memory()
            swap_color = "#44cc88" if swap.percent < 50 else "#ffbb33" if swap.percent < 80 else "#ff5566"
            st.plotly_chart(_mini_gauge("Swap", swap.percent, "%", swap_color), use_container_width=True, key="mon_swap")

        # ── Stat cards ──
        st.markdown("<br>", unsafe_allow_html=True)
        s1, s2, s3, s4, s5, s6 = st.columns(6)
        stats = [
            ("CPU Freq",    f"{cpu_freq.current:.0f}" if cpu_freq else "N/A", "MHz"),
            ("CPU Cores",   str(psutil.cpu_count(logical=True)), "threads"),
            ("RAM Total",   f"{mem.total/1073741824:.1f}", "GB"),
            ("RAM Free",    f"{mem.available/1073741824:.1f}", "GB"),
            ("Disk Total",  f"{disk.total/1073741824:.0f}", "GB"),
            ("Disk Free",   f"{disk.free/1073741824:.0f}", "GB"),
        ]
        for col, (lbl, val, unit) in zip([s1,s2,s3,s4,s5,s6], stats):
            with col:
                st.markdown(f"""
                <div style="background:#0e1c2e;border:1px solid #1a3352;border-radius:10px;
                            padding:0.8rem;text-align:center">
                  <div style="color:#3a6080;font-size:0.68rem;text-transform:uppercase">{lbl}</div>
                  <div style="color:#c8d8f0;font-size:1.3rem;font-weight:700">{val}</div>
                  <div style="color:#2a4060;font-size:0.7rem">{unit}</div>
                </div>""", unsafe_allow_html=True)

    except Exception as e:
        st.error(f"Hardware read error: {e}")

    # ── Top processes ──
    st.markdown('<div class="ss-section" style="margin-top:1.2rem">Top Processes by CPU</div>', unsafe_allow_html=True)
    try:
        procs = []
        for p in psutil.process_iter(["pid","name","cpu_percent","memory_percent","status"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
        proc_df = pd.DataFrame([{
            "PID":    p.get("pid",""),
            "Name":   p.get("name",""),
            "CPU %":  round(p.get("cpu_percent") or 0, 1),
            "RAM %":  round(p.get("memory_percent") or 0, 2),
            "Status": p.get("status",""),
        } for p in procs[:20]])
        st.dataframe(proc_df, use_container_width=True, hide_index=True,
                     column_config={"CPU %": st.column_config.ProgressColumn("CPU %", min_value=0, max_value=100, format="%.1f%%")})
    except Exception as e:
        st.warning(f"Could not list processes: {e}")

    # ── Active connections ──
    st.markdown('<div class="ss-section" style="margin-top:1rem">Active Network Connections</div>', unsafe_allow_html=True)
    try:
        conns = psutil.net_connections(kind="inet")
        conn_data = [{
            "Local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "Remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "Status": c.status,
            "PID":    c.pid or "",
        } for c in conns if c.status != "NONE"][:25]
        if conn_data:
            st.dataframe(pd.DataFrame(conn_data), use_container_width=True, hide_index=True)
        else:
            st.info("No active connections.")
    except Exception as e:
        st.warning(f"Connection read error: {e}")

    # ── Auto-refresh ──
    if auto:
        time.sleep(5)
        st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: AUTO-FIX
# ─────────────────────────────────────────────────────────────────────────────
def page_autofix():
    from remediation.engine import is_admin, can_fix, apply_fix, get_fix_meta

    _page_header("🔧", "Auto-Remediation",
                 "Apply verified fixes to detected vulnerabilities — no manual steps required")

    # ── Admin status banner ──
    admin = is_admin()
    if not admin:
        st.markdown("""
        <div style="background:#1a1000;border:1px solid #6b4f00;border-radius:10px;
                    padding:0.8rem 1.2rem;display:flex;align-items:center;gap:0.8rem;margin-bottom:1rem">
          <span style="font-size:1.3rem">⚠️</span>
          <div>
            <div style="color:#ffbb33;font-weight:700;font-size:0.9rem">Not running as Administrator</div>
            <div style="color:#8a6820;font-size:0.82rem">
              Most fixes require elevated privileges.
              Right-click your terminal or the SentinelScan shortcut and choose
              <strong style="color:#c09030">Run as Administrator</strong>, then restart the app.
            </div>
          </div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:#0a1e0a;border:1px solid #1a4d1a;border-radius:10px;
                    padding:0.6rem 1.2rem;display:flex;align-items:center;gap:0.6rem;margin-bottom:1rem">
          <span>✅</span>
          <span style="color:#44cc88;font-size:0.88rem;font-weight:600">
            Running as Administrator — all fixes are available
          </span>
        </div>""", unsafe_allow_html=True)

    # ── Guard: need a scan first ──
    res = st.session_state.scan_results
    if not res:
        st.info("Run a scan first to identify fixable issues.")
        if st.button("▶ Run Scan Now", type="primary", key="af_runscan"):
            _nav_to("Run Scan")
        return

    findings = res["findings"]
    fixable  = [f for f in findings if can_fix(f) and f.get("severity") != "Info"]

    already_fixed_ids = {e["id"] for e in st.session_state.fix_log if e.get("success")}
    pending   = [f for f in fixable if f.get("id") not in already_fixed_ids]
    completed = [f for f in fixable if f.get("id") in already_fixed_ids]
    not_fixable = [f for f in findings
                   if not can_fix(f) and f.get("severity") not in ("Info", None)]

    # ── Summary KPIs ──
    st.markdown(f"""
    <div class="kpi-grid" style="grid-template-columns:repeat(4,1fr)">
      <div class="kpi-card" style="--accent:linear-gradient(90deg,#4f8ef7,transparent);--val-color:#4f8ef7">
        <div class="kpi-icon">🔍</div>
        <div class="kpi-label">Fixable Issues</div>
        <div class="kpi-value">{len(fixable)}</div>
        <div class="kpi-sub">detected in last scan</div>
      </div>
      <div class="kpi-card" style="--accent:linear-gradient(90deg,#44cc88,transparent);--val-color:#44cc88">
        <div class="kpi-icon">✅</div>
        <div class="kpi-label">Fixed This Session</div>
        <div class="kpi-value">{len(completed)}</div>
        <div class="kpi-sub">applied successfully</div>
      </div>
      <div class="kpi-card" style="--accent:linear-gradient(90deg,#ffbb33,transparent);--val-color:#ffbb33">
        <div class="kpi-icon">⏳</div>
        <div class="kpi-label">Still Pending</div>
        <div class="kpi-value">{len(pending)}</div>
        <div class="kpi-sub">ready to fix</div>
      </div>
      <div class="kpi-card" style="--accent:linear-gradient(90deg,#5a7fa0,transparent);--val-color:#5a7fa0">
        <div class="kpi-icon">📋</div>
        <div class="kpi-label">Manual Action</div>
        <div class="kpi-value">{len(not_fixable)}</div>
        <div class="kpi-sub">require manual steps</div>
      </div>
    </div>""", unsafe_allow_html=True)

    # ── Pending fixes ──
    if pending:
        hdr_c1, hdr_c2 = st.columns([4, 1])
        with hdr_c1:
            st.markdown(f'<div class="ss-section">Pending Fixes ({len(pending)})</div>',
                        unsafe_allow_html=True)
        with hdr_c2:
            if st.button("⚡ Fix All Now", type="primary", use_container_width=True, key="af_fix_all"):
                prog = st.progress(0, text="Applying fixes…")
                for i, f in enumerate(pending):
                    prog.progress((i + 1) / len(pending), text=f"Fixing {f.get('id','')}: {f.get('title','')[:40]}…")
                    result = apply_fix(f)
                    st.session_state.fix_log.append(result)
                st.rerun()

        for idx, f in enumerate(pending):
            fid   = f.get("id", "")
            sev   = f.get("severity", "Info")
            color = SEV_COLORS.get(sev, "#4f8ef7")
            meta  = get_fix_meta(fid) or {}

            row_card, row_btn = st.columns([5, 1])
            with row_card:
                st.markdown(f"""
                <div style="background:#0a1628;border:1px solid #1a3352;border-left:3px solid {color};
                            border-radius:8px;padding:0.75rem 1rem;margin-bottom:0.25rem">
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.25rem">
                    {_badge(sev)}
                    <span style="color:#4f8ef7;font-size:0.72rem;font-family:monospace;
                                 background:#0d1b2a;padding:0.1rem 0.35rem;border-radius:3px">{fid}</span>
                    <span style="color:#c8d8f0;font-weight:600;font-size:0.88rem">{f.get('title','')}</span>
                  </div>
                  <div style="color:#5a7fa0;font-size:0.78rem">{meta.get('desc','')}</div>
                </div>""", unsafe_allow_html=True)
            with row_btn:
                st.markdown("<div style='padding-top:0.45rem'></div>", unsafe_allow_html=True)
                if st.button("🔧 Fix", key=f"af_fix_{fid}_{idx}",
                             use_container_width=True, type="primary"):
                    with st.spinner(f"Applying fix for {fid}…"):
                        result = apply_fix(f)
                    st.session_state.fix_log.append(result)
                    if result["success"]:
                        st.success(result["message"])
                    else:
                        st.error(result["message"])
                    time.sleep(0.8)
                    st.rerun()

    elif fixable:
        st.markdown("""
        <div style="background:#0a1e0a;border:1px solid #1a4d1a;border-radius:10px;
                    padding:1.5rem;text-align:center;margin:1rem 0">
          <div style="font-size:2.5rem;margin-bottom:0.5rem">🎉</div>
          <div style="color:#44cc88;font-weight:700;font-size:1.1rem">All auto-fixable issues resolved!</div>
          <div style="color:#2a5a2a;font-size:0.85rem;margin-top:0.3rem">
            Run a new scan to verify the fixes took effect.
          </div>
        </div>""", unsafe_allow_html=True)
        if st.button("🔍 Run Verification Scan", type="primary", key="af_verify"):
            _nav_to("Run Scan")
    else:
        st.info("No auto-fixable issues found in the last scan. Run a full scan to check for issues.")

    # ── Already fixed (this session) ──
    if completed:
        with st.expander(f"✅ Fixed this session ({len(completed)})"):
            for f in completed:
                st.markdown(
                    f'<div style="color:#44cc88;font-size:0.85rem;padding:0.2rem 0">'
                    f'✓ &nbsp;<strong>{f.get("id","")}</strong> — {f.get("title","")}</div>',
                    unsafe_allow_html=True,
                )

    # ── Issues requiring manual steps ──
    if not_fixable:
        with st.expander(f"📋 {len(not_fixable)} issues require manual steps"):
            st.markdown(
                '<div style="color:#5a7fa0;font-size:0.82rem;margin-bottom:0.8rem">'
                'These findings cannot be auto-fixed — follow the guidance below.</div>',
                unsafe_allow_html=True,
            )
            for f in not_fixable:
                _render_finding_card(f)

    # ── Fix log ──
    if st.session_state.fix_log:
        st.markdown('<hr style="border-color:#1a3352;margin:1.5rem 0">', unsafe_allow_html=True)
        log_hdr, log_clear = st.columns([4, 1])
        with log_hdr:
            st.markdown('<div class="ss-section">Fix Log (this session)</div>', unsafe_allow_html=True)
        with log_clear:
            if st.button("🗑 Clear Log", key="af_clear_log", use_container_width=True):
                st.session_state.fix_log = []
                st.rerun()

        log_html = (
            '<div style="font-family:\'Courier New\',monospace;font-size:0.82rem;'
            'background:#060e18;border:1px solid #1a3352;border-radius:8px;'
            'padding:1rem;max-height:320px;overflow-y:auto">'
        )
        for entry in reversed(st.session_state.fix_log):
            icon  = "✅" if entry.get("success") else "❌"
            color = "#44cc88" if entry.get("success") else "#ff5566"
            sev_c = SEV_COLORS.get(entry.get("severity", ""), "#4f8ef7")
            log_html += (
                f'<div style="margin-bottom:0.5rem;padding-bottom:0.5rem;border-bottom:1px solid #0f1e2e">'
                f'<span style="color:#2a4060">{entry.get("timestamp","")}</span>  '
                f'{icon}  '
                f'<span style="background:#0d1b2a;color:#4f8ef7;padding:0.1rem 0.3rem;'
                f'border-radius:3px;font-size:0.75rem">{entry.get("id","")}</span>  '
                f'<span style="color:{sev_c};font-size:0.75rem">{entry.get("severity","")}</span>  '
                f'<span style="color:{color}">{entry.get("message","")}</span>'
                f'</div>'
            )
        log_html += '</div>'
        st.markdown(log_html, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTER
# ═══════════════════════════════════════════════════════════════════════════════
page = st.session_state.page

if   page == "Dashboard":    page_dashboard()
elif page == "Run Scan":     page_run_scan()
elif page == "Results":      page_results()
elif page == "History":      page_history()
elif page == "Live Monitor": page_monitor()
elif page == "Auto-Fix":     page_autofix()

# ── Footer ──
st.markdown("""
<div style="text-align:center;color:#1a3040;font-size:0.72rem;padding:2rem 0 1rem;border-top:1px solid #0f1e2e;margin-top:2rem">
  🛡️ SentinelScan v1.0 &nbsp;·&nbsp; localhost only &nbsp;·&nbsp;
  no telemetry &nbsp;·&nbsp; no cloud &nbsp;·&nbsp; no data leaves this machine
</div>""", unsafe_allow_html=True)
