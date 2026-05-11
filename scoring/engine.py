"""Scoring engine — calculates security score from findings."""

from typing import Any

SEVERITY_DEDUCTIONS: dict[str, int] = {
    "Critical": 15,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

SEVERITY_ORDER: list[str] = ["Critical", "High", "Medium", "Low", "Info"]


def calculate_score(findings: list[dict[str, Any]]) -> int:
    """Calculate security score (0-100) by deducting for each finding."""
    score = 100
    for finding in findings:
        severity = finding.get("severity", "Info")
        deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        # Use finding's own score_deduction if provided (capped at severity default)
        custom = finding.get("score_deduction", deduction)
        score -= min(custom, deduction)
    return max(0, score)


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        sev = finding.get("severity", "Info")
        if sev in counts:
            counts[sev] += 1
    return counts


def get_priority_fixes(findings: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Group findings into fix-immediately, recommended, and optional buckets."""
    buckets: dict[str, list[dict]] = {
        "fix_immediately": [],
        "recommended": [],
        "optional": [],
    }
    for f in findings:
        sev = f.get("severity", "Info")
        if sev in ("Critical", "High"):
            buckets["fix_immediately"].append(f)
        elif sev == "Medium":
            buckets["recommended"].append(f)
        elif sev == "Low":
            buckets["optional"].append(f)
    return buckets


def score_to_grade(score: int) -> str:
    """Return letter grade for a score."""
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def score_to_color(score: int) -> str:
    """Return hex color for a score."""
    if score >= 90: return "#00c853"
    if score >= 80: return "#64dd17"
    if score >= 70: return "#ffd600"
    if score >= 60: return "#ff6d00"
    return "#d50000"


def score_to_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    elif score >= 80:
        return "Good"
    elif score >= 70:
        return "Fair"
    elif score >= 60:
        return "Poor"
    else:
        return "Critical Risk"
