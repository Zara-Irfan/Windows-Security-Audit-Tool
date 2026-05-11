"""Scan history management using SQLite."""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).parent.parent / "database" / "scans.db"


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL DEFAULT 0,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                findings_json TEXT NOT NULL,
                system_info_json TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)
        """)
        conn.commit()


def save_scan(
    score: int,
    findings: list[dict[str, Any]],
    system_info: dict[str, Any] | None = None,
) -> int:
    from scoring.engine import count_by_severity
    counts = count_by_severity(findings)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans
                (timestamp, score, findings_count, critical_count, high_count,
                 medium_count, low_count, findings_json, system_info_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                score,
                len(findings),
                counts.get("Critical", 0),
                counts.get("High", 0),
                counts.get("Medium", 0),
                counts.get("Low", 0),
                json.dumps(findings),
                json.dumps(system_info or {}),
            ),
        )
        conn.commit()
        return cursor.lastrowid or 0


def get_scan_history(limit: int = 20) -> list[dict[str, Any]]:
    init_db()
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, score, findings_count,
                   critical_count, high_count, medium_count, low_count
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    init_db()
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json", "[]"))
    result["system_info"] = json.loads(result.pop("system_info_json", "{}"))
    return result


def delete_scan(scan_id: int) -> None:
    with _get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
