"""
SQLite database service for storing URL scan history and generating statistics.
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "webshield.db")


def _get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row_factory set for dict-like access."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the database schema if it does not already exist."""
    conn = _get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                url              TEXT    NOT NULL,
                normalized_url   TEXT    NOT NULL,
                status           TEXT    NOT NULL,
                risk_level       TEXT    NOT NULL DEFAULT 'safe',
                risk_score       INTEGER NOT NULL DEFAULT 0,
                similarity_score REAL    NOT NULL DEFAULT 0.0,
                matched_domain   TEXT,
                detection_method TEXT    NOT NULL DEFAULT 'blacklist',
                signals          TEXT,
                timestamp        TEXT    NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def save_scan(
    url: str,
    normalized_url: str,
    status: str,
    risk_level: str,
    risk_score: int,
    similarity_score: float = 0.0,
    matched_domain: str = "",
    detection_method: str = "blacklist",
    signals: Optional[List[str]] = None,
) -> int:
    """
    Persist a completed scan result to the database.

    Returns:
        The inserted row ID.
    """
    conn = _get_connection()
    try:
        signals_str = "; ".join(signals) if signals else ""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.execute(
            """
            INSERT INTO scan_history
                (url, normalized_url, status, risk_level, risk_score,
                 similarity_score, matched_domain, detection_method, signals, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (url, normalized_url, status, risk_level, risk_score,
             similarity_score, matched_domain, detection_method, signals_str, timestamp),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_history(limit: int = 50) -> List[Dict]:
    """
    Retrieve the most recent scan records.

    Args:
        limit: Maximum number of records to return.

    Returns:
        List of dicts representing each row.
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_stats() -> Dict:
    """
    Compute summary statistics across all scan history.

    Returns a dict with keys:
        total_scanned, total_malicious, total_safe, total_high_risk,
        total_medium_risk, total_low_risk, recent_scans (last 10).
    """
    conn = _get_connection()
    try:
        def count(where: str, params: tuple = ()) -> int:
            row = conn.execute(
                f"SELECT COUNT(*) as c FROM scan_history WHERE {where}", params
            ).fetchone()
            return row["c"] if row else 0

        total = count("1=1")
        malicious = count("status = 'malicious'")
        safe = count("risk_level = 'safe'")
        high = count("risk_level = 'high'")
        medium = count("risk_level = 'medium'")
        low = count("risk_level = 'low'")

        # Recent scans for the dashboard table (last 10)
        cursor = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT 10"
        )
        recent = [dict(row) for row in cursor.fetchall()]

        # Risk level distribution for chart
        dist_cursor = conn.execute(
            """
            SELECT risk_level, COUNT(*) as count
            FROM scan_history
            GROUP BY risk_level
            """
        )
        distribution = {row["risk_level"]: row["count"] for row in dist_cursor.fetchall()}

        # Daily scan counts for last 7 days
        daily_cursor = conn.execute(
            """
            SELECT DATE(timestamp) as day, COUNT(*) as count
            FROM scan_history
            WHERE DATE(timestamp) >= DATE('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY day ASC
            """
        )
        daily_scans = [dict(row) for row in daily_cursor.fetchall()]

        return {
            "total_scanned": total,
            "total_malicious": malicious,
            "total_safe": safe,
            "total_high_risk": high,
            "total_medium_risk": medium,
            "total_low_risk": low,
            "recent_scans": recent,
            "risk_distribution": distribution,
            "daily_scans": daily_scans,
            "detection_rate": round((malicious / total * 100), 1) if total > 0 else 0,
        }
    finally:
        conn.close()
