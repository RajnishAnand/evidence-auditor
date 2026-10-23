"""Small, dependency-free persistence layer for completed scans."""

import json
import sqlite3
from pathlib import Path

from backend.app.scanning.schemas import ScanResult


class ScanStore:
    """Persist complete scan results without discarding raw observations."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )"""
            )

    def save(self, result: ScanResult) -> int:
        observed_at = result.evidence[0].observed_at.isoformat() if result.evidence else ""
        with sqlite3.connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO scans (target, status, observed_at, result_json) VALUES (?, ?, ?, ?)",
                (result.target, result.status.value, observed_at, result.model_dump_json()),
            )
            return int(cursor.lastrowid)

    def recent(self, limit: int = 20) -> list[ScanResult]:
        if limit < 1:
            return []
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                "SELECT result_json FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [ScanResult.model_validate(json.loads(row[0])) for row in rows]
