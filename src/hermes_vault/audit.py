from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from hermes_vault.models import AccessLogRecord


class AuditLogger:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS access_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    ttl_seconds INTEGER,
                    verification_result TEXT
                )
                """
            )
            conn.commit()
        if self.db_path.exists():
            self.db_path.chmod(0o600)

    def record(self, record: AccessLogRecord) -> None:
        self.initialize()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO access_logs (
                    id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.timestamp.isoformat(),
                    record.agent_id,
                    record.service,
                    record.action,
                    record.decision.value,
                    record.reason,
                    record.ttl_seconds,
                    record.verification_result.value if record.verification_result else None,
                ),
            )
            conn.commit()

    def list_recent(self, limit: int = 100) -> list[dict[str, object]]:
        self.initialize()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def export_jsonl(self, path: Path, limit: int = 100) -> None:
        entries = self.list_recent(limit=limit)
        with path.open("w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
