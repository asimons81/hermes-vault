from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
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
                    verification_result TEXT,
                    metadata_json TEXT
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(access_logs)")}
            if "metadata_json" not in columns:
                conn.execute("ALTER TABLE access_logs ADD COLUMN metadata_json TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_logs_agent_id ON access_logs(agent_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_logs_service ON access_logs(service)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp)"
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
                    id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(record.metadata, sort_keys=True) if record.metadata else "{}",
                ),
            )
            conn.commit()

    def list_recent(
        self,
        limit: int = 100,
        agent_id: str | None = None,
        service: str | None = None,
        action: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        self.initialize()
        conditions: list[str] = []
        params: list[object] = []

        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if service is not None:
            conditions.append("service = ?")
            params.append(service)
        if action is not None:
            conditions.append("action = ?")
            params.append(action)
        if decision is not None:
            conditions.append("decision = ?")
            params.append(decision)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until is not None:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        query = f"SELECT * FROM access_logs WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
        results: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            metadata_raw = item.get("metadata_json")
            if isinstance(metadata_raw, str) and metadata_raw:
                try:
                    item["metadata"] = json.loads(metadata_raw)
                except json.JSONDecodeError:
                    item["metadata"] = {"raw": metadata_raw}
            else:
                item["metadata"] = {}
            item.pop("metadata_json", None)
            results.append(item)
        return results

    def export_jsonl(self, path: Path, limit: int = 100) -> None:
        entries = self.list_recent(limit=limit)
        with path.open("w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
