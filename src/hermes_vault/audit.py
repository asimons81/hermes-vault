from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from hermes_vault import _platform
from hermes_vault.audit_integrity.service import AuditIntegrityService
from hermes_vault.models import AccessLogRecord


class AuditLogger:
    """Records audit decisions and, when unlocked, protects each new row.

    A logger without a master key remains a read-only/backward-compatible
    legacy logger. Normal runtime construction supplies ``master_key`` from
    the unlocked :class:`Vault`, which activates the v0.21 assurance path.
    """

    def __init__(self, db_path: Path, master_key: bytes | None = None, checkpoint_path: Path | None = None) -> None:
        self.db_path = db_path
        self.master_key = master_key
        self.checkpoint_path = checkpoint_path
        self._integrity: AuditIntegrityService | None = None

    @property
    def integrity(self) -> AuditIntegrityService | None:
        if self.master_key is None:
            return None
        if self._integrity is None:
            self._integrity = AuditIntegrityService(self.db_path, self.master_key, self.checkpoint_path)
        return self._integrity

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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_agent_id ON access_logs(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_service ON access_logs(service)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp)")
            conn.commit()
        if self.db_path.exists():
            _platform.secure_file(self.db_path)

    def record(self, record: AccessLogRecord) -> None:
        self.initialize()
        if self.integrity is not None:
            self.integrity.append(record)
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO access_logs (
                    id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record.id, record.timestamp.isoformat(), record.agent_id, record.service, record.action, record.decision.value,
                 record.reason, record.ttl_seconds, record.verification_result.value if record.verification_result else None,
                 json.dumps(record.metadata, sort_keys=True) if record.metadata else "{}"),
            )
            conn.commit()

    def list_recent(self, limit: int = 100, agent_id: str | None = None, service: str | None = None, action: str | None = None, decision: str | None = None, since: datetime | None = None, until: datetime | None = None) -> list[dict[str, object]]:
        self.initialize()
        conditions: list[str] = []
        params: list[object] = []
        for field, value in (("agent_id", agent_id), ("service", service), ("action", action), ("decision", decision)):
            if value is not None:
                conditions.append(f"{field} = ?")
                params.append(value)
        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if until is not None:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"SELECT * FROM access_logs WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?", params).fetchall()
        results: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            raw = item.get("metadata_json")
            try:
                item["metadata"] = json.loads(raw) if isinstance(raw, str) and raw else {}
            except json.JSONDecodeError:
                item["metadata"] = {"raw": raw}
            item.pop("metadata_json", None)
            results.append(item)
        return results

    def export_jsonl(self, path: Path, limit: int = 100) -> None:
        with path.open("w", encoding="utf-8") as handle:
            for entry in self.list_recent(limit=limit):
                handle.write(json.dumps(entry, sort_keys=True) + "\n")