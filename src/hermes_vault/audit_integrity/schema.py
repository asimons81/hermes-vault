from __future__ import annotations
import sqlite3

SCHEMA_VERSION = "audit-integrity-schema-v1"


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS access_logs (
      id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, agent_id TEXT NOT NULL, service TEXT NOT NULL, action TEXT NOT NULL,
      decision TEXT NOT NULL, reason TEXT NOT NULL, ttl_seconds INTEGER, verification_result TEXT, metadata_json TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_integrity_state (      id INTEGER PRIMARY KEY CHECK (id = 1), schema_version TEXT NOT NULL, migration_state TEXT NOT NULL,
      active_segment_id TEXT, legacy_cutoff_timestamp TEXT, legacy_cutoff_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_integrity_segments (
      segment_id TEXT PRIMARY KEY, segment_number INTEGER NOT NULL UNIQUE, chain_version TEXT NOT NULL,
      serialization_version TEXT NOT NULL, key_derivation_version TEXT NOT NULL, entry_signature_version TEXT NOT NULL,
      checkpoint_signature_version TEXT NOT NULL, entry_public_key TEXT NOT NULL, checkpoint_public_key TEXT NOT NULL,
      sequence_start INTEGER NOT NULL, sequence_end INTEGER, predecessor_segment_id TEXT, predecessor_tip_digest TEXT,
      transition_reason TEXT NOT NULL CHECK (transition_reason IN ('fresh_vault','legacy_migration','master_key_rotation','checkpoint_recovery')),
      legacy_count INTEGER NOT NULL DEFAULT 0, legacy_snapshot_digest TEXT, legacy_first_id TEXT, legacy_last_id TEXT,
      created_at TEXT NOT NULL, closed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_integrity_records (
      sequence INTEGER PRIMARY KEY, segment_id TEXT NOT NULL, access_log_id TEXT NOT NULL UNIQUE, previous_digest TEXT NOT NULL,
      entry_digest TEXT NOT NULL, signature TEXT NOT NULL, chain_version TEXT NOT NULL, serialization_version TEXT NOT NULL,
      created_at TEXT NOT NULL, FOREIGN KEY(access_log_id) REFERENCES access_logs(id)
    );
    CREATE INDEX IF NOT EXISTS idx_audit_integrity_records_segment_sequence ON audit_integrity_records(segment_id, sequence);
    CREATE INDEX IF NOT EXISTS idx_audit_integrity_records_access_log ON audit_integrity_records(access_log_id);
    CREATE INDEX IF NOT EXISTS idx_audit_integrity_records_digest ON audit_integrity_records(entry_digest);
    CREATE TABLE IF NOT EXISTS audit_verification_runs (
      verification_id TEXT PRIMARY KEY, verified_at TEXT NOT NULL, status TEXT NOT NULL, reason_code TEXT,
      segment_id TEXT, chain_version TEXT, verified_count INTEGER NOT NULL, legacy_count INTEGER NOT NULL,
      first_sequence INTEGER, last_sequence INTEGER, checkpoint_status TEXT NOT NULL, failure_sequence INTEGER, registry_digest TEXT
    );
    """)