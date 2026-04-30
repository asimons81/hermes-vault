from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.models import (
    AccessLogRecord,
    AgentPolicy,
    Decision,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault


def _make_policy_with_env(agent: str = "hermes", service: str = "openai") -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(
            agents={
                agent: AgentPolicy(
                    services=[service],
                    ephemeral_env_only=True,
                    max_ttl_seconds=1800,
                    service_actions={
                        service: ServicePolicyEntry(actions=[ServiceAction.get_env]),
                    },
                )
            }
        )
    )


def test_broker_no_expiry_warnings_when_unset(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test-passphrase")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    expiry_warnings = [w for w in warnings if w["kind"] in ("credential_expiring_soon", "credential_expired")]
    assert len(expiry_warnings) == 0


def test_broker_expiry_warning_when_expiring_soon(tmp_path: Path) -> None:
    os.environ["HERMES_VAULT_EXPIRY_WARNING_DAYS"] = "7"
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    expiry = datetime.now(timezone.utc) + timedelta(days=3)
    vault.set_expiry("openai", expiry, alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    expiry_warnings = [w for w in warnings if w["kind"] == "credential_expiring_soon"]
    assert len(expiry_warnings) == 1
    assert expiry_warnings[0]["service"] == "openai"


def test_broker_expired_warning(tmp_path: Path) -> None:
    os.environ["HERMES_VAULT_EXPIRY_WARNING_DAYS"] = "7"
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    expiry = datetime.now(timezone.utc) - timedelta(days=2)
    vault.set_expiry("openai", expiry, alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    expired = [w for w in warnings if w["kind"] == "credential_expired"]
    assert len(expired) == 1


def test_broker_backup_reminder_when_no_backup(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    backup_warnings = [w for w in warnings if w["kind"] in ("no_backup", "backup_overdue")]
    assert len(backup_warnings) >= 1


def test_broker_no_backup_reminder_when_recent(tmp_path: Path) -> None:
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="backup exported",
        timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
    ))
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    backup_warnings = [w for w in warnings if w["kind"] in ("no_backup", "backup_overdue")]
    assert len(backup_warnings) == 0


def test_broker_backup_reminder_when_stale(tmp_path: Path) -> None:
    os.environ["HERMES_VAULT_BACKUP_REMINDER_DAYS"] = "30"
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-1", "api_key", alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    audit.record(AccessLogRecord(
        agent_id="operator",
        service="*",
        action="export_backup",
        decision=Decision.allow,
        reason="backup",
        timestamp=datetime.now(timezone.utc) - timedelta(days=60),
    ))
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    overdue = [w for w in warnings if w["kind"] == "backup_overdue"]
    assert len(overdue) >= 1


def test_warnings_never_contain_raw_secrets(tmp_path: Path) -> None:
    os.environ["HERMES_VAULT_EXPIRY_WARNING_DAYS"] = "7"
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    vault = Vault(db, salt, "test")
    vault.add_credential("openai", "sk-test-secret-abc", "api_key", alias="primary")
    expiry = datetime.now(timezone.utc) + timedelta(days=3)
    vault.set_expiry("openai", expiry, alias="primary")
    policy = _make_policy_with_env()
    audit = AuditLogger(db)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    decision = broker.get_ephemeral_env("openai", "hermes", 900)
    warnings = decision.metadata.get("warnings", [])
    assert warnings
    for w in warnings:
        assert "sk-test-secret-abc" not in str(w)
