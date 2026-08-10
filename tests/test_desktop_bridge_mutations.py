"""Mutation surface tests for the desktop bridge (P1).

Covers the security-architecture test matrix rows 1-9 (§7) for the bridge
mutation methods (``add``, ``rotate``, ``delete``) behind the
``allow_mutations`` opt-in:

1. add writes credential + audit row, returns metadata-only record
2. rotate replaces secret, audit row, response excludes secret
3. delete with matching confirmation deletes + audits credential_id
4. delete with missing/mismatched confirmation -> CONFIRMATION_MISMATCH, no vault write
5. without allow_mutations -> MUTATIONS_DISABLED
6. canary: raw secret never in add/rotate/delete responses or error envelopes
7. AUDIT_INTEGRITY rollback: corrupted chain -> add denied, no credential persists
8. request_id echoed + stored in audit metadata
9. renderer agent_id rejected (INVALID_PARAMS)

All fixtures use disposable tmp_path vaults; no live vault is touched.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import AppSettings
from hermes_vault.dashboard import DashboardContext
from hermes_vault.desktop_bridge import (
    DesktopBridge,
    MUTATION_METHODS,
    PROTOCOL_VERSION,
)
from hermes_vault.models import AccessLogRecord, Decision
from hermes_vault.policy import PolicyEngine
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault

CANARY_SECRET = "CANARY-RAW-SECRET-VALUE-9f2c"
CANARY_NEW_SECRET = "CANARY-ROTATED-SECRET-VALUE-77ab"


def _policy(tmp_path: Path) -> Path:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  operator:
    capabilities: [list_credentials, add_credential, scan_secrets]
    services:
      openai:
        actions: [get_env, verify, metadata, add_credential, rotate, delete]
""".lstrip(),
        encoding="utf-8",
    )
    return policy_path


def _writable_context(tmp_path: Path) -> DashboardContext:
    """Real writable context: Vault + AuditLogger(master_key) + Broker."""
    policy_path = _policy(tmp_path)
    settings = AppSettings(runtime_home=tmp_path, base_home=tmp_path, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "test-passphrase")
    audit = AuditLogger(settings.db_path, master_key=vault.key)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
    )


def _mutation_bridge(tmp_path: Path) -> tuple[DesktopBridge, DashboardContext]:
    ctx = _writable_context(tmp_path)
    bridge = DesktopBridge(
        allow_mutations=True,
        writable_context_factory=lambda prompt=True, profile=None: ctx,
    )
    return bridge, ctx


def _dispatch(
    bridge: DesktopBridge,
    method: str,
    params: dict | None = None,
    request_id: int = 1,
) -> dict:
    request: dict = {"id": request_id, "method": method, "params": params or {}}
    return bridge.handle_request(request)


def _audit_rows(ctx: DashboardContext, action: str) -> list[dict]:
    return [
        entry
        for entry in ctx.audit.list_recent(limit=100)
        if entry.get("action") == action
    ]


def _raw_count(ctx: DashboardContext) -> int:
    with sqlite3.connect(ctx.settings.db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]


# ── row 1: add writes credential + audit row, returns metadata-only record ──


def test_bridge_add_credential(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)

    response = _dispatch(
        bridge,
        "add",
        {
            "service": "openai",
            "alias": "primary",
            "credential_type": "api_key",
            "secret": CANARY_SECRET,
        },
    )

    assert response["ok"] is True
    result = response["result"]
    assert result["allowed"] is True
    assert result["action"] == "add_credential"
    assert result["service"] == "openai"
    record = result["record"]
    assert record["service"] == "openai"
    assert record["alias"] == "primary"
    assert record["credential_type"] == "api_key"
    assert "secret" not in record
    assert "encrypted_payload" not in record
    assert "has_notes" in record

    # The credential really exists in the vault (encrypted).
    records = ctx.vault.list_credentials()
    assert len(records) == 1
    assert records[0].service == "openai"
    assert records[0].alias == "primary"

    # An audit row was written.
    add_rows = _audit_rows(ctx, "add_credential")
    assert len(add_rows) == 1
    assert add_rows[0]["decision"] == "allow"

    # Response is metadata-only: the raw secret never serializes.
    assert CANARY_SECRET not in json.dumps(response)


# ── row 2: rotate replaces secret, audit row, response excludes secret ──────


def test_bridge_rotate_credential(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)
    ctx.broker.add_credential(
        agent_id="operator",
        service="openai",
        secret=CANARY_SECRET,
        alias="primary",
    )
    before = ctx.vault.resolve_credential("openai", alias="primary")

    response = _dispatch(
        bridge,
        "rotate",
        {"service_or_id": "openai", "alias": "primary", "new_secret": CANARY_NEW_SECRET},
    )

    assert response["ok"] is True
    result = response["result"]
    assert result["allowed"] is True
    assert result["action"] == "rotate_credential"
    assert CANARY_NEW_SECRET not in json.dumps(response)

    # The stored secret really changed.
    after = ctx.vault.resolve_credential("openai", alias="primary")
    assert after.id == before.id
    rotated_secret = ctx.vault.get_secret(after.id)
    original_secret = ctx.vault.get_secret(before.id)
    assert rotated_secret is not None
    assert original_secret is not None
    assert rotated_secret.secret == CANARY_NEW_SECRET
    assert original_secret.secret != CANARY_SECRET

    rotate_rows = _audit_rows(ctx, "rotate_credential")
    assert len(rotate_rows) == 1
    assert rotate_rows[0]["decision"] == "allow"


# ── row 3: delete with matching confirmation deletes + audits credential_id ─


def test_bridge_delete_with_confirmation(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)
    added = ctx.broker.add_credential(
        agent_id="operator",
        service="openai",
        secret=CANARY_SECRET,
        alias="primary",
    )
    assert added.record is not None
    credential_id = added.record.id

    response = _dispatch(
        bridge,
        "delete",
        {"service_or_id": credential_id, "confirmation": credential_id},
    )

    assert response["ok"] is True
    result = response["result"]
    assert result["allowed"] is True
    assert result["action"] == "delete_credential"
    assert result["metadata"].get("credential_id") == credential_id
    assert CANARY_SECRET not in json.dumps(response)

    # Credential is gone from the vault.
    assert _raw_count(ctx) == 0

    # Audit row carries the credential_id metadata.
    delete_rows = _audit_rows(ctx, "delete_credential")
    assert len(delete_rows) == 1
    assert delete_rows[0]["metadata"].get("credential_id") == credential_id


def test_bridge_delete_confirmation_accepts_service_alias(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)
    ctx.broker.add_credential(
        agent_id="operator",
        service="openai",
        secret=CANARY_SECRET,
        alias="primary",
    )

    response = _dispatch(
        bridge,
        "delete",
        {"service_or_id": "openai", "alias": "primary", "confirmation": "openai:primary"},
    )

    assert response["ok"] is True
    assert response["result"]["allowed"] is True
    assert _raw_count(ctx) == 0


# ── row 4: delete missing/mismatched confirmation -> CONFIRMATION_MISMATCH ──


def test_bridge_delete_denied_without_confirmation(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)
    ctx.broker.add_credential(
        agent_id="operator",
        service="openai",
        secret=CANARY_SECRET,
        alias="primary",
    )

    # Missing confirmation.
    response = _dispatch(bridge, "delete", {"service_or_id": "openai"})
    assert response["ok"] is False
    assert response["error"]["code"] == "CONFIRMATION_MISMATCH"
    assert _raw_count(ctx) == 1  # no vault write

    # Mismatched confirmation (id present but wrong).
    wrong = _dispatch(
        bridge,
        "delete",
        {"service_or_id": "openai", "confirmation": "not-the-real-id"},
    )
    assert wrong["ok"] is False
    assert wrong["error"]["code"] == "CONFIRMATION_MISMATCH"
    assert _raw_count(ctx) == 1  # still no vault write
    assert CANARY_SECRET not in json.dumps(response) + json.dumps(wrong)


# ── row 5: without allow_mutations -> MUTATIONS_DISABLED ────────────────────


def test_bridge_mutations_disabled_by_default(tmp_path: Path) -> None:
    ctx = _writable_context(tmp_path)
    bridge = DesktopBridge(context_factory=lambda prompt=True, profile=None: ctx)

    for method in MUTATION_METHODS:
        response = _dispatch(bridge, method, {"service": "openai", "secret": CANARY_SECRET})
        assert response["ok"] is False
        assert response["error"]["code"] == "MUTATIONS_DISABLED"

    # Nothing was written by the denied attempts.
    assert _raw_count(ctx) == 0


def test_bridge_mutations_disabled_does_not_build_writable_context(tmp_path: Path) -> None:
    ctx = _writable_context(tmp_path)
    called = {"writable": False}

    def writable_factory(*, prompt: bool = False, profile: str | None = None) -> DashboardContext:
        called["writable"] = True
        return ctx

    bridge = DesktopBridge(
        context_factory=lambda prompt=True, profile=None: ctx,
        allow_mutations=False,
        writable_context_factory=writable_factory,
    )

    response = _dispatch(bridge, "add", {"service": "openai", "secret": CANARY_SECRET})

    assert response["error"]["code"] == "MUTATIONS_DISABLED"
    assert called["writable"] is False


# ── row 6: canary raw secret never in responses or error envelopes ──────────


def test_mutation_responses_never_serialize_secret(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)

    # add -> duplicate add (denial) -> rotate -> delete with matching confirmation
    add = _dispatch(
        bridge,
        "add",
        {"service": "openai", "alias": "primary", "secret": CANARY_SECRET},
    )
    assert add["ok"] is True
    # Error envelope: duplicate add while the credential still exists.
    dup = _dispatch(
        bridge,
        "add",
        {"service": "openai", "alias": "primary", "secret": CANARY_SECRET},
    )
    assert dup["ok"] is False
    assert dup["error"]["code"] == "DUPLICATE"
    rotate = _dispatch(
        bridge,
        "rotate",
        {"service_or_id": "openai", "alias": "primary", "new_secret": CANARY_NEW_SECRET},
    )
    assert rotate["ok"] is True
    added = ctx.vault.resolve_credential("openai", alias="primary")
    delete = _dispatch(
        bridge,
        "delete",
        {"service_or_id": added.id, "confirmation": added.id},
    )
    assert delete["ok"] is True

    # Error envelopes: mismatched confirmation on a missing target, denied rotate.
    bad_conf = _dispatch(
        bridge,
        "delete",
        {"service_or_id": "openai", "confirmation": "wrong"},
    )
    assert bad_conf["ok"] is False
    denied_rotate = _dispatch(
        bridge,
        "rotate",
        {"service_or_id": "missing-service", "new_secret": CANARY_NEW_SECRET},
    )
    assert denied_rotate["ok"] is False

    serialized = "".join(
        json.dumps(item)
        for item in (add, dup, rotate, delete, bad_conf, denied_rotate)
    )
    assert CANARY_SECRET not in serialized
    assert CANARY_NEW_SECRET not in serialized
    assert "encrypted_payload" not in serialized


# ── row 7: AUDIT_INTEGRITY rollback -> denied, no credential persists ───────


def _write_legacy_audit_row(ctx: DashboardContext, reason: str = "legacy") -> None:
    ctx.audit.initialize()
    record = AccessLogRecord(
        agent_id="legacy-agent",
        service="openai",
        action="add_credential",
        decision=Decision.allow,
        reason=reason,
        metadata={"ticket": "fake"},
    )
    with sqlite3.connect(ctx.audit.db_path) as conn:
        conn.execute(
            """INSERT INTO access_logs (id, timestamp, agent_id, service, action, decision, reason, ttl_seconds, verification_result, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (record.id, record.timestamp.isoformat(), record.agent_id, record.service,
             record.action, record.decision.value, record.reason, record.ttl_seconds,
             None, "{}"),
        )
        conn.commit()


def test_bridge_add_rolls_back_on_integrity_failure(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)

    # Seed a legacy prefix and activate the integrity chain, then corrupt the
    # checkpoint so the next append fails (mirrors test_audit_integrity_toctou.py).
    for i in range(3):
        _write_legacy_audit_row(ctx, reason=f"setup-{i}")
    assert ctx.audit.integrity is not None
    ctx.audit.integrity.ensure_initialized()
    checkpoint_path = ctx.audit.db_path.with_name("audit.checkpoint.json")
    checkpoint_path.write_bytes(
        b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}'
    )

    response = _dispatch(
        bridge,
        "add",
        {"service": "openai", "alias": "rollback-test", "secret": CANARY_SECRET},
    )

    assert response["ok"] is False
    assert response["error"]["code"] == "AUDIT_INTEGRITY"
    assert "integrity" in response["error"]["message"].lower()

    # No credential was persisted (the mutations layer rolled it back).
    records = ctx.vault.list_credentials()
    assert all(r.alias != "rollback-test" for r in records)
    assert CANARY_SECRET not in json.dumps(response)


# ── row 8: request_id echoed + stored in audit metadata ─────────────────────


def test_request_id_echoed_and_audited(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)

    response = _dispatch(
        bridge,
        "add",
        {
            "service": "openai",
            "alias": "primary",
            "secret": CANARY_SECRET,
            "request_id": "req-123",
        },
    )

    assert response["ok"] is True
    assert response["result"]["request_id"] == "req-123"
    add_rows = _audit_rows(ctx, "add_credential")
    assert len(add_rows) == 1
    assert add_rows[0]["metadata"].get("request_id") == "req-123"


def test_request_id_must_be_alphanumeric_and_short(tmp_path: Path) -> None:
    bridge, _ = _mutation_bridge(tmp_path)

    bad = _dispatch(
        bridge,
        "add",
        {"service": "openai", "secret": CANARY_SECRET, "request_id": "has space"},
    )
    assert bad["ok"] is False
    assert bad["error"]["code"] == "INVALID_PARAMS"

    too_long = _dispatch(
        bridge,
        "add",
        {"service": "openai", "secret": CANARY_SECRET, "request_id": "x" * 65},
    )
    assert too_long["ok"] is False
    assert too_long["error"]["code"] == "INVALID_PARAMS"


# ── row 9: renderer agent_id rejected (INVALID_PARAMS) ──────────────────────


def test_renderer_agent_id_rejected(tmp_path: Path) -> None:
    bridge, ctx = _mutation_bridge(tmp_path)

    for method, params in (
        ("add", {"service": "openai", "secret": CANARY_SECRET}),
        ("rotate", {"service_or_id": "openai", "new_secret": CANARY_NEW_SECRET}),
        ("delete", {"service_or_id": "openai", "confirmation": "openai:primary"}),
    ):
        params = dict(params)
        params["agent_id"] = "renderer-supplied"
        response = _dispatch(bridge, method, params)
        assert response["ok"] is False
        assert response["error"]["code"] == "INVALID_PARAMS"

    assert _raw_count(ctx) == 0


# ── hello advertises mutation capabilities only when enabled ────────────────


def test_hello_advertises_mutations_only_when_enabled(tmp_path: Path) -> None:
    read_only_bridge, _ = _mutation_bridge(tmp_path)
    read_only_bridge._allow_mutations = False  # exercise default advertisement
    read_only = read_only_bridge.handle_request({"id": 1, "method": "hello"})
    assert read_only["result"]["read_only"] is True
    assert read_only["result"]["mutations"] is False
    assert set(MUTATION_METHODS).isdisjoint(read_only["result"]["capabilities"])

    bridge, _ = _mutation_bridge(tmp_path)
    enabled = bridge.handle_request({"id": 1, "method": "hello"})
    assert enabled["result"]["read_only"] is False
    assert enabled["result"]["mutations"] is True
    assert set(MUTATION_METHODS) <= set(enabled["result"]["capabilities"])
    assert enabled["result"]["protocol_version"] == PROTOCOL_VERSION
