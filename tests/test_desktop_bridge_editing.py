"""Issue #90 — desktop bridge mutation methods for metadata editing and origin rebinding.

Bridge-surface coverage (mirrors test_desktop_bridge_mutations.py):

1. ``update_metadata`` edits alias/tags/notes through Broker → VaultMutations
   with a distinct audit action; response is metadata-only
2. ``rebind_origin`` moves the credential to a new origin; response is
   metadata-only; audit metadata records old/new service
3. rebind requires ``confirmation`` matching the NEW origin exactly
4. rebind confirmation equal to the OLD origin is rejected
5. missing/empty confirmation → CONFIRMATION_MISMATCH before any write
6. both methods are disabled without ``allow_mutations``
7. renderer-supplied agent_id is rejected
8. malformed params fail closed
9. canary: the raw secret never appears in any response envelope
10. hello advertises the new methods only when mutations are enabled
11. audit-integrity failure → AUDIT_INTEGRITY envelope, row unchanged

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
from hermes_vault.policy import PolicyEngine
from hermes_vault.verifier import Verifier
from hermes_vault.vault import Vault

CANARY_SECRET = "CANARY-RAW-SECRET-VALUE-90ab"


def _policy(tmp_path: Path) -> Path:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
agents:
  operator:
    capabilities: [list_credentials, add_credential]
    services:
      openai:
        actions: [get_env, verify, metadata, add_credential, rotate, delete, update_metadata, rebind_origin]
      github:
        actions: [get_env, verify, metadata, add_credential, rotate, delete, update_metadata, rebind_origin]
""".lstrip(),
        encoding="utf-8",
    )
    return policy_path


def _writable_context(tmp_path: Path) -> DashboardContext:
    policy_path = _policy(tmp_path)
    settings = AppSettings(runtime_home=tmp_path, base_home=tmp_path, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "test-passphrase")
    audit = AuditLogger(settings.db_path, master_key=vault.key)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    return DashboardContext(settings=settings, vault=vault, policy=policy, broker=broker, audit=audit)


def _bridge(tmp_path: Path, *, allow_mutations: bool = True) -> tuple[DesktopBridge, DashboardContext]:
    ctx = _writable_context(tmp_path)
    bridge = DesktopBridge(
        allow_mutations=allow_mutations,
        writable_context_factory=lambda prompt=True, profile=None: ctx,
    )
    return bridge, ctx


def _dispatch(bridge: DesktopBridge, method: str, params: dict | None = None) -> dict:
    return bridge.handle_request({"id": 1, "method": method, "params": params or {}})


def _add_credential(bridge: DesktopBridge, ctx: DashboardContext, alias: str = "default") -> dict:
    resp = _dispatch(bridge, "add", {
        "service": "openai",
        "alias": alias,
        "credential_type": "api_key",
        "secret": CANARY_SECRET,
    })
    assert resp["ok"] is True, resp
    return resp["result"]


def _audit_actions(ctx: DashboardContext) -> list[str]:
    return [str(e.get("action")) for e in ctx.audit.list_recent(limit=100)]


def _raw_secret_count(ctx: DashboardContext) -> int:
    with sqlite3.connect(ctx.settings.db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]


# ── 1. update_metadata ───────────────────────────────────────────────────────


def test_bridge_update_metadata_edits_alias(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    added = _add_credential(bridge, ctx)

    resp = _dispatch(bridge, "update_metadata", {
        "service_or_id": "openai",
        "alias": "default",
        "new_alias": "renamed",
        "tags": ["prod"],
        "notes": "edited via bridge",
    })
    assert resp["ok"] is True, resp
    result = resp["result"]
    assert result["action"] == "update_credential_metadata"
    assert result["record"]["alias"] == "renamed"
    assert result["record"]["tags"] == ["prod"]
    assert CANARY_SECRET not in json.dumps(resp)

    # the secret is unchanged
    secret = ctx.vault.get_secret(added["record"]["id"])
    assert secret is not None and secret.secret == CANARY_SECRET
    # distinct audit action
    assert "update_credential_metadata" in _audit_actions(ctx)


def test_bridge_update_metadata_requires_a_field(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)

    resp = _dispatch(bridge, "update_metadata", {"service_or_id": "openai"})
    assert resp["ok"] is False
    assert resp["error"]["code"] == "INVALID_PARAMS"
    assert "at least one" in resp["error"]["message"]


def test_bridge_update_metadata_not_found(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    resp = _dispatch(bridge, "update_metadata", {
        "service_or_id": "ghost", "new_alias": "x"
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "DENIED"
    assert "not found" in resp["error"]["message"]


# ── 2/3/4/5. rebind_origin ───────────────────────────────────────────────────


def test_bridge_rebind_origin_with_new_origin_confirmation(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    added = _add_credential(bridge, ctx)
    record_id = added["record"]["id"]

    resp = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "openai",
        "alias": "default",
        "new_service": "github",
        "confirmation": "github",  # the NEW origin — the typed destination
    })
    assert resp["ok"] is True, resp
    result = resp["result"]
    assert result["action"] == "rebind_credential_origin"
    assert result["record"]["service"] == "github"
    assert result["record"]["id"] == record_id
    assert CANARY_SECRET not in json.dumps(resp)

    # secret preserved
    secret = ctx.vault.get_secret(record_id)
    assert secret is not None and secret.secret == CANARY_SECRET
    # distinct audit action with old/new recorded
    raw_entries = ctx.audit.list_recent(limit=100)
    entries = [e for e in raw_entries if e.get("action") == "rebind_credential_origin"]
    assert len(entries) == 1
    metadata = dict(entries[0].get("metadata") or {})
    assert metadata.get("old_service") == "openai"
    assert metadata.get("new_service") == "github"
    assert CANARY_SECRET not in json.dumps(entries[0])


def test_bridge_rebind_confirmation_mismatch_rejects_before_write(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    added = _add_credential(bridge, ctx)
    record_id = added["record"]["id"]
    payload_before = ctx.vault.resolve_credential(record_id).encrypted_payload

    resp = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "openai",
        "new_service": "github",
        "confirmation": "typo-wrong-origin",
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "CONFIRMATION_MISMATCH"
    # nothing changed
    assert ctx.vault.resolve_credential(record_id).encrypted_payload == payload_before
    assert "rebind_credential_origin" not in _audit_actions(ctx)


def test_bridge_rebind_confirmation_old_origin_rejected(tmp_path: Path) -> None:
    """Confirming with the OLD origin must not pass: the destination is what
    is being authorized."""
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)

    resp = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "openai",
        "new_service": "github",
        "confirmation": "openai",
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "CONFIRMATION_MISMATCH"


def test_bridge_rebind_missing_confirmation(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)
    resp = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "openai",
        "new_service": "github",
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "CONFIRMATION_MISMATCH"


def test_bridge_rebind_unknown_target_denied(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    resp = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "ghost",
        "new_service": "github",
        "confirmation": "github",
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "DENIED"


# ── 6. opt-in gating ─────────────────────────────────────────────────────────


def test_bridge_editing_methods_disabled_by_default(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path, allow_mutations=False)
    for method in ("update_metadata", "rebind_origin"):
        resp = _dispatch(bridge, method, {"service_or_id": "openai"})
        assert resp["ok"] is False
        assert resp["error"]["code"] == "MUTATIONS_DISABLED"
    assert _raw_secret_count(ctx) == 0


# ── 7. renderer identity ─────────────────────────────────────────────────────


def test_bridge_editing_rejects_renderer_agent_id(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)
    for method, params in (
        ("update_metadata", {"service_or_id": "openai", "new_alias": "x", "agent_id": "hermes"}),
        ("rebind_origin", {"service_or_id": "openai", "new_service": "github", "confirmation": "github", "agent_id": "hermes"}),
    ):
        resp = _dispatch(bridge, method, params)
        assert resp["ok"] is False
        assert resp["error"]["code"] == "INVALID_PARAMS"
        assert "agent_id" in resp["error"]["message"]


# ── 8. malformed params fail closed ──────────────────────────────────────────


def test_bridge_update_metadata_malformed_params(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)
    bad_cases = [
        {"service_or_id": ""},  # missing target
        {"service_or_id": "openai", "new_alias": 123},  # non-string alias
        {"service_or_id": "openai", "new_alias": "   "},  # whitespace-only alias
        {"service_or_id": "openai", "tags": "prod"},  # tags not a list
        {"service_or_id": "openai", "tags": [1, 2]},  # non-string tags
        {"service_or_id": "openai", "notes": 42},  # non-string notes
    ]
    for params in bad_cases:
        resp = _dispatch(bridge, "update_metadata", params)
        assert resp["ok"] is False, params
        assert resp["error"]["code"] == "INVALID_PARAMS", params
    # the credential is untouched by every malformed attempt
    record = ctx.vault.resolve_credential("openai")
    assert record.alias == "default"


def test_bridge_rebind_malformed_params(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)
    bad_cases = [
        {"service_or_id": "openai", "new_service": "github"},  # no confirmation
        {"service_or_id": "openai", "new_service": "", "confirmation": "github"},  # empty new origin
        {"service_or_id": "openai", "new_service": 5, "confirmation": "github"},  # non-string
        {"service_or_id": "openai", "new_service": "github", "confirmation": 7},  # non-string confirmation
    ]
    for params in bad_cases:
        resp = _dispatch(bridge, "rebind_origin", params)
        assert resp["ok"] is False, params
        assert resp["error"]["code"] in ("INVALID_PARAMS", "CONFIRMATION_MISMATCH"), params
    record = ctx.vault.resolve_credential("openai")
    assert record.service == "openai"


# ── 9. canary ────────────────────────────────────────────────────────────────


def test_editing_responses_never_serialize_secret(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    _add_credential(bridge, ctx)

    ok_edit = _dispatch(bridge, "update_metadata", {"service_or_id": "openai", "new_alias": "safe"})
    assert ok_edit["ok"] is True
    assert CANARY_SECRET not in json.dumps(ok_edit)

    ok_rebind = _dispatch(bridge, "rebind_origin", {
        "service_or_id": "openai", "alias": "safe", "new_service": "github", "confirmation": "github",
    })
    assert ok_rebind["ok"] is True
    assert CANARY_SECRET not in json.dumps(ok_rebind)
    # error envelopes too
    err = _dispatch(bridge, "update_metadata", {"service_or_id": "nope", "new_alias": "x"})
    assert err["ok"] is False
    assert CANARY_SECRET not in json.dumps(err)


# ── 10. capability negotiation ───────────────────────────────────────────────


def test_hello_advertises_editing_methods_only_when_enabled(tmp_path: Path) -> None:
    read_only_bridge, _ = _bridge(tmp_path, allow_mutations=False)
    read_only = _dispatch(read_only_bridge, "hello")
    assert read_only["result"]["mutations"] is False
    assert set(MUTATION_METHODS).isdisjoint(read_only["result"]["capabilities"])
    assert "update_metadata" in MUTATION_METHODS
    assert "rebind_origin" in MUTATION_METHODS

    enabled_dir = tmp_path / "enabled"
    enabled_dir.mkdir()
    (enabled_dir / "policy.yaml").write_text((tmp_path / "policy.yaml").read_text(), encoding="utf-8")
    enabled_bridge, _ = _bridge(enabled_dir, allow_mutations=True)
    enabled = _dispatch(enabled_bridge, "hello")
    assert enabled["result"]["mutations"] is True
    assert set(MUTATION_METHODS) <= set(enabled["result"]["capabilities"])
    # old methods unchanged
    assert {"add", "rotate", "delete"} <= set(enabled["result"]["capabilities"])
    assert enabled["result"]["protocol_version"] == PROTOCOL_VERSION


# ── 11. audit rollback ───────────────────────────────────────────────────────


def test_bridge_editing_rolls_back_on_integrity_failure(tmp_path: Path) -> None:
    bridge, ctx = _bridge(tmp_path)
    added = _add_credential(bridge, ctx)
    record_id = added["record"]["id"]
    before = ctx.vault.resolve_credential(record_id)

    checkpoint = ctx.settings.db_path.with_name("audit.checkpoint.json")
    checkpoint.write_bytes(
        b'{"format": "hermes-vault-audit-checkpoint", "version": "audit-checkpoint-v1", "signature": "bogus"}'
    )

    resp = _dispatch(bridge, "update_metadata", {
        "service_or_id": "openai", "new_alias": "rolled-back"
    })
    assert resp["ok"] is False
    assert resp["error"]["code"] == "AUDIT_INTEGRITY"
    after = ctx.vault.resolve_credential(record_id)
    assert after.alias == before.alias
    secret_after = ctx.vault.get_secret(record_id)
    assert secret_after is not None and secret_after.secret == CANARY_SECRET
