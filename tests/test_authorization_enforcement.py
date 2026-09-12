"""Authorization enforcement tests for v0.26.0 pack P2 (F-01 + F-03).

F-01 — lease ownership: an agent must only be able to list/show/renew/revoke
leases issued to itself, unless it explicitly holds the ``manage_leases``
capability (operator/auditor escape hatch). The list filter must be applied
in the DB query, never as a post-fetch filter.

F-03 — expiry at handoff: ``get_ephemeral_env()`` must deny any record whose
expiry <= now at the point of final materialization (after any OAuth
refresh), unless the operator explicitly set ``allow_expired_env``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.models import (
    AgentCapability,
    AgentPolicy,
    LeaseStatus,
    PolicyConfig,
    ServiceAction,
    ServicePolicyEntry,
    VerificationCategory,
    VerificationResult,
    utc_now,
)
from hermes_vault.oauth.oauth_refresh import RefreshEngine
from hermes_vault.oauth.providers import OAuthProviderRegistry
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault


class StubVerifier:
    def verify(self, service: str, secret: str) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.valid,
            success=True,
            reason="ok",
        )


_LEASE_ACTIONS = [
    ServiceAction.get_env,
    ServiceAction.issue_lease,
    ServiceAction.list_leases,
    ServiceAction.show_lease,
    ServiceAction.renew_lease,
    ServiceAction.revoke_lease,
]


def _agent(
    services: list[str],
    actions: list[ServiceAction] | None = None,
    capabilities: list[AgentCapability] | None = None,
    allow_expired_env: bool | None = None,
    service_allow_expired_env: bool | None = None,
    omit_capabilities: bool = False,
) -> AgentPolicy:
    """Build an AgentPolicy; ``omit_capabilities`` mimics a legacy policy."""
    kwargs: dict = {
        "services": services,
        "service_actions": {
            service: ServicePolicyEntry(
                actions=actions if actions is not None else list(_LEASE_ACTIONS),
                allow_expired_env=service_allow_expired_env,
            )
            for service in services
        },
        "max_ttl_seconds": 900,
        "ephemeral_env_only": True,
    }
    if allow_expired_env is not None:
        kwargs["allow_expired_env"] = allow_expired_env
    if not omit_capabilities:
        kwargs["capabilities"] = capabilities if capabilities is not None else []
    return AgentPolicy(**kwargs)


def _make_broker(
    tmp_path: Path,
    agents: dict[str, AgentPolicy],
) -> tuple[Vault, Broker]:
    vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
    vault.add_credential("openai", "sk-openai", "api_key", alias="primary")
    policy = PolicyEngine(PolicyConfig(agents=agents))
    audit = AuditLogger(tmp_path / "vault.db")
    broker = Broker(vault, policy, StubVerifier(), audit)
    return vault, broker


def _two_agent_broker(
    tmp_path: Path,
    operator: bool = False,
    legacy: bool = False,
) -> tuple[Vault, Broker]:
    """agent-a and agent-b hold IDENTICAL service policy on openai.

    The only difference between them is who owns the lease — exactly the
    F-01 scenario. ``operator`` adds a third agent holding manage_leases;
    ``legacy`` adds a legacy agent with no capabilities field at all.
    """
    agents: dict[str, AgentPolicy] = {
        "agent-a": _agent(["openai"]),
        "agent-b": _agent(["openai"]),
    }
    if operator:
        agents["operator"] = _agent(["openai"], capabilities=[AgentCapability.manage_leases])
    if legacy:
        agents["legacy-agent"] = _agent(["openai"], omit_capabilities=True)
    return _make_broker(tmp_path, agents)


# ── F-01: lease ownership ──────────────────────────────────────────────


class TestLeaseOwnership:
    def test_cross_agent_show_denied(self, tmp_path: Path) -> None:
        """agent B cannot view agent A's lease even with identical service policy."""
        vault, broker = _two_agent_broker(tmp_path)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")

        decision = broker.show_lease("agent-b", issued.metadata["lease"]["id"])

        assert decision.allowed is False
        assert "manage_leases" in decision.reason
        # The denial must not leak the lease payload.
        assert "lease" not in decision.metadata
        assert decision.metadata.get("owner_agent_id") == "agent-a"

    def test_cross_agent_renew_denied_and_lease_untouched(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")
        lease_id = issued.metadata["lease"]["id"]

        decision = broker.renew_lease("agent-b", lease_id, 300)

        assert decision.allowed is False
        assert "manage_leases" in decision.reason
        stored = vault.get_lease(lease_id)
        assert stored is not None
        assert stored.renew_count == 0
        assert stored.status is LeaseStatus.active

    def test_cross_agent_revoke_denied_and_lease_untouched(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")
        lease_id = issued.metadata["lease"]["id"]

        decision = broker.revoke_lease("agent-b", lease_id, reason="hostile")

        assert decision.allowed is False
        assert "manage_leases" in decision.reason
        stored = vault.get_lease(lease_id)
        assert stored is not None
        assert stored.status is LeaseStatus.active
        assert stored.revoked_at is None

    def test_cross_agent_list_hides_other_agents_leases(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path)
        a_lease = vault.issue_lease(
            "openai", agent_id="agent-a", ttl_seconds=600, alias="primary",
        )
        b_lease = vault.issue_lease(
            "openai", agent_id="agent-b", ttl_seconds=600, alias="primary",
        )

        decision = broker.list_leases("agent-b")

        assert decision.allowed is True
        visible_ids = {lease["id"] for lease in decision.metadata["leases"]}
        assert visible_ids == {b_lease.id}
        assert a_lease.id not in visible_ids

    def test_list_ownership_filter_applied_in_db_query(self, tmp_path: Path) -> None:
        """The agent_id filter must reach vault.list_leases (DB-level), not be
        a post-fetch filter in the broker."""
        vault, broker = _two_agent_broker(tmp_path, operator=True)
        calls: list[dict] = []
        original = vault.list_leases

        def spy(*args, **kwargs):
            calls.append(kwargs)
            return original(*args, **kwargs)

        vault.list_leases = spy  # type: ignore[method-assign]

        broker.list_leases("agent-b")
        broker.list_leases("operator")

        assert calls[0].get("agent_id") == "agent-b", (
            "non-operator list must filter by agent_id in the DB query"
        )
        assert calls[1].get("agent_id") is None, (
            "manage_leases operator must not be ownership-filtered"
        )

    def test_owner_still_allowed_on_own_leases(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")
        lease_id = issued.metadata["lease"]["id"]

        shown = broker.show_lease("agent-a", lease_id)
        renewed = broker.renew_lease("agent-a", lease_id, 300)
        revoked = broker.revoke_lease("agent-a", lease_id, reason="done")

        assert shown.allowed is True
        assert renewed.allowed is True
        assert revoked.allowed is True

    def test_manage_leases_operator_can_administer_other_agents_leases(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path, operator=True)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")
        lease_id = issued.metadata["lease"]["id"]

        shown = broker.show_lease("operator", lease_id)
        renewed = broker.renew_lease("operator", lease_id, 300)
        listed = broker.list_leases("operator")
        revoked = broker.revoke_lease("operator", lease_id, reason="audit cleanup")

        assert shown.allowed is True
        assert renewed.allowed is True
        assert revoked.allowed is True
        # Operator's unfiltered list sees agent-a's lease.
        assert lease_id in {lease["id"] for lease in listed.metadata["leases"]}

    def test_manage_leases_does_not_bypass_service_policy(self, tmp_path: Path) -> None:
        """The operator capability escapes OWNERSHIP, not service policy."""
        agents = {
            "agent-a": _agent(["openai"]),
            "operator": _agent(
                ["openai"],
                actions=[ServiceAction.issue_lease, ServiceAction.list_leases],
                capabilities=[AgentCapability.manage_leases],
            ),
        }
        vault, broker = _make_broker(tmp_path, agents)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")

        decision = broker.show_lease("operator", issued.metadata["lease"]["id"])

        assert decision.allowed is False
        assert "show_lease" in decision.reason

    def test_legacy_agent_does_not_get_manage_leases_implicitly(self, tmp_path: Path) -> None:
        """Legacy policies (no capabilities field) implicitly grant all OTHER
        capabilities for backward compatibility — manage_leases must NOT be
        one of them. Ownership is the default; cross-agent is opt-in only."""
        vault, broker = _two_agent_broker(tmp_path, legacy=True)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")
        lease_id = issued.metadata["lease"]["id"]

        decision = broker.show_lease("legacy-agent", lease_id)

        assert decision.allowed is False
        assert "manage_leases" in decision.reason

    def test_cross_agent_denials_are_audited(self, tmp_path: Path) -> None:
        vault, broker = _two_agent_broker(tmp_path)
        issued = broker.issue_lease("agent-a", "openai", 600, alias="primary")

        broker.show_lease("agent-b", issued.metadata["lease"]["id"])

        entries = broker.audit.list_recent(limit=10, action="show_lease")
        denied = [e for e in entries if e.get("decision") == "deny"]
        assert denied, "cross-agent denial must land in the audit log"


# ── F-03: expiry at env handoff ────────────────────────────────────────


class TestExpiryAtHandoff:
    def _expired_broker(
        self,
        tmp_path: Path,
        agent_kwargs: dict | None = None,
        service_allow_expired_env: bool | None = None,
        expiry: datetime | None = None,
    ) -> tuple[Vault, Broker, datetime]:
        vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
        vault.add_credential("openai", "sk-stale", "api_key", alias="primary")
        past = expiry if expiry is not None else utc_now() - timedelta(days=2)
        vault.set_expiry("openai", past, alias="primary")
        actions = [ServiceAction.get_env]
        agents = {
            "hermes": _agent(
                ["openai"],
                actions=actions,
                service_allow_expired_env=service_allow_expired_env,
                **(agent_kwargs or {}),
            ),
        }
        policy = PolicyEngine(PolicyConfig(agents=agents))
        audit = AuditLogger(tmp_path / "vault.db")
        return vault, Broker(vault, policy, StubVerifier(), audit), past

    def test_expired_api_key_denied_at_handoff(self, tmp_path: Path) -> None:
        vault, broker, past = self._expired_broker(tmp_path)

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is False
        assert "expired" in decision.reason
        assert decision.env == {}
        assert decision.metadata.get("expired_at") == past.isoformat()
        assert decision.metadata.get("allow_expired_env") is False

    def test_expired_deny_is_audited(self, tmp_path: Path) -> None:
        _, broker, _ = self._expired_broker(tmp_path)

        broker.get_ephemeral_env("openai", "hermes", 900)

        entries = broker.audit.list_recent(limit=10, action="get_ephemeral_env")
        denied = [e for e in entries if e.get("decision") == "deny"]
        assert denied and "expired" in str(denied[0]["reason"])

    def test_expiry_exactly_now_denied(self, tmp_path: Path, monkeypatch) -> None:
        """Boundary: expiry == now is expired (the check is <=, not <)."""
        import hermes_vault.broker as broker_mod

        frozen = utc_now().replace(microsecond=0)

        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is not None:
                    return frozen.astimezone(tz)
                return frozen

        monkeypatch.setattr(broker_mod, "datetime", FrozenDateTime)
        _, broker, _ = self._expired_broker(tmp_path, expiry=frozen)

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is False
        assert "expired" in decision.reason

    def test_future_expiry_still_serves(self, tmp_path: Path) -> None:
        vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
        vault.add_credential("openai", "sk-live", "api_key", alias="primary")
        vault.set_expiry("openai", utc_now() + timedelta(days=1), alias="primary")
        policy = PolicyEngine(
            PolicyConfig(
                agents={
                    "hermes": _agent(["openai"], actions=[ServiceAction.get_env]),
                }
            )
        )
        broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is True
        assert decision.env["OPENAI_API_KEY"] == "sk-live"

    def test_allow_expired_env_service_override_serves_with_warning(self, tmp_path: Path) -> None:
        _, broker, _ = self._expired_broker(tmp_path, service_allow_expired_env=True)

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is True
        assert decision.env["OPENAI_API_KEY"] == "sk-stale"
        kinds = {w["kind"] for w in decision.metadata.get("warnings", [])}
        assert "credential_expired" in kinds

    def test_allow_expired_env_agent_default_serves(self, tmp_path: Path) -> None:
        _, broker, _ = self._expired_broker(tmp_path, agent_kwargs={"allow_expired_env": True})

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is True
        assert decision.env["OPENAI_API_KEY"] == "sk-stale"

    def test_allow_expired_env_service_false_beats_agent_true(self, tmp_path: Path) -> None:
        _, broker, _ = self._expired_broker(
            tmp_path,
            agent_kwargs={"allow_expired_env": True},
            service_allow_expired_env=False,
        )

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is False
        assert "expired" in decision.reason


class TestExpiryAfterOAuthRefresh:
    """The expiry re-check must run AFTER OAuth refresh — a refresh that moves
    the expiry forward rescues an expired token; one that leaves it expired
    (or fails) still denies at materialization."""

    @staticmethod
    def _seed(vault: Vault, expiry: datetime) -> None:
        vault.add_credential(
            "openai", "old_access", "oauth_access_token",
            alias="default", replace_existing=True,
        )
        vault.set_expiry("openai", expiry, alias="default")
        vault.add_credential(
            "openai", "old_refresh", "oauth_refresh_token",
            alias="refresh", replace_existing=True,
        )

    @staticmethod
    def _registry(tmp_path: Path) -> OAuthProviderRegistry:
        path = tmp_path / "providers.yaml"
        path.write_text(
            "providers:\n"
            "  openai:\n    name: OpenAI\n"
            "    authorization_endpoint: https://example.com/auth\n"
            "    token_endpoint: https://example.com/token\n"
        )
        return OAuthProviderRegistry(path)

    def _broker(self, tmp_path: Path, expiry: datetime) -> Broker:
        vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
        self._seed(vault, expiry)
        refresh_engine = RefreshEngine(vault=vault, registry=self._registry(tmp_path))
        policy = PolicyEngine(
            PolicyConfig(
                agents={
                    "dwight": _agent(
                        ["openai"], actions=[ServiceAction.get_env, ServiceAction.rotate],
                    ),
                }
            )
        )
        return Broker(
            vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"),
            refresh_engine=refresh_engine,
        )

    def test_expired_oauth_refreshed_then_served(self, tmp_path: Path) -> None:
        """Expired token + successful refresh (new future expiry) still hands off —
        proves the expiry gate re-checks the POST-refresh record."""
        from tests.test_broker import MockTokenEndpoint

        broker = self._broker(tmp_path, utc_now() - timedelta(seconds=10))
        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "fresh_access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "fresh_refresh",
            "scope": "openid",
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

        assert decision.allowed is True, decision.reason
        assert decision.env["OPENAI_API_KEY"] == "fresh_access"
        assert decision.metadata["oauth_refresh"]["refreshed"] is True

    def test_refresh_without_expires_in_clears_expiry_and_serves(self, tmp_path: Path) -> None:
        """A refresh that returns no expires_in clears the stored expiry
        (unknown). The handoff succeeds: the token was just rotated by the
        provider, and an unknown expiry is not provably expired (consistent
        with _ensure_oauth_freshness' no-expiry pass-through). The F-03 gate
        only denies records whose expiry is known and <= now."""
        from tests.test_broker import MockTokenEndpoint

        broker = self._broker(tmp_path, utc_now() - timedelta(seconds=10))
        endpoint = MockTokenEndpoint(success_tokens={
            "access_token": "fresh_but_undated",
            "token_type": "Bearer",
            "refresh_token": "fresh_refresh",
            "scope": "openid",
            # no expires_in
        })

        with patch("hermes_vault.oauth.oauth_refresh.requests.post", side_effect=endpoint.handler):
            decision = broker.get_ephemeral_env("openai", "dwight", ttl=900, alias="default")

        assert decision.allowed is True
        assert decision.env["OPENAI_API_KEY"] == "fresh_but_undated"
        assert decision.metadata["oauth_refresh"]["refreshed"] is True


class TestYamlPolicyParsing:
    def test_allow_expired_env_and_manage_leases_from_yaml(self, tmp_path: Path) -> None:
        """Both knobs survive YAML v2 preprocessing and resolution."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "agents:\n"
            "  ops:\n"
            "    services:\n"
            "      openai:\n"
            "        actions: [get_env, list_leases]\n"
            "        allow_expired_env: true\n"
            "    capabilities: [manage_leases]\n"
            "  worker:\n"
            "    services:\n"
            "      openai:\n"
            "        actions: [get_env]\n"
        )
        engine = PolicyEngine.from_yaml(policy_file)

        ok, _ = engine.can_manage_leases("ops")
        assert ok is True
        ok, _ = engine.can_manage_leases("worker")
        assert ok is False
        assert engine.allow_expired_env("ops", "openai") is True
        assert engine.allow_expired_env("worker", "openai") is False

    def test_naive_expiry_treated_as_utc(self, tmp_path: Path) -> None:
        """A naive (tz-unaware) stored expiry must be interpreted as UTC, not
        crash or slip through the gate."""
        vault = Vault(tmp_path / "vault.db", tmp_path / "salt.bin", "test-passphrase")
        vault.add_credential("openai", "sk-stale", "api_key", alias="primary")
        naive_past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
        vault.set_expiry("openai", naive_past, alias="primary")
        policy = PolicyEngine(
            PolicyConfig(
                agents={"hermes": _agent(["openai"], actions=[ServiceAction.get_env])},
            )
        )
        broker = Broker(vault, policy, StubVerifier(), AuditLogger(tmp_path / "vault.db"))

        decision = broker.get_ephemeral_env("openai", "hermes", 900)

        assert decision.allowed is False
        assert "expired" in decision.reason
