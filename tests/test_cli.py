from __future__ import annotations

import json
import sys
from pathlib import Path

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group, app
from hermes_vault.models import BrokerDecision, MutationResult


class StubBroker:
    def __init__(self) -> None:
        self.called_with: list[str] = []

    def verify_credential(self, service: str, alias: str | None = None) -> BrokerDecision:
        self.called_with.append(service)
        return BrokerDecision(
            allowed=True,
            service=service,
            agent_id="hermes-vault",
            reason="ok",
        )


class StubMutations:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.records: dict[str, object] = {}

    def add_credential(self, **kwargs):
        self.calls.append(("add", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service", "openai"),
            alias=kwargs.get("alias", "default"),
            credential_type=kwargs.get("credential_type", "api_key"),
            encrypted_payload="encrypted",
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service", "openai"),
            agent_id="operator",
            action="add_credential",
            reason="ok",
            record=rec,
        )

    def get_metadata(self, **kwargs):
        self.calls.append(("metadata", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service_or_id", "openai"),
            alias="default",
            credential_type="api_key",
            encrypted_payload="encrypted",
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="get_metadata",
            reason="ok",
            record=rec,
        )

    def rotate_credential(self, **kwargs):
        self.calls.append(("rotate", kwargs))
        from hermes_vault.models import CredentialRecord
        rec = CredentialRecord(
            id="test-id-123",
            service=kwargs.get("service_or_id", "openai"),
            alias="default",
            credential_type="api_key",
            encrypted_payload="encrypted",
        )
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="rotate_credential",
            reason="ok",
            record=rec,
        )

    def delete_credential(self, **kwargs):
        self.calls.append(("delete", kwargs))
        return MutationResult(
            allowed=True,
            service=kwargs.get("service_or_id", "openai"),
            agent_id="operator",
            action="delete_credential",
            reason="ok",
            metadata={"credential_id": "test-id-123"},
        )


def _fake_build_services(mutations: StubMutations | None = None, broker: StubBroker | None = None):
    """Return a fake build_services that uses stubs."""
    broker = broker or StubBroker()
    mutations = mutations or StubMutations()

    def _inner(prompt: bool = False):
        return object(), object(), broker, mutations

    return _inner


# ── verify (positional target — post issue #6) ────────────────────────────


def test_verify_accepts_positional_target(monkeypatch) -> None:
    broker = StubBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(broker=broker))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "minimax"])

    assert result.exit_code == 0
    assert broker.called_with == ["minimax"]


def test_verify_accepts_alias_flag(monkeypatch) -> None:
    broker = StubBroker()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(broker=broker))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "github", "--alias", "work"])

    assert result.exit_code == 0
    assert broker.called_with == ["github"]


def test_verify_accepts_all_flag(monkeypatch) -> None:
    """--all should iterate over all vault credentials."""

    class FakeVault:
        def list_credentials(self):
            from hermes_vault.models import CredentialRecord
            return [
                CredentialRecord(id="1", service="openai", alias="default",
                                 credential_type="api_key", encrypted_payload="x"),
                CredentialRecord(id="2", service="github", alias="work",
                                 credential_type="personal_access_token", encrypted_payload="x"),
            ]

    broker = StubBroker()

    def fake_build(prompt=False):
        return FakeVault(), object(), broker, object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--all"])

    assert result.exit_code == 0
    assert set(broker.called_with) == {"openai", "github"}


def test_verify_no_target_shows_helpful_error(monkeypatch) -> None:
    """No target and no --all should print examples."""
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify"])

    assert result.exit_code == 1
    assert "Provide a credential target" in result.output
    assert "hermes-vault verify openai" in result.output


# ── add (canonical service ID) ─────────────────────────────────────────────


def test_add_normalizes_service_name(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["add", "open_ai", "--secret", "sk-test"])

    assert result.exit_code == 0
    # The service should be normalized to 'openai'
    assert mutations.calls[0][1]["service"] == "openai"
    assert "openai" in result.output


def test_add_shows_credential_id(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["add", "openai", "--secret", "sk-test"])

    assert result.exit_code == 0
    assert "test-id-123" in result.output


# ── show-metadata (error handling) ─────────────────────────────────────────


def test_show_metadata_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def get_metadata(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "github"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_show_metadata_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def get_metadata(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "nonexistent"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_show_metadata_with_alias(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["show-metadata", "github", "--alias", "work"])

    assert result.exit_code == 0
    assert mutations.calls[0][1]["alias"] == "work"


# ── rotate (error handling) ────────────────────────────────────────────────


def test_rotate_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def rotate_credential(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "github", "--secret", "new"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_rotate_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def rotate_credential(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "nonexistent", "--secret", "new"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_rotate_shows_canonical_service(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["rotate", "openai", "--secret", "new"])

    assert result.exit_code == 0
    assert "openai" in result.output


# ── delete (error handling) ────────────────────────────────────────────────


def test_delete_requires_yes(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "openai"])

    assert result.exit_code == 1
    assert "--yes" in result.output


def test_delete_handles_ambiguous_target(monkeypatch) -> None:
    from hermes_vault.vault import AmbiguousTargetError

    class AmbiguousMutations(StubMutations):
        def delete_credential(self, **kwargs):
            raise AmbiguousTargetError("Service 'github' has 2 credentials — specify credential ID or service+alias")

    mutations = AmbiguousMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "github", "--yes"])

    assert result.exit_code == 1
    assert "Ambiguous" in result.output
    assert "--alias" in result.output


def test_delete_handles_not_found(monkeypatch) -> None:
    class NotFoundMutations(StubMutations):
        def delete_credential(self, **kwargs):
            raise KeyError("Service 'nonexistent' not found in vault")

    mutations = NotFoundMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "nonexistent", "--yes"])

    assert result.exit_code == 1
    assert "Not found" in result.output


def test_delete_shows_credential_id(monkeypatch) -> None:
    mutations = StubMutations()
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services(mutations=mutations))

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["delete", "openai", "--yes"])

    assert result.exit_code == 0
    assert "test-id-123" in result.output


# ── broker get/env (canonical ID) ──────────────────────────────────────────


def test_broker_get_normalizes_service(monkeypatch) -> None:
    """broker get should normalize service names like open_ai → openai."""
    calls = []

    class FakeBroker:
        def get_credential(self, service, purpose, agent_id):
            calls.append(service)
            return BrokerDecision(
                allowed=True, service=service, agent_id=agent_id,
                reason="ok",
            )

    def fake_build(prompt=False):
        return object(), object(), FakeBroker(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["broker", "get", "open_ai", "--agent", "hermes"])

    assert result.exit_code == 0
    assert calls == ["openai"]


def test_broker_env_normalizes_service(monkeypatch) -> None:
    calls = []

    class FakeBroker:
        def get_ephemeral_env(self, service, agent_id, ttl):
            calls.append(service)
            return BrokerDecision(
                allowed=True, service=service, agent_id=agent_id,
                reason="ok", ttl_seconds=ttl,
            )

    def fake_build(prompt=False):
        return object(), object(), FakeBroker(), object()

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["broker", "env", "gh", "--agent", "hermes"])

    assert result.exit_code == 0
    assert calls == ["github"]


# ── import (error handling) ────────────────────────────────────────────────


def test_import_requires_source(monkeypatch) -> None:
    monkeypatch.setattr("hermes_vault.cli.build_services", _fake_build_services())

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["import"])

    assert result.exit_code == 1
    assert "--from-env" in result.output or "--from-file" in result.output


# ── banner tests (unchanged) ──────────────────────────────────────────────


def test_app_shows_banner_before_root_help(monkeypatch) -> None:
    calls: list[object] = []

    monkeypatch.setattr("hermes_vault.cli._should_show_banner", lambda: True)
    monkeypatch.setattr("hermes_vault.cli._show_banner", lambda: calls.append("banner"))
    monkeypatch.setattr(sys, "argv", ["hermes-vault", "--help"])

    def fake_group(*, args=None, prog_name=None):
        calls.append(("group", args, prog_name))
        return 0

    monkeypatch.setattr("hermes_vault.cli._hermes_group", fake_group)

    assert app() == 0
    assert calls == ["banner", ("group", ["--help"], "hermes-vault")]


def test_app_respects_no_banner_for_root_help(monkeypatch) -> None:
    calls: list[object] = []

    monkeypatch.setattr("hermes_vault.cli._should_show_banner", lambda: True)
    monkeypatch.setattr("hermes_vault.cli._show_banner", lambda: calls.append("banner"))
    monkeypatch.setattr(sys, "argv", ["hermes-vault", "--no-banner", "--help"])

    def fake_group(*, args=None, prog_name=None):
        calls.append(("group", args, prog_name))
        return 0

    monkeypatch.setattr("hermes_vault.cli._hermes_group", fake_group)

    assert app() == 0
    assert calls == [("group", ["--no-banner", "--help"], "hermes-vault")]
