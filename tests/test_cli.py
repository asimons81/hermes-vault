from __future__ import annotations

import sys

from click.testing import CliRunner

from hermes_vault.cli import _hermes_group, app
from hermes_vault.models import BrokerDecision


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


def test_verify_accepts_service_flag(monkeypatch) -> None:
    broker = StubBroker()

    def fake_build_services(prompt: bool = False):
        return object(), object(), broker

    monkeypatch.setattr("hermes_vault.cli.build_services", fake_build_services)

    runner = CliRunner()
    result = runner.invoke(_hermes_group, ["verify", "--service", "minimax"])

    assert result.exit_code == 0
    assert broker.called_with == ["minimax"]


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
