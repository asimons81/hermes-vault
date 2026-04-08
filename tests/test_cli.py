from __future__ import annotations

from typer.testing import CliRunner

from hermes_vault.cli import app
from hermes_vault.models import BrokerDecision


class StubBroker:
    def __init__(self) -> None:
        self.called_with: list[str] = []

    def verify_credential(self, service: str) -> BrokerDecision:
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
    result = runner.invoke(app, ["verify", "--service", "minimax"])

    assert result.exit_code == 0
    assert broker.called_with == ["minimax"]
