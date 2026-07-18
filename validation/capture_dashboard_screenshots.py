from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import AppSettings
from hermes_vault.dashboard import DashboardAPI, DashboardContext, create_dashboard_server
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault
from hermes_vault.verifier import Verifier


TOKEN = "fake-screenshot-token"
FAKE_SECRETS = {
    "openai": "fake-openai-screenshot-secret",
    "github": "fake-github-screenshot-secret",
}


def _context(home: Path) -> DashboardContext:
    policy_path = home / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata, issue_lease, list_leases, show_lease]
      github:
        actions: [get_env, verify, metadata, issue_lease, list_leases, show_lease]
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )
    settings = AppSettings(runtime_home=home, base_home=home, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "fake-screenshot-passphrase")
    vault.add_credential(
        "openai",
        FAKE_SECRETS["openai"],
        "api_key",
        alias="default",
        tags=["ai", "validation"],
        notes="Fake credential for release documentation",
    )
    vault.add_credential(
        "github",
        FAKE_SECRETS["github"],
        "personal_access_token",
        alias="work",
        tags=["development", "validation"],
        notes="Fake credential for release documentation",
    )
    audit = AuditLogger(settings.db_path)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    broker.issue_lease(
        agent_id="hermes",
        service_or_id="openai",
        ttl_seconds=600,
        purpose="dashboard screenshot validation",
    )
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
    )


def main() -> None:
    output = Path("dashboard-screenshots")
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="hermes-vault-screenshots-") as raw_home:
        ctx = _context(Path(raw_home))
        api = DashboardAPI(context_factory=lambda: ctx)
        server = create_dashboard_server(token=TOKEN, api=api)
        try:
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=["--disable-dev-shm-usage"],
                )
                page = browser.new_page(viewport={"width": 1600, "height": 1000})
                page.goto(
                    f"http://127.0.0.1:{port}/?token={TOKEN}&no_intro=1",
                    wait_until="networkidle",
                )
                page.wait_for_function(
                    "document.querySelector('#connection')?.textContent === 'Local session'"
                )
                page.wait_for_function(
                    "document.querySelector('#metric-credentials')?.textContent === '2'"
                )
                body_text = page.locator("body").inner_text()
                for secret in FAKE_SECRETS.values():
                    assert secret not in body_text

                overview_path = output / "hermes-vault-v0.20-overview.png"
                page.screenshot(path=str(overview_path), full_page=True)

                page.locator("button[data-view='credentials']").click()
                page.wait_for_function(
                    "document.querySelector('#credentials')?.classList.contains('active')"
                )
                page.wait_for_selector("#credential-table table")
                credentials_text = page.locator("body").inner_text()
                for secret in FAKE_SECRETS.values():
                    assert secret not in credentials_text

                credentials_path = output / "hermes-vault-v0.20-credentials.png"
                page.screenshot(path=str(credentials_path), full_page=True)
                browser.close()

            summary = {
                "version": "dashboard-screenshot-evidence-v1",
                "fake_credentials_only": True,
                "screenshots": [
                    overview_path.name,
                    credentials_path.name,
                ],
                "raw_secret_values_absent_from_rendered_ui": True,
            }
            (output / "evidence.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
