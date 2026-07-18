from __future__ import annotations

import json
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.broker import Broker
from hermes_vault.config import AppSettings
from hermes_vault.dashboard import (
    DashboardAPI,
    DashboardContext,
    create_dashboard_server,
    dashboard_static_dir,
)
from hermes_vault.policy import PolicyEngine
from hermes_vault.vault import Vault
from hermes_vault.verifier import Verifier


FAKE_SECRET = "fake-dashboard-validation-secret"
TOKEN = "fake-dashboard-validation-token"


def _request(url: str, *, token: str | None = None) -> tuple[int, bytes]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _context(home: Path) -> DashboardContext:
    policy_path = home / "policy.yaml"
    policy_path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata]
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
""".lstrip(),
        encoding="utf-8",
    )
    settings = AppSettings(runtime_home=home, base_home=home, policy_path=policy_path)
    settings.ensure_runtime_layout()
    policy = PolicyEngine.from_yaml(policy_path)
    vault = Vault(settings.db_path, settings.salt_path, "fake-dashboard-passphrase")
    vault.add_credential("openai", FAKE_SECRET, "api_key", alias="default")
    audit = AuditLogger(settings.db_path)
    broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)
    return DashboardContext(
        settings=settings,
        vault=vault,
        policy=policy,
        broker=broker,
        audit=audit,
    )


def main() -> None:
    static_root = dashboard_static_dir()
    expected_assets = [
        static_root / "index.html",
        static_root / "app.js",
        static_root / "styles.css",
        static_root / "assets" / "hermes-vault-console-brand.png",
    ]
    for asset in expected_assets:
        assert asset.is_file(), f"packaged dashboard asset missing: {asset}"

    try:
        create_dashboard_server(host="0.0.0.0")
    except ValueError:
        pass
    else:
        raise AssertionError("dashboard accepted a non-local bind address")

    with tempfile.TemporaryDirectory(prefix="hermes-vault-dashboard-") as raw_home:
        home = Path(raw_home)
        ctx = _context(home)
        api = DashboardAPI(context_factory=lambda: ctx)
        server = create_dashboard_server(token=TOKEN, api=api)
        try:
            assert server.server_address[0] == "127.0.0.1"
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            base = f"http://127.0.0.1:{port}"
            no_token_status, _ = _request(f"{base}/api/credentials")
            wrong_token_status, _ = _request(
                f"{base}/api/credentials",
                token="wrong-validation-token",
            )
            ok_status, payload_bytes = _request(
                f"{base}/api/credentials",
                token=TOKEN,
            )
            assert no_token_status == 401
            assert wrong_token_status == 401
            assert ok_status == 200

            payload_text = payload_bytes.decode("utf-8")
            payload = json.loads(payload_text)
            assert payload["credentials"][0]["service"] == "openai"
            assert "encrypted_payload" not in payload_text
            assert FAKE_SECRET not in payload_text

            for relative_path in (
                "index.html",
                "app.js",
                "styles.css",
                "assets/hermes-vault-console-brand.png",
            ):
                status, body = _request(f"{base}/{relative_path}")
                assert status == 200
                assert body

            summary = {
                "version": "packaged-dashboard-validation-v1",
                "static_asset_count": len(expected_assets),
                "bound_to_localhost": True,
                "missing_token_rejected": no_token_status == 401,
                "invalid_token_rejected": wrong_token_status == 401,
                "authorized_api_sanitized": FAKE_SECRET not in payload_text,
            }
            print(json.dumps(summary, indent=2, sort_keys=True))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
