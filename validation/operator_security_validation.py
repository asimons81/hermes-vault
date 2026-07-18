from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hermes_vault.audit import AuditLogger
from hermes_vault.backup import restore_dry_run, verify_backup_file
from hermes_vault.broker import Broker
from hermes_vault.policy import PolicyEngine
from hermes_vault.recovery import run_recovery_drill
from hermes_vault.secret_source import fetch_secret_source_bindings
from hermes_vault.vault import Vault
from hermes_vault.verifier import Verifier


FAKE_SECRET = "fake-openai-post-merge-validation"


def _write_policy(path: Path) -> None:
    path.write_text(
        """
agents:
  hermes:
    services:
      openai:
        actions: [get_env, verify, metadata, issue_lease, list_leases, show_lease]
        require_lease_for_env: true
    capabilities: [list_credentials]
    raw_secret_access: false
    ephemeral_env_only: true
    max_ttl_seconds: 900
""".lstrip(),
        encoding="utf-8",
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hermes-vault-validation-") as raw_home:
        home = Path(raw_home)
        policy_path = home / "policy.yaml"
        db_path = home / "vault.db"
        salt_path = home / "master_key_salt.bin"
        backup_path = home / "vault-backup.json"
        _write_policy(policy_path)

        policy = PolicyEngine.from_yaml(policy_path)
        vault = Vault(db_path, salt_path, "fake-local-passphrase")
        vault.add_credential(
            "openai",
            FAKE_SECRET,
            "api_key",
            alias="default",
            tags=["validation"],
            notes="Disposable post-merge validation credential",
        )
        audit = AuditLogger(db_path)
        broker = Broker(vault=vault, policy=policy, verifier=Verifier(), audit=audit)

        denied_before_lease = broker.get_ephemeral_env(
            service="openai",
            agent_id="hermes",
            ttl=300,
        )
        assert denied_before_lease.allowed is False
        assert denied_before_lease.metadata.get("lease_required") is True

        checkout = broker.lease_checkout(
            agent_id="hermes",
            service="openai",
            ttl_seconds=300,
            purpose="post-merge security validation",
        )
        assert checkout.allowed is True
        assert checkout.env == {"OPENAI_API_KEY": FAKE_SECRET}
        assert checkout.metadata["lease_checkout"]["lease_id"]

        secret_source = fetch_secret_source_bindings(
            vault=vault,
            policy=policy,
            agent_id="hermes",
            ttl=300,
            bindings=["OPENAI_API_KEY=hv://openai"],
        )
        assert secret_source.ok is True
        assert secret_source.secrets == {"OPENAI_API_KEY": FAKE_SECRET}

        malformed = fetch_secret_source_bindings(
            vault=vault,
            policy=policy,
            agent_id="hermes",
            ttl=300,
            bindings=["OPENAI_API_KEY=not-a-vault-ref"],
        )
        assert malformed.ok is False
        assert malformed.errors["OPENAI_API_KEY=not-a-vault-ref"].kind == "REF_INVALID"

        denied_agent = fetch_secret_source_bindings(
            vault=vault,
            policy=policy,
            agent_id="unknown-agent",
            ttl=300,
            bindings=["OPENAI_API_KEY=hv://openai"],
        )
        assert denied_agent.ok is False
        assert denied_agent.errors["OPENAI_API_KEY"].kind == "AUTH_FAILED"

        backup = vault.export_backup()
        backup_path.write_text(json.dumps(backup, indent=2), encoding="utf-8")

        verify = verify_backup_file(backup_path, vault)
        assert verify.decryptable is True
        assert not verify.findings

        dry_run = restore_dry_run(backup_path, vault)
        assert dry_run.decryptable is True
        assert not dry_run.findings

        recovery = run_recovery_drill(
            backup_path=backup_path,
            vault=vault,
            policy=policy,
        )
        assert recovery.healthy is True
        assert recovery.backup_verify["decryptable"] is True
        assert recovery.restore_dry_run["decryptable"] is True

        summary = {
            "version": "post-merge-security-validation-v1",
            "vault_home_disposable": True,
            "credential_count": len(vault.list_credentials()),
            "lease_checkout_allowed": checkout.allowed,
            "secret_source_mapping_count": len(secret_source.secrets),
            "malformed_ref_failed_closed": malformed.ok is False,
            "unknown_agent_failed_closed": denied_agent.ok is False,
            "backup_decryptable": verify.decryptable,
            "restore_dry_run_decryptable": dry_run.decryptable,
            "recovery_healthy": recovery.healthy,
        }
        rendered = json.dumps(summary, sort_keys=True)
        assert FAKE_SECRET not in rendered
        print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
