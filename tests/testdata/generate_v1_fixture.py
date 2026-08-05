"""Regenerate the aesgcm-v1 backup fixture under tests/testdata.

The fixture is a real, decryptable hvbackup-v1 backup produced by the
vault's own export path with writes pinned to aesgcm-v1 (AAD=None). It
represents an "existing v1 backup" that must stay restorable after the
v2 codec is active.

Run from the repo root:

    env -u PYTHONPATH .venv/bin/python tests/testdata/generate_v1_fixture.py

The generator writes two files that MUST stay in sync:

- backup_aesgcm_v1.json  — the hvbackup-v1 backup document
- backup_aesgcm_v1.salt  — the 16-byte salt the test restores against

The salt is random per run; only the pair (json + salt) matters. The
passphrase is FIXED and documented in README.md; tests that consume the
fixture must use the same constant.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parent.parent
TESTDATA = Path(__file__).resolve().parent
FIXTURE_JSON = TESTDATA / "backup_aesgcm_v1.json"
FIXTURE_SALT = TESTDATA / "backup_aesgcm_v1.salt"
PASSPHRASE = "test-passphrase"

# Secrets stored inside the fixture. Tests assert these exact values come
# back out of a restore, so keep them in sync with
# tests/test_backup_roundtrip_v1_v2.py.
SECRET_OPENAI = "sk-roundtrip-fixture-αβγ-12345"
SECRET_GITHUB = "ghp_roundtrip_fixture_token"


def main() -> None:
    # Pin writes to v1 regardless of any ambient env flag.
    os.environ.pop("HERMES_VAULT_CRYPTO_VERSION", None)

    from hermes_vault.vault import Vault

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        db_path = tmp_path / "vault.db"
        salt_path = tmp_path / "salt.bin"
        vault = Vault(db_path, salt_path, PASSPHRASE)

        rec_a = vault.add_credential(
            "openai",
            SECRET_OPENAI,
            "api_key",
            alias="primary",
            scopes=["models.read", "models.write"],
            tags=["production"],
            notes="fixture main key",
        )
        rec_b = vault.add_credential(
            "github",
            SECRET_GITHUB,
            "personal_access_token",
            alias="default",
            scopes=[],
            tags=[],
            notes=None,
        )
        vault.issue_lease(
            rec_a.id,
            agent_id="fixture-agent",
            ttl_seconds=900,
            metadata={"ticket": "fixture-42"},
        )

        backup = vault.export_backup()

        # Simulate a true pre-#60 v1 backup: drop the crypto_version key from
        # the second credential. import_backup defaults missing labels to
        # aesgcm-v1, and the fixture must prove that legacy shape restores.
        for cred in backup["credentials"]:
            if cred["id"] == rec_b.id:
                cred.pop("crypto_version", None)

        FIXTURE_JSON.write_text(json.dumps(backup, indent=2, sort_keys=True), encoding="utf-8")
        shutil.copyfile(salt_path, FIXTURE_SALT)

        print(f"wrote {FIXTURE_JSON}")
        print(f"wrote {FIXTURE_SALT}")
        print(
            f"credentials: {len(backup['credentials'])}, leases: {len(backup['leases'])}, version: {backup['version']}"
        )


if __name__ == "__main__":
    main()
