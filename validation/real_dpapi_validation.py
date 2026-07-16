from __future__ import annotations

import gc
import json
import os
import tempfile
from pathlib import Path

from hermes_vault import dpapi
from hermes_vault.vault import Vault


FAKE_SECRET = "fake-dpapi-validation-secret"


def main() -> None:
    if os.name != "nt":
        raise RuntimeError("real DPAPI validation must run on Windows")
    if not dpapi.is_available():
        raise RuntimeError("DPAPI is unavailable after installing the Windows extra")

    previous = os.environ.get("HERMES_VAULT_DPAPI")
    os.environ["HERMES_VAULT_DPAPI"] = "1"
    try:
        # sqlite3 connection context managers commit or roll back but do not
        # guarantee immediate OS-handle release. Explicit collection below
        # prevents Windows runner cleanup from racing delayed finalizers.
        with tempfile.TemporaryDirectory(
            prefix="hermes-vault-dpapi-",
            ignore_cleanup_errors=True,
        ) as raw_home:
            home = Path(raw_home)
            db_path = home / "vault.db"
            salt_path = home / "master_key_salt.bin"

            vault = Vault(db_path, salt_path, "fake-passphrase")
            assert salt_path.read_bytes().startswith(dpapi.DPAPI_HEADER)
            vault.add_credential("openai", FAKE_SECRET, "api_key", alias="default")

            reopened = Vault(db_path, salt_path, "different-passphrase")
            resolved = reopened.get_secret("openai")
            assert resolved is not None
            assert resolved.secret == FAKE_SECRET
            assert FAKE_SECRET.encode("utf-8") not in db_path.read_bytes()

            reopened.rotate_master_key("different-passphrase", "rotated-passphrase")
            assert salt_path.read_bytes().startswith(dpapi.DPAPI_HEADER)
            rotated = Vault(db_path, salt_path, "rotated-passphrase")
            rotated_secret = rotated.get_secret("openai")
            assert rotated_secret is not None
            assert rotated_secret.secret == FAKE_SECRET

            summary = {
                "version": "real-dpapi-validation-v1",
                "platform": "windows",
                "pywin32_available": True,
                "dpapi_envelope_created": True,
                "credential_round_trip": True,
                "master_key_rotation_round_trip": True,
                "plaintext_absent_from_database": True,
            }
            rendered = json.dumps(summary, sort_keys=True)
            assert FAKE_SECRET not in rendered
            print(json.dumps(summary, indent=2, sort_keys=True))

            del rotated_secret, rotated, resolved, reopened, vault
            gc.collect()
    finally:
        if previous is None:
            os.environ.pop("HERMES_VAULT_DPAPI", None)
        else:
            os.environ["HERMES_VAULT_DPAPI"] = previous


if __name__ == "__main__":
    main()
