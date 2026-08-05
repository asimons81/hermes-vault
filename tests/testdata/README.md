# tests/testdata fixtures

| File | Purpose |
|------|---------|
| `backup_aesgcm_v1.json` | Real hvbackup-v1 backup produced by `Vault.export_backup()` with writes pinned to aesgcm-v1. Contains a legacy credential without `crypto_version`, an explicit `aesgcm-v1` credential with scopes/tags/notes, and one lease. |
| `backup_aesgcm_v1.salt` | The 16-byte salt the backup's ciphertexts were encrypted under. Tests copy it to a temp vault so the derived key matches (a real restore uses the operator's own salt file). |
| `generate_v1_fixture.py` | Reproducible generator. Re-run with `env -u PYTHONPATH .venv/bin/python tests/testdata/generate_v1_fixture.py` from the repo root. |

Passphrase for the fixture: `test-passphrase` (constant `PASSPHRASE` in
`tests/test_backup_roundtrip_v1_v2.py` and in the generator).

Notes:
- The salt is random per generator run; only the json+salt pair must stay
  in sync (the generator writes both in one run).
- Tests resolve credential ids from the fixture JSON, so regenerating the
  fixture with fresh UUIDs does not break them.
- The fixture contains no real credentials; secrets are fixed test values.
