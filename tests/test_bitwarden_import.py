"""Tests for the Bitwarden import bridge (P9).

Unit tests parse a fixture export shape-compatible with
``bw export --format json``; CLI tests drive the real command group through
CliRunner against isolated vault homes. Fixture secrets are fake test values
(the same shapes tests/test_detectors.py already uses).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from click.testing import CliRunner

from hermes_vault.bitwarden import (
    BitwardenExportError,
    BitwardenPlan,
    _custom_fields,
    _host_service,
    _slug,
    load_bitwarden_export,
    plan_bitwarden_import,
    resolve_collisions,
)
from hermes_vault.cli import _hermes_group


def _bw_export() -> dict:
    """A representative unencrypted bw export covering every item type."""
    return {
        "encrypted": False,
        "folders": [
            {"id": "f1", "name": "Work"},
            {"id": "f2", "name": "Personal"},
        ],
        "items": [
            {
                "id": "i1",
                "folderId": "f1",
                "type": 1,
                "name": "GitHub",
                "notes": "Work GitHub account",
                "login": {
                    "username": "tony@example.com",
                    "password": "ghp_fakefakefakefakefakefake",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://github.com"}],
                },
                "fields": [
                    {"name": "recovery-code", "type": 1, "value": "AAAA-BBBB"},
                    {"name": "is-primary", "type": 2, "value": True},
                    {"name": "linked-thing", "type": 3, "value": None},
                ],
            },
            {
                "id": "i2",
                "folderId": None,
                "type": 1,
                "name": "OpenAI API",
                "notes": None,
                "login": {
                    "username": None,
                    "password": "sk-fakefakefakefakefake12",
                    "totp": None,
                    "uris": [{"uri": "https://api.openai.com"}],
                },
                "fields": [],
            },
            {
                "id": "i3",
                "folderId": "f2",
                "type": 1,
                "name": "No-password login",
                "login": {"username": "someone", "password": "", "totp": None, "uris": []},
                "fields": [],
            },
            {
                "id": "i4",
                "folderId": "f2",
                "type": 2,
                "name": "Server recovery notes",
                "notes": "break-glass procedure: contact on-call",
                "login": None,
                "fields": [],
            },
            {"id": "i5", "folderId": None, "type": 3, "name": "Personal card", "login": None, "fields": []},
            {"id": "i6", "folderId": None, "type": 4, "name": "Identity", "login": None, "fields": []},
        ],
    }


def _write_export(tmp_path: Path, data: dict | None = None) -> Path:
    path = tmp_path / "bw-export.json"
    path.write_text(json.dumps(data or _bw_export()), encoding="utf-8")
    return path


# ── Unit: loading + validation ─────────────────────────────────────────


class TestLoadExport:
    def test_load_valid_export(self, tmp_path: Path) -> None:
        path = _write_export(tmp_path)
        data = load_bitwarden_export(path)
        assert "items" in data and len(data["items"]) == 6

    def test_rejects_non_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(BitwardenExportError, match="bw export"):
            load_bitwarden_export(path)

    def test_rejects_wrong_shape(self, tmp_path: Path) -> None:
        path = tmp_path / "wrong.json"
        path.write_text(json.dumps({"credentials": []}), encoding="utf-8")
        with pytest.raises(BitwardenExportError, match="items"):
            load_bitwarden_export(path)

    def test_rejects_encrypted_export(self, tmp_path: Path) -> None:
        # Encrypted exports have string ciphertexts, not item objects.
        path = tmp_path / "enc.json"
        path.write_text(json.dumps({"encrypted": True, "items": ["2.bm90X2FuX2l0ZW0=="]}), encoding="utf-8")
        with pytest.raises(BitwardenExportError, match="ENCRYPTED"):
            load_bitwarden_export(path)


# ── Unit: planning ─────────────────────────────────────────────────────


class TestPlanning:
    def test_full_fixture_plan(self) -> None:
        plan = plan_bitwarden_import(_bw_export())
        # 3 importable: github login, openai login, secure note
        assert plan.importable_count == 3
        # 3 skipped: no-password login, card, identity
        assert len(plan.skipped) == 3
        assert plan.folders == 2
        assert plan.items_seen == 6

        pairs = {(c.service, c.alias) for c in plan.planned}
        # folder prefix + canonical service from the item name
        assert ("work-github", "tony-example-com") in pairs
        # no-folder item: name slug matched a canonical service
        assert ("openai", "default") in pairs
        # secure note → service slug from item name
        assert ("personal-server-recovery-notes", "default") in pairs

    def test_totp_rides_the_secret(self) -> None:
        plan = plan_bitwarden_import(_bw_export())
        github = next(c for c in plan.planned if c.service == "work-github")
        assert "totp:" in github.secret
        assert "JBSWY3DPEHPK3PXP" in github.secret
        assert github.secret.startswith("ghp_fake")

    def test_otpauth_uri_passed_through(self) -> None:
        data = _bw_export()
        data["items"][0]["login"]["totp"] = "otpauth://totp/Test?secret=ABC123"
        plan = plan_bitwarden_import(data)
        github = next(c for c in plan.planned if c.service == "work-github")
        assert "otpauth://totp/Test?secret=ABC123" in github.secret

    def test_custom_fields_become_metadata(self) -> None:
        plan = plan_bitwarden_import(_bw_export())
        github = next(c for c in plan.planned if c.service == "work-github")
        assert github.metadata == {"recovery-code": "AAAA-BBBB", "is-primary": True}

    def test_notes_land_in_plaintext_notes(self) -> None:
        plan = plan_bitwarden_import(_bw_export())
        github = next(c for c in plan.planned if c.service == "work-github")
        assert github.notes == "Work GitHub account"

    def test_credential_type_from_detector(self) -> None:
        plan = plan_bitwarden_import(_bw_export())
        openai = next(c for c in plan.planned if c.service == "openai")
        assert openai.credential_type == "api_key"

    def test_duplicate_usernames_get_unique_aliases(self) -> None:
        data = _bw_export()
        data["items"].append({
            "id": "i7",
            "folderId": "f1",
            "type": 1,
            "name": "GitHub",
            "login": {"username": "tony@example.com", "password": "ghp_fakefakefakefake2", "totp": None, "uris": []},
            "fields": [],
        })
        plan = plan_bitwarden_import(data)
        aliases = [c.alias for c in plan.planned if c.service == "work-github"]
        assert sorted(aliases) == ["tony-example-com", "tony-example-com-2"]

    def test_uri_host_used_when_name_unknown(self) -> None:
        data = {
            "items": [
                {
                    "id": "x1",
                    "folderId": None,
                    "type": 1,
                    "name": "My internal thing",
                    "login": {
                        "username": "svc",
                        "password": "plain-password-value",
                        "totp": None,
                        "uris": [{"uri": "https://api.internalcorp.io/v1"}],
                    },
                    "fields": [],
                }
            ]
        }
        plan = plan_bitwarden_import(data)
        assert plan.importable_count == 1
        # Unknown name falls to the URI host as a custom service id
        assert plan.planned[0].service == "internalcorp"

    def test_slug_and_host_helpers(self) -> None:
        assert _slug("Work / GitHub!") == "work-github"
        assert _host_service("https://api.github.com/v3") == "github"
        assert _host_service("https://github.com") == "github"

    def test_field_extraction_rules(self) -> None:
        item = {
            "fields": [
                {"name": "text", "type": 0, "value": "visible"},
                {"name": "hidden", "type": 1, "value": "s3cret-value"},
                {"name": "bool", "type": 2, "value": False},
                {"name": "linked", "type": 3, "value": None},
                {"name": "", "type": 0, "value": "no name"},
            ]
        }
        fields = _custom_fields(item)
        assert fields == {"text": "visible", "hidden": "s3cret-value", "bool": False}

    def test_empty_items_list_is_valid(self) -> None:
        plan = plan_bitwarden_import({"items": []})
        assert plan.importable_count == 0
        assert plan.skipped == []


# ── Unit: collision resolution ─────────────────────────────────────────


class TestCollisions:
    def _plan_with(self, service: str, alias: str) -> BitwardenPlan:
        from hermes_vault.bitwarden import PlannedCredential

        plan = plan_bitwarden_import({"items": []})
        plan.planned.append(PlannedCredential(service=service, alias=alias, secret="x"))
        return plan

    def test_skip_policy_keeps_vault_row(self) -> None:
        plan = self._plan_with("openai", "default")
        result = resolve_collisions(plan, {("openai", "default")}, "skip")
        assert result.to_write == []
        assert [(x.service, x.alias, x.action) for x in result.collisions] == [("openai", "default", "skip")]

    def test_rename_policy_suffixes_alias(self) -> None:
        plan = self._plan_with("openai", "default")
        result = resolve_collisions(plan, {("openai", "default")}, "rename")
        assert [(c.service, c.alias) for c in result.to_write] == [("openai", "default-bw2")]
        assert result.to_write[0].alias == "default-bw2"

    def test_rename_avoids_taken_suffixes(self) -> None:
        plan = self._plan_with("openai", "default")
        taken = {("openai", "default"), ("openai", "default-bw2"), ("openai", "default-bw3")}
        result = resolve_collisions(plan, taken, "rename")
        assert result.to_write[0].alias == "default-bw4"

    def test_fail_policy_lists_collision(self) -> None:
        plan = self._plan_with("openai", "default")
        result = resolve_collisions(plan, {("openai", "default")}, "fail")
        assert result.to_write == []
        assert result.collisions[0].action == "fail"

    def test_intra_import_duplicates_are_unique_before_policy(self) -> None:
        # Two planned credentials resolving to the same pair: the second
        # must not silently overwrite the first during apply.
        plan = self._plan_with("openai", "default")
        from hermes_vault.bitwarden import PlannedCredential

        plan.planned.append(PlannedCredential(service="openai", alias="default", secret="y"))
        result = resolve_collisions(plan, set(), "skip")
        assert len(result.to_write) == 1
        assert result.to_write[0].secret == "x"

    def test_unknown_policy_rejected(self) -> None:
        plan = self._plan_with("openai", "default")
        with pytest.raises(ValueError, match="collision policy"):
            resolve_collisions(plan, set(), "explode")


# ── CLI: import group ──────────────────────────────────────────────────


class TestImportBitwardenCli:
    def test_dry_run_needs_no_vault(self, tmp_path: Path) -> None:
        export = _write_export(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(export), "--dry-run"],
            env={"HERMES_VAULT_HOME": str(tmp_path / "no-vault-home")},
        )
        assert result.exit_code == 0
        # No vault was created
        assert not (tmp_path / "no-vault-home" / "vault.db").exists()
        # Preview shows services, never secrets
        assert "work-github" in result.output
        assert "ghp_fake" not in result.output
        assert "sk-fake" not in result.output
        assert "JBSWY3DPEHPK3PXP" not in result.output

    def test_dry_run_json_is_clean(self, tmp_path: Path) -> None:
        export = _write_export(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(export), "--dry-run", "--json"],
            env={"HERMES_VAULT_HOME": str(tmp_path / "h")},
        )
        assert result.exit_code == 0
        # CliRunner mixes stderr into output; the JSON payload starts at the
        # first '{' and the plaintext-export warning never collides with it.
        payload = json.loads(result.output[result.output.index("{"):])
        assert payload["importable"] == 3
        assert payload["skipped_items"] == 3
        assert payload["folders"] == 2
        assert {p["service"] for p in payload["planned"]} == {
            "work-github", "openai", "personal-server-recovery-notes",
        }

    def test_apply_end_to_end_with_audit(self, tmp_path: Path, monkeypatch) -> None:
        export = _write_export(tmp_path)
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(
            _hermes_group, ["import", "bitwarden", "--file", str(export), "--yes"]
        )
        assert result.exit_code == 0, result.output
        assert "Imported 3 credential(s) from Bitwarden" in result.output

        from hermes_vault.vault import Vault

        vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
        creds = vault.list_credentials()
        assert len(creds) == 3
        by_pair = {(r.service, r.alias): r for r in creds}
        assert ("work-github", "tony-example-com") in by_pair
        assert ("openai", "default") in by_pair
        assert ("personal-server-recovery-notes", "default") in by_pair

        github = by_pair[("work-github", "tony-example-com")]
        assert github.imported_from == "bitwarden"
        assert github.tags == ["imported", "bitwarden"]
        assert github.notes == "Work GitHub account"
        cs = vault.get_secret(github.id)
        assert cs is not None and cs.secret.startswith("ghp_fake")
        assert "totp:" in cs.secret
        assert cs.metadata == {"recovery-code": "AAAA-BBBB", "is-primary": True}

        with sqlite3.connect(home / "vault.db") as conn:
            events = conn.execute(
                "SELECT action, decision FROM access_logs WHERE action='import_bitwarden'"
            ).fetchall()
        assert events == [("import_bitwarden", "allow")]

    def test_collision_fail_aborts_before_writes(self, tmp_path: Path, monkeypatch) -> None:
        export = _write_export(tmp_path)
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        runner = CliRunner()
        first = runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export), "--yes"])
        assert first.exit_code == 0, first.output

        second = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(export), "--yes", "--on-collision", "fail"],
        )
        assert second.exit_code == 1
        assert "already exist" in second.output
        assert "Nothing was written" in second.output

        from hermes_vault.vault import Vault

        vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
        assert len(vault.list_credentials()) == 3  # unchanged

    def test_collision_skip_is_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        export = _write_export(tmp_path)
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        runner = CliRunner()
        runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export), "--yes"])
        again = runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export), "--yes"])
        assert again.exit_code == 0, again.output
        assert "Imported 0 credential(s)" in again.output
        assert "3 skipped on collision" in again.output.replace("\n", "")

        from hermes_vault.vault import Vault

        vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
        assert len(vault.list_credentials()) == 3

    def test_collision_rename_imports_under_suffixed_alias(self, tmp_path: Path, monkeypatch) -> None:
        export = _write_export(tmp_path)
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        runner = CliRunner()
        runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export), "--yes"])
        renamed = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(export), "--yes", "--on-collision", "rename"],
        )
        assert renamed.exit_code == 0, renamed.output
        assert "3 renamed on collision" in renamed.output

        from hermes_vault.vault import Vault

        vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
        aliases = sorted(r.alias for r in vault.list_credentials() if r.service == "openai")
        assert aliases == ["default", "default-bw2"]

    def test_missing_file_exits_two(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(tmp_path / "nope.json"), "--dry-run"],
        )
        assert result.exit_code == 2
        assert "Could not read" in result.output

    def test_invalid_json_exits_two(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(bad), "--dry-run"])
        assert result.exit_code == 2
        assert "bw export" in result.output

    def test_invalid_collision_policy_exits_two(self, tmp_path: Path) -> None:
        export = _write_export(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            _hermes_group,
            ["import", "bitwarden", "--file", str(export), "--on-collision", "explode", "--dry-run"],
        )
        assert result.exit_code == 2
        assert "skip, rename, or fail" in result.output

    def test_declined_confirmation_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        export = _write_export(tmp_path)
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export)], input="n\n")
        assert result.exit_code == 1
        assert "cancelled" in result.output

        from hermes_vault.vault import Vault

        vault = Vault(home / "vault.db", home / "master_key_salt.bin", "test-passphrase")
        assert len(vault.list_credentials()) == 0

    def test_secrets_never_printed(self, tmp_path: Path) -> None:
        export = _write_export(tmp_path)
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "bitwarden", "--file", str(export), "--dry-run"])
        assert result.exit_code == 0
        for secret in ("ghp_fakefakefakefakefakefake", "sk-fakefakefakefakefake12", "JBSWY3DPEHPK3PXP"):
            assert secret not in result.output


class TestLegacyImportCompat:
    """`import` became a group; the flat flags must keep working unchanged."""

    def test_legacy_from_env_still_works(self, tmp_path: Path, monkeypatch) -> None:
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_VAULT_HOME", str(home))
        monkeypatch.setenv("HERMES_VAULT_PASSPHRASE", "test-passphrase")
        env_path = tmp_path / ".env"
        env_path.write_text("OPENAI_API_KEY=sk-fakefakefakefakefake99\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path)])
        assert result.exit_code == 0, result.output
        assert "Imported 1 credential" in result.output

    def test_legacy_no_source_exits_one(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import"])
        assert result.exit_code == 1
        assert "--from-env" in result.output

    def test_legacy_dry_run_flag_still_works(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("OPENAI_API_KEY=sk-fakefakefakefakefake77\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "--from-env", str(env_path), "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "Would import" in result.output

    def test_help_lists_bitwarden_subcommand(self) -> None:
        runner = CliRunner()
        result = runner.invoke(_hermes_group, ["import", "--help"])
        assert result.exit_code == 0
        assert "bitwarden" in result.output
        assert "--from-env" in result.output
