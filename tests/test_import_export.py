"""Tests for import_export module."""
from __future__ import annotations

import csv
import io
import json
import tempfile
from pathlib import Path

from hermes_vault.import_export import (
    parse_csv,
    parse_env,
    parse_json_backup,
    export_credentials,
    add_tags,
    remove_tags,
    set_tags,
    _guess_service_from_env_var,
    _service_to_env_var,
)
from hermes_vault.models import CredentialRecord, CredentialStatus, CredentialSecret, utc_now


class TestCsvImport:
    def test_parse_csv_simple(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "test.csv"
        csv_path.write_text("service,secret,alias\ntest-svc,my-secret,myalias\n", encoding="utf-8")
        rows = parse_csv(csv_path)
        assert len(rows) == 1
        assert rows[0]["service"] == "test-svc"
        assert rows[0]["secret"] == "my-secret"
        assert rows[0]["alias"] == "myalias"

    def test_parse_csv_custom_columns(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "custom.csv"
        csv_path.write_text("provider,key\nopenai,sk-123\n", encoding="utf-8")
        rows = parse_csv(csv_path, service_column="provider", secret_column="key")
        assert len(rows) == 1
        assert rows[0]["service"] == "openai"
        assert rows[0]["secret"] == "sk-123"

    def test_parse_csv_skips_empty(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "empty.csv"
        csv_path.write_text("service,secret\nopenai,sk-123\n,,skip\n", encoding="utf-8")
        rows = parse_csv(csv_path)
        assert len(rows) == 1

    def test_parse_csv_no_header_uses_first_row(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "noheader.csv"
        csv_path.write_text("openai,sk-123\n", encoding="utf-8")
        # DictReader uses first row as fieldnames — 'openai' becomes a column
        rows = parse_csv(csv_path)
        # The first row becomes the header, so data starts with row 2
        # With one row + header interpretation: no data rows => empty
        assert len(rows) == 0

    def test_parse_csv_with_tags(self, tmp_path: Path) -> None:
        csv_path = tmp_path / "tags.csv"
        csv_path.write_text("service,secret,tags\nopenai,sk-123,production\n", encoding="utf-8")
        rows = parse_csv(csv_path, tag_column="tags")
        assert rows[0].get("tags_csv") == "production"


class TestEnvImport:
    def test_parse_env(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("OPENAI_API_KEY=sk-test\nANTHROPIC_API_KEY=sk-ant-test\n# comment\nUNKNOWN=mystery\n", encoding="utf-8")
        rows = parse_env(env_path)
        assert len(rows) == 2
        assert any(r["service"] == "openai" for r in rows)
        assert any(r["service"] == "anthropic" for r in rows)

    def test_parse_env_skips_empty_values(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        env_path.write_text("OPENAI_API_KEY=\nGITHUB_TOKEN=${GITHUB_TOKEN}\n", encoding="utf-8")
        rows = parse_env(env_path)
        assert len(rows) == 0

    def test_guess_service_map(self) -> None:
        assert _guess_service_from_env_var("OPENAI_API_KEY") == "openai"
        assert _guess_service_from_env_var("FAL_KEY") == "fal"
        assert _guess_service_from_env_var("UNKNOWN_VAR") is None


class TestJsonImport:
    def test_parse_json_list(self, tmp_path: Path) -> None:
        json_path = tmp_path / "backup.json"
        json_path.write_text(json.dumps([{"service": "openai", "secret": "sk-123"}]), encoding="utf-8")
        rows = parse_json_backup(json_path)
        assert len(rows) == 1
        assert rows[0]["service"] == "openai"

    def test_parse_json_backup_format(self, tmp_path: Path) -> None:
        json_path = tmp_path / "backup.json"
        json_path.write_text(json.dumps({"credentials": [{"service": "github", "secret": "ghp_xxx"}]}), encoding="utf-8")
        rows = parse_json_backup(json_path)
        assert len(rows) == 1
        assert rows[0]["service"] == "github"

    def test_parse_json_invalid(self, tmp_path: Path) -> None:
        json_path = tmp_path / "bad.json"
        json_path.write_text('{"not_credentials": 5}', encoding="utf-8")
        try:
            parse_json_backup(json_path)
            assert False, "should raise"
        except ValueError:
            pass


class TestExport:
    def test_export_json(self) -> None:
        rec = _make_record()
        out = export_credentials([rec], fmt="json")
        parsed = json.loads(out)
        assert len(parsed) == 1
        assert parsed[0]["service"] == "test-svc"

    def test_export_csv(self) -> None:
        rec = _make_record()
        out = export_credentials([rec], fmt="csv")
        assert "test-svc" in out
        assert "service,alias" in out  # header

    def test_export_env(self) -> None:
        rec = _make_record(service="openai")
        out = export_credentials([rec], fmt="env")
        assert "OPENAI_API_KEY" in out
        assert "REDACTED_USE_EXPORT_WITH_SECRETS" in out

    def test_export_invalid_format(self) -> None:
        rec = _make_record()
        try:
            export_credentials([rec], fmt="xml")
            assert False
        except ValueError:
            pass

    def test_service_to_env_var(self) -> None:
        assert _service_to_env_var("openai") == "OPENAI_API_KEY"
        assert _service_to_env_var("github") in ("GITHUB_TOKEN", "GH_TOKEN")
        assert _service_to_env_var("unknown-service") == "UNKNOWN_SERVICE_KEY"  # fallback


def _make_record(service: str = "test-svc", alias: str = "default", tags: list[str] | None = None) -> CredentialRecord:
    return CredentialRecord(
        id="test-id-123",
        service=service,
        alias=alias,
        credential_type="api_key",
        encrypted_payload="fake-encrypted",
        status=CredentialStatus.active,
        tags=tags if tags is not None else [],
        created_at=utc_now(),
        updated_at=utc_now(),
    )
