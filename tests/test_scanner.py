from __future__ import annotations

from pathlib import Path

from hermes_vault.config import AppSettings
from hermes_vault.scanner import Scanner


def test_scanner_detects_plaintext_and_duplicates(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "hermes"
    secrets_dir.mkdir()
    one = secrets_dir / ".env"
    two = secrets_dir / "config.yaml"
    one.write_text("OPENAI_API_KEY=sk-testsecretvalue1234567890\n", encoding="utf-8")
    two.write_text("token: sk-testsecretvalue1234567890\n", encoding="utf-8")

    settings = AppSettings(runtime_home=tmp_path / "runtime", default_scan_roots=[secrets_dir])
    scanner = Scanner(settings)
    findings = scanner.scan()

    kinds = {finding.kind for finding in findings}
    assert "plaintext_secret" in kinds
    assert "duplicate_secret" in kinds


def test_scanner_respects_ignore_patterns(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "hermes"
    secrets_dir.mkdir()
    target = secrets_dir / ".env"
    target.write_text("OPENAI_API_KEY=sk-testsecretvalue1234567890\n", encoding="utf-8")

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "scan.ignore").write_text(str(target), encoding="utf-8")

    settings = AppSettings(runtime_home=runtime, default_scan_roots=[secrets_dir])
    scanner = Scanner(settings)
    findings = scanner.scan()

    assert findings == []


def test_scanner_ignores_comment_only_example_lines(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "hermes"
    secrets_dir.mkdir()
    target = secrets_dir / ".env"
    target.write_text(
        "# OPENAI_API_KEY=sk-testsecretvalue1234567890\n"
        "OPENAI_API_KEY=sk-testsecretvalue1234567890\n",
        encoding="utf-8",
    )

    settings = AppSettings(runtime_home=tmp_path / "runtime", default_scan_roots=[secrets_dir])
    scanner = Scanner(settings)
    findings = scanner.scan()

    assert len([finding for finding in findings if finding.kind == "plaintext_secret"]) == 1
    plaintext = next(finding for finding in findings if finding.kind == "plaintext_secret")
    assert plaintext.line_number == 2


def test_scanner_does_not_flag_placeholder_like_values_without_detector_match(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "hermes"
    secrets_dir.mkdir()
    target = secrets_dir / ".env"
    target.write_text("OPENAI_API_KEY=sk-test-placeholder\n", encoding="utf-8")

    settings = AppSettings(runtime_home=tmp_path / "runtime", default_scan_roots=[secrets_dir])
    scanner = Scanner(settings)
    findings = scanner.scan()

    assert not any(finding.kind == "plaintext_secret" for finding in findings)
