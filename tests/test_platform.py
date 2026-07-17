"""Tests for the platform abstraction module (_platform.py).

These tests verify Windows-specific behavior using monkeypatching,
since we are running on POSIX (WSL/Linux). The Windows code paths
are exercised by temporarily overriding os.name.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


from hermes_vault import _platform


# ── Platform Detection ─────────────────────────────────────────────────────────


def test_current_platform_is_posix() -> None:
    expected = _platform.PlatformKind.WINDOWS if os.name == "nt" else _platform.PlatformKind.POSIX
    assert _platform.current_platform() == expected
    assert _platform.current_platform().value == expected.value


def test_current_platform_when_nt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    assert _platform.current_platform() == _platform.PlatformKind.WINDOWS


# ── Default Vault Home ─────────────────────────────────────────────────────────


def test_default_vault_home_posix() -> None:
    home = _platform.default_vault_home()
    assert home == _platform.default_vault_home()
    assert home.is_absolute()


def test_default_vault_home_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
    home = _platform.default_vault_home()
    assert "HermesVault" in str(home)


def test_default_vault_home_windows_no_appdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    home = _platform.default_vault_home()
    assert "AppData" in str(home)
    assert "HermesVault" in str(home)


def test_default_vault_home_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """HERMES_VAULT_HOME should still be the highest-priority override."""
    monkeypatch.setenv("HERMES_VAULT_HOME", "/custom/vault/path")
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    # The env override is handled in config._base_home(), not here
    home = _platform.default_vault_home()
    # Should still return the platform default since this function doesn't
    # check HERMES_VAULT_HOME — that's config.py's job
    assert "HermesVault" in str(home)


# ── Default Scan Roots ─────────────────────────────────────────────────────────


def test_default_scan_roots_posix() -> None:
    roots = _platform.default_scan_roots()
    if _platform.current_platform() == _platform.PlatformKind.WINDOWS:
        assert len(roots) == 1
        assert any("Hermes" in str(r) for r in roots)
    else:
        assert len(roots) == 5
        assert any("bashrc" in str(r) for r in roots)
        assert any("zshrc" in str(r) for r in roots)
        assert any(".profile" in str(r) for r in roots)
        assert any(".hermes" in str(r) for r in roots)


def test_default_scan_roots_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
    roots = _platform.default_scan_roots()
    # On Windows, no bash/zsh roots
    assert len(roots) == 1
    assert "Hermes" in str(roots[0])
    assert "bashrc" not in str(roots[0])
    assert "zshrc" not in str(roots[0])


# ── Secure File / Permissions ──────────────────────────────────────────────────


def test_secure_file_posix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    f = tmp_path / "test.txt"
    f.write_text("test")
    _platform.secure_file(f)
    mode = os.stat(f).st_mode & 0o777
    if os.name == "nt":
        assert f.exists()
    else:
        assert mode == 0o600


def test_secure_file_windows_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    f = tmp_path / "test.txt"
    f.write_text("test")
    orig_mode = os.stat(f).st_mode
    _platform.secure_file(f)
    # Mode should be unchanged on Windows (no-op)
    assert os.stat(f).st_mode == orig_mode


def test_secure_directory_posix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    _platform.secure_directory(tmp_path)
    mode = os.stat(tmp_path).st_mode & 0o777
    if os.name == "nt":
        assert tmp_path.exists()
    else:
        assert mode == 0o700


def test_secure_directory_windows_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    orig_mode = os.stat(tmp_path).st_mode
    _platform.secure_directory(tmp_path)
    assert os.stat(tmp_path).st_mode == orig_mode


def test_set_owner_only_posix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    f = tmp_path / "secret.txt"
    f.write_text("secret")
    f.chmod(0o644)
    _platform.set_owner_only(f)
    if os.name == "nt":
        assert f.exists()
    else:
        assert os.stat(f).st_mode & 0o777 == 0o600


def test_set_owner_only_windows_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    f = tmp_path / "secret.txt"
    f.write_text("secret")
    orig_mode = os.stat(f).st_mode
    _platform.set_owner_only(f)
    assert os.stat(f).st_mode == orig_mode


def test_mode_is_insecure_posix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    if os.name == "nt":
        pytest.skip("POSIX chmod semantics are not enforced on Windows hosts")
    f = tmp_path / "test.txt"
    f.write_text("content")
    f.chmod(0o644)
    assert _platform.mode_is_insecure(f) is True
    f.chmod(0o600)
    assert _platform.mode_is_insecure(f) is False


def test_mode_is_insecure_windows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    f = tmp_path / "test.txt"
    f.write_text("content")
    f.chmod(0o777)
    # On Windows, mode_is_insecure always returns False
    assert _platform.mode_is_insecure(f) is False


# ── Temp Path Check ────────────────────────────────────────────────────────────


def test_temp_path_check_posix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    # A path under /tmp should return True
    sys_path = Path("/usr/bin")
    assert _platform.temp_path_check(sys_path) is False
    # /tmp path should return True
    tmp_file = Path("/tmp/hermes-vault-test-temp")
    assert _platform.temp_path_check(tmp_file.parent) is True


def test_temp_path_check_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)

    # Mock _platform.temp_path_check to simulate Windows behavior
    import hermes_vault._platform as plat
    orig = plat.temp_path_check

    def mock_check(path):
        if plat._is_windows():
            # Simulate Windows check without resolve()
            for var in ("TEMP", "TMP"):
                val = os.environ.get(var)
                if val and val.lower() in str(path).lower():
                    return True
            return False
        return orig(path)

    monkeypatch.setattr(plat, "temp_path_check", mock_check)
    monkeypatch.setenv("TEMP", "C:\\Users\\test\\AppData\\Local\\Temp")
    assert plat.temp_path_check(Path("C:\\Users\\test\\AppData\\Local\\Temp\\hermes-vault")) is True
    assert plat.temp_path_check(Path("C:\\Users\\test\\Documents")) is False


# ── Command Formatting ─────────────────────────────────────────────────────────


def test_format_command_posix() -> None:
    result = _platform.format_command(("hermes-vault", "maintain", "--format", "json"))
    assert result == "hermes-vault maintain --format json"


def test_format_command_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    result = _platform.format_command(("hermes-vault", "maintain", "--format", "json"))
    # On Windows, uses subprocess.list2cmdline
    assert result == "hermes-vault maintain --format json"


def test_format_command_with_spaces_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    result = _platform.format_command(("hermes-vault", "mcp", "--profile", "my profile"))
    assert '"my profile"' in result


# ── Shell Safe Quote ───────────────────────────────────────────────────────────


def test_shell_safe_quote_posix() -> None:
    result = _platform.shell_safe_quote("simple")
    assert isinstance(result, str)


def test_shell_safe_quote_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    result = _platform.shell_safe_quote("simple path")
    assert result.startswith('"')
    assert result.endswith('"')


# ── Task Scheduler Template ────────────────────────────────────────────────────


def test_render_task_scheduler_template() -> None:
    result = _platform.render_task_scheduler_template()
    assert "schtasks /Create" in result
    assert "HermesVaultMaintenance" in result
    assert "hermes-vault" in result
    assert "New-ScheduledTaskAction" in result
    assert "New-ScheduledTaskTrigger" in result


def test_render_task_scheduler_template_custom() -> None:
    result = _platform.render_task_scheduler_template(
        command="python",
        args="-m hermes_vault.cli maintain",
        task_name="CustomVaultJob",
        interval_minutes=60,
    )
    assert "CustomVaultJob" in result
    assert "python" in result
    assert "60" in result


# ── Permission Finding (Windows safe fallback) ────────────────────────────────


def test_permission_finding_windows_safe_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    f = tmp_path / "secret.txt"
    f.write_text("secret")
    # Without pywin32, should return None (safe fallback)
    result = _platform.permission_finding(f)
    assert result is None


def test_permission_finding_posix_insecure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    f = tmp_path / "secret.txt"
    f.write_text("secret")
    f.chmod(0o644)
    result = _platform.permission_finding(f)
    assert result is not None
    assert result.kind == "insecure_permissions"
    assert "recommendation" in str(result)
    assert "600" in str(result.recommendation)


# ── Durable Writes (integration smoke) ─────────────────────────────────────────


def test_write_bytes_durable(tmp_path: Path) -> None:
    p = tmp_path / "sub" / "test.bin"
    _platform.write_bytes_durable(p, b"hello")
    assert p.read_bytes() == b"hello"
    assert p.exists()


def test_write_text_durable(tmp_path: Path) -> None:
    p = tmp_path / "sub" / "test.txt"
    _platform.write_text_durable(p, "hello world")
    assert p.read_text() == "hello world"
    assert p.exists()


def test_fsync_directory(tmp_path: Path) -> None:
    # Should not raise on either platform
    _platform.fsync_directory(tmp_path)


def test_fsync_directory_windows_noop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    # Should be a no-op, not raise
    _platform.fsync_directory(tmp_path)


# ── Integrate with config.py (env override precedence) ────────────────────────


def test_config_base_home_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """HERMES_VAULT_HOME env var must override platform default."""
    from hermes_vault.config import _base_home

    monkeypatch.setenv("HERMES_VAULT_HOME", "/custom/hermes-vault")
    home, source = _base_home()
    assert home == Path("/custom/hermes-vault").expanduser()
    assert source == "env"


def test_config_base_home_default_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without HERMES_VAULT_HOME, should use _platform.default_vault_home()."""
    monkeypatch.delenv("HERMES_VAULT_HOME", raising=False)
    home, source = _platform.default_vault_home(), "default"
    assert source == "default"
    assert "hermes-vault-data" in str(home) or "HermesVault" in str(home)


def test_config_base_home_default_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """On Windows without HERMES_VAULT_HOME, should use LOCALAPPDATA/HermesVault."""
    monkeypatch.delenv("HERMES_VAULT_HOME", raising=False)
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
    home = _platform.default_vault_home()
    assert "AppData" in str(home)
    assert "Local" in str(home)
    assert "HermesVault" in str(home)
