# Native Windows Support — Implementation Plan

## Overview

Hermes Vault currently assumes POSIX-style paths, permissions (chmod, stat),
shell behavior (systemd, shlex-only formatting), and platform conventions.
This plan adds native Windows support without breaking existing Linux/macOS behavior.

## Unix/Linux Assumptions Identified

1. **Config path defaults**: ~/.hermes/hermes-vault-data assumed POSIX home.
2. **Default scan roots**: ~/.bashrc, ~/.zshrc, ~/.profile — Unix shell dotfiles.
3. **File permissions**: chmod(0o600), chmod(0o700), stat.S_IMODE, stat.S_IRWXG|S_IRWXO — everywhere (vault, crypto, audit, bootstrap, oauth/providers, backup).
4. **Durable writes**: os.fsync(fd), os.open(path, os.O_RDONLY) — _write_bytes_durable, _write_text_durable, _fsync_directory, _replace_salt_durable.
5. **Shell command rendering**: _format_command has os.name == nt handling but is only in update.py.
6. **Scheduled maintenance**: --print-systemd only — no Windows Task Scheduler.
7. **Browser opening**: webbrowser.open() works cross-platform but not tested on Windows.
8. **Executable detection**: shutil.which("pipx"), sys.executable — path formats differ.
9. **Temp path detection**: startswith("/tmp/") in dashboard warning.

## Implementation Steps

### 1. Create _platform.py — central platform abstraction

Centralizes:
- PlatformKind enum (WINDOWS, POSIX)
- current_platform() -> PlatformKind
- default_vault_home() -> Path — POSIX: ~/.hermes/hermes-vault-data, Windows: %LOCALAPPDATA%/HermesVault  
- default_scan_roots() -> list[Path] — POSIX: bash/zsh/profile; Windows: empty/%USERPROFILE%
- secure_file(path) -> None — POSIX: chmod(0o600); Windows: best-effort ACL
- secure_directory(path) -> None — POSIX: chmod(0o700); Windows: best-effort
- set_owner_only(path) -> None — POSIX: chmod(0o600); Windows: no-op
- mode_is_insecure(path) -> bool — POSIX: stat mode; Windows: best-effort ACL
- permission_finding(path) -> FindingRecord | None
- write_bytes_durable(path, content) -> None
- write_text_durable(path, content) -> None
- fsync_directory(path) -> None
- temp_path_check(path) -> bool
- format_command(parts) -> str
- shell_safe_quote(s) -> str — for PowerShell-safe quoting
- open_browser(url) -> bool

### 2. Update config.py
### 3. Update permissions.py
### 4. Update vault.py
### 5. Update crypto.py
### 6. Update audit.py
### 7. Update bootstrap.py
### 8. Update oauth/providers.py
### 9. Update cli.py — platform-aware maintain, temp check
### 10. Update dashboard.py — platform-aware temp check
### 11. Update update.py — verify Windows command formatting
### 12. Add tests/test_platform.py
### 13. Update README.md with Windows section
### 14. Create docs/windows.md

## Files Changed

| File | Change |
|------|--------|
| src/hermes_vault/_platform.py | NEW — platform abstraction |
| src/hermes_vault/config.py | Use platform defaults |
| src/hermes_vault/permissions.py | Delegate to _platform |
| src/hermes_vault/vault.py | Use platform durable write |
| src/hermes_vault/crypto.py | Use platform secure_file |
| src/hermes_vault/audit.py | Use platform secure_file |
| src/hermes_vault/bootstrap.py | Use platform secure_file |
| src/hermes_vault/oauth/providers.py | Use platform secure_file |
| src/hermes_vault/cli.py | Platform-aware maintain |
| src/hermes_vault/dashboard.py | Temp check fix |
| tests/test_platform.py | NEW — platform tests |
| README.md | Windows install section |
| docs/windows.md | NEW — Windows docs |

## Backward Compatibility

- All existing Linux/macOS tests must pass unchanged
- Vault database format is unchanged
- All CLI commands work identically on POSIX

## Known Limitations

- Windows uses passphrase-based auth, not DPAPI
- Windows ACL checks are best-effort
- Task Scheduler output is a template, not auto-installed
