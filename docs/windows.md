# Hermes Vault on Windows

Hermes Vault runs natively on Windows -- no WSL required. This document tracks the v0.14.0 release line and covers installation, configuration, CLI usage, and known limitations for Windows.

## Install

### Prerequisites

- Python 3.11+ installed (from [python.org](https://python.org) or the Microsoft Store)
- `pipx` or `uv` installed and in your PATH, OR a Python virtual environment

### Install with uv (recommended)

```powershell
uv tool install git+https://github.com/asimons81/hermes-vault.git@v0.14.0
```

### Install with pipx

```powershell
pipx install git+https://github.com/asimons81/hermes-vault.git@v0.14.0
```

### Install with pip (editable/dev)

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -e '.[dev]'
```

Verify the install:

```powershell
hermes-vault --help
```

## Default Locations

| Data | Windows Path | POSIX Equivalent |
|---|---|---|
| Vault data | `%LOCALAPPDATA%\HermesVault` | `~/.hermes/hermes-vault-data` |
| Vault database | `%LOCALAPPDATA%\HermesVault\vault.db` | `~/.hermes/hermes-vault-data/vault.db` |
| Salt file | `%LOCALAPPDATA%\HermesVault\master_key_salt.bin` | `~/.hermes/hermes-vault-data/master_key_salt.bin` |
| Policy file | `%LOCALAPPDATA%\HermesVault\policy.yaml` | `~/.hermes/hermes-vault-data/policy.yaml` |

**Override any of these** with the same environment variables as on POSIX:

```powershell
$env:HERMES_VAULT_HOME = "C:\Users\me\.hermes\hermes-vault-data"
$env:HERMES_VAULT_PASSPHRASE = "your-strong-passphrase"
$env:HERMES_VAULT_POLICY = "C:\Users\me\.hermes\hermes-vault-data\policy.yaml"
```

`HERMES_VAULT_HOME` is the highest-priority override on every platform.

## Passphrase and DPAPI

Hermes Vault is **passphrase-based** on all platforms (Windows, Linux, macOS). The legacy passphrase-only path is unchanged. With `pywin32` installed and `HERMES_VAULT_DPAPI=1` set, the master key is wrapped with DPAPI on write and unwrapped transparently on read. The passphrase is still required to derive the 32-byte key that DPAPI wraps. DPAPI is an at-rest protection, not a passphrase replacement.

```powershell
$env:HERMES_VAULT_PASSPHRASE = "your-strong-passphrase"
```

Or prompted interactively when not set. Profile-specific passphrases work:

```powershell
$env:HERMES_VAULT_PASSPHRASE_WORK = "your-work-passphrase"
```

## Quick Start (Windows)

```powershell
$env:HERMES_VAULT_PASSPHRASE = "choose-a-strong-local-passphrase"
hermes-vault --help
hermes-vault bootstrap --from-env .env --agent hermes --dry-run
hermes-vault status
hermes-vault health
hermes-vault import --from-env .env --dry-run
```

## CLI Commands

All CLI commands work from PowerShell:

```powershell
hermes-vault status
hermes-vault health
hermes-vault maintain --dry-run
hermes-vault backup --output C:\Users\me\vault-backup.json
hermes-vault backup-verify --input C:\Users\me\vault-backup.json
hermes-vault restore --dry-run --input C:\Users\me\vault-backup.json
hermes-vault policy doctor
hermes-vault dashboard --no-open
hermes-vault oauth login google --headless
hermes-vault oauth device-login github --alias work
hermes-vault update --check
```

### PowerShell-safe quoting

When passing paths with spaces, use PowerShell quoting:

```powershell
hermes-vault backup --output "C:\Users\me\My Backups\vault-backup.json"
hermes-vault import --from-env "C:\Users\me\Project\.env"
```

## Dashboard

The dashboard launches locally on `127.0.0.1`. Use `--no-open` to skip
auto-opening the browser:

```powershell
hermes-vault dashboard --no-open
```

Then open the printed URL in your browser manually.

## OAuth Login

Browser PKCE login works on Windows -- `webbrowser.open` opens your default
browser. For headless/device-code login:

```powershell
hermes-vault oauth device-login google --alias work
hermes-vault oauth login google --alias work --headless
```

## Backup and Restore

On Windows, use full paths:

```powershell
hermes-vault backup --output C:\Users\me\vault-backup.json
hermes-vault backup-verify --input C:\Users\me\vault-backup.json
hermes-vault restore --dry-run --input C:\Users\me\vault-backup.json
```

## Scheduled Maintenance

Hermes Vault supports both systemd (Linux/macOS) and Windows Task Scheduler.

To print a Windows Task Scheduler template:

```powershell
hermes-vault maintain --print-schedule
```

This outputs a PowerShell script and `schtasks.exe` command. The template
is a starting point -- review and adjust before use. It is not auto-installed.

To create the task manually using the template output:

```powershell
# Or use schtasks.exe directly
schtasks /Create /SC MINUTE /MO 15 /TN "HermesVaultMaintenance" /TR "hermes-vault --no-banner maintain --format json" /IT /DELAY 0005:00 /F
```

## Security on Windows

Hermes Vault uses **best-effort file security checks** on Windows:

- When `pywin32` is installed, Hermes Vault checks that sensitive files
  (vault database, salt, passphrase files, OAuth tokens) are not readable
  by `Everyone`, `Users`, or `Authenticated Users`.
- When `pywin32` is not available, Hermes Vault skips permission warnings
  rather than producing false scary chmod advice.
- On **all platforms**, no raw secrets are ever output in logs, CLI output,
  dashboard responses, errors, or markdown reports.

With DPAPI enabled, the master-key salt file is replaced by a DPAPI envelope that only your Windows user account can unwrap. Copying the envelope to another machine or another user account will fail at vault-open time. This is by design: DPAPI is a portability boundary, not a portability feature.

## Known Limitations

| Feature | Status | Details |
|---|---|---|
| DPAPI | Opt-in (Windows + pywin32) | Set `HERMES_VAULT_DPAPI=1` to wrap the master key with DPAPI. Falls back to legacy passphrase-only when pywin32 is not installed. |
| Windows ACL checks | Best-effort | Install `pywin32` for full ACL checking. |
| Directory fsync | Not available | `os.fsync` on directories has limited support on Windows. |
| Auto-update | Tool-dependent | Requires `pipx` or `uv` to be in PATH. |
| Task Scheduler | Template only | Not auto-installed. Review the template first. |
| Dashboard auto-open | Uses default browser | Behavior depends on Windows browser configuration. |
| Paths with spaces | Supported | Use PowerShell quoting (double quotes). |

## Troubleshooting

**"hermes-vault is not recognized"**
Make sure the install location is in your PATH. For `pipx`:
```powershell
pipx ensurepath
```

**Permission errors on vault files**
Hermes Vault uses `chmod` on POSIX and best-effort ACL checks on Windows.
On Windows, ensure your vault directory is in your user profile
(`%LOCALAPPDATA%`) and not in a system-managed location.

**Dashboard won't open**
Use `--no-open` and open the printed URL manually in your browser.
