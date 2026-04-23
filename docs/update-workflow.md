# Hermes Vault Update Workflow

Hermes Vault treats CLI upgrades as a guarded lifecycle action, not a blind self-updater.

## Canonical Release Source

- Hermes Vault currently resolves the latest available version from GitHub Releases for `asimons81/hermes-vault`.
- The update workflow does not assume PyPI publishing.
- Release tags are treated as the authoritative version boundary for update checks and manual fallback instructions.

## Supported Auto-Update Methods

- `pipx`
- `uv tool`

These installs are isolated from project environments, so Hermes Vault can safely ask the original tool manager to reinstall from the canonical GitHub release tag.

## Manual-Only Methods

- editable/dev installs
- standard `pip` and ad-hoc virtualenv installs
- unknown or ambiguous installs

These environments are detected and reported, but Hermes Vault refuses to mutate them automatically. Instead, it prints an exact manual command based on the detected state.

## Safety Constraints

- `hermes-vault update --check` is read-only.
- `hermes-vault update` prints the exact command before executing it.
- Unsupported or ambiguous installs fail closed with a non-zero exit.
- The workflow does not mutate vault data, indexes, policy files, or config as part of package upgrade.
- Package upgrade remains separate from any future schema or migration work.
- Successful auto-updates are verified by checking the installed Hermes Vault version in a fresh subprocess after the update command returns.

## Rationale

Hermes Vault is installed through multiple workflows today, and they do not all have the same safety profile. `pipx` and `uv tool` provide isolated tool environments that are a good fit for guarded automation. Generic `pip` and editable installs are too ambiguous to modify safely from inside the running process, especially while GitHub Releases remains the canonical source of truth.
