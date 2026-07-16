# Security Policy

Hermes Vault handles credential material and agent access boundaries. Please report suspected vulnerabilities privately and do not include real secrets, vault databases, salt files, provider responses, or operator logs in a public issue.

## Supported versions

| Version | Supported |
|---|---|
| 0.20.x | Yes |
| Earlier releases | Upgrade before requesting a fix unless the issue prevents migration |

Security fixes are developed against the latest release line. A fix may be backported when the vulnerability blocks safe upgrade or recovery.

## Reporting a vulnerability

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability** to create a private security advisory.
3. Describe the affected version, platform, attack path, expected boundary, and a minimal reproduction using fake credentials and a temporary `HERMES_VAULT_HOME`.
4. State whether the issue may expose raw secrets, encrypted payloads, passphrases, salts, OAuth tokens, dashboard tokens, agent identities, audit records, backups, or incident bundles.

If private vulnerability reporting is unavailable, open a public issue containing only a request for a private contact channel. Do not publish exploit details or sensitive artifacts.

## What to include

- Hermes Vault version and commit SHA
- Operating system and Python version
- Installation method
- Relevant policy shape with names and values replaced
- Minimal reproduction using fake credentials
- Whether the dashboard, CLI, MCP server, Secret Source plugin, backup/restore path, OAuth flow, or filesystem scanner is involved
- The security boundary you expected to hold

## Response process

The maintainer will acknowledge the report, reproduce it in an isolated environment, assess affected versions, and coordinate a fix and disclosure. Public details should wait until a patched release is available or the maintainer confirms disclosure is safe.

## Scope priorities

Reports involving the following receive the highest priority:

- raw-secret or token disclosure
- passphrase, key-derivation, salt, or backup-decryptability failures
- policy or lease bypass
- MCP caller-identity or binding bypass
- dashboard remote-binding or token-auth bypass
- unsafe OAuth callback, refresh, or provider-response handling
- path traversal, unsafe restore/import, or scanner escape
- command injection or unintended shell execution
- secret leakage through logs, errors, audit records, generated context, screenshots, or incident bundles

## Safe research rules

Use only credentials and vaults you own. Keep tests local, use temporary directories, avoid destructive testing against real operator vaults, and stop if testing could affect another user or external service.
