# Hermes Vault v0.6.0 — Technical Review Report

**Date:** 2026-05-05
**Reviewer:** Hermes operator (kanban task t_e584bf0d)
**Verdict:** **BLOCK** — one security issue must be fixed before release.

---

## Summary

Reviewed all v0.6.0 changes across 51 files (10,376+ insertions). Seven of eight checklist items pass. One OAuth state-validation bypass in the MCP server is a blocking security issue. Everything else — encryption, PKCE, CSRF protection, atomic updates, audit trail, policy gates, test coverage, docs, and backward compatibility — is solid.

---

## Detailed Findings

### 1. OAuth flow security: PKCE S256, state validation, timeout — PASS (CLI flow)

The CLI LoginFlow (`flow.py`) is correct:

- PKCEGenerator generates 128-byte `code_verifier` via `secrets.token_bytes`, SHA-256 `code_challenge` (RFC 7636 S256).
- StateManager uses `secrets.token_urlsafe(32)` for state, `secrets.compare_digest` for timing-safe validation, clears state in `finally` (single-use), in-memory only — never persisted to disk.
- CallbackServer binds `127.0.0.1` only, auto-assigned port, suppresses HTTP access logging, accepts exactly one GET request then shuts down.
- TokenExchanger sends `code_verifier` to the token endpoint, 30s timeout, handles URL-encoded fallback responses.
- Timeout enforced via `threading.Event.wait(timeout=...)` with configurable default (120s).
- State validation happens BEFORE code exchange (step 8 before step 9 in `flow.py`).

### 2. Token storage: encrypted at rest, no plaintext leakage — PASS

- AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead` (not homegrown).
- PBKDF2-HMAC-SHA256 with 390,000 iterations, 256-bit derived key.
- 128-bit random nonce per encryption, versioned format (`aesgcm-v1`).
- All storage files (`db_path`, `salt_path`, backups, provider registry) secured with `0o600`.
- Secrets are never printed to stdout/cli except as truncated previews (12 chars + `...`).
- Callback server suppresses `log_message` to avoid leaking `code`/`state` in HTTP logs.
- Redaction helpers exist for log scrubbing (pre-existing, not touched by v0.6.0).

### 3. Auto-refresh: atomic updates, retry logic, audit trail — PASS

- `_update_vault_atomic` wraps token updates in `BEGIN EXCLUSIVE` → commit/rollback in a single SQLite transaction.
- Both access token and refresh token (if rotated) update atomically.
- Exponential backoff: base 2s, doubling per retry, max 3 retries (all configurable).
- `RefreshTokenExpiredError` correctly caught and surfaced (fixed by t_d715772b).
- Every refresh attempt (success or failure) logged via `_log_refresh()` → audit.record().
- Rotation counter and family_id tracking preserved on provider-side refresh token rotation.
- Proactive margin defaults to 300s, configurable.

### 4. MCP integration: tools work, policy gates enforced — **BLOCK** (see issue #1)

**Existing tools** (list_services, get_credential_metadata, get_ephemeral_env, verify_credential, rotate_credential, scan_for_secrets) — all PASS. Policy gates are enforced correctly, `agent_id` required, audit trail intact.

**New OAuth tools** — `oauth_login` and `oauth_refresh` — functional, but one security issue:

#### BLOCK Issue #1: State validation bypass in MCP `oauth_login`

**File:** `src/hermes_vault/mcp_server.py`, lines 487-490

```python
if hasattr(result, "state") and result.state:
    if not secrets.compare_digest(info["state"], result.state):
        logger.error("State mismatch for %s — possible CSRF", pending_key)
        return
```

**Problem:** The outer `if` guards the state check. `CallbackResult.state` defaults to `None`. If the browser callback arrives without a `state` query parameter (e.g., `GET /callback?code=abc123`), `result.state` is `None`, the outer condition is `False`, and state validation is *entirely skipped*. The code proceeds to exchange the authorization code without any CSRF protection.

This means an attacker who can craft a URL that reaches the callback server (local network, XSS on localhost, or process-level race) can inject an authorization code without knowing the state value.

**Severity:** Medium. The callback server binds to `127.0.0.1` only, limiting the attack surface to local processes. But the state parameter is meant to be *required*, not optional — this undermines the documented CSRF protection.

**Fix:** Require state unconditionally. Compare the CLI `flow.py` approach which validates state unconditionally (line 162-165):

```python
# Current (broken):
if hasattr(result, "state") and result.state:
    if not secrets.compare_digest(info["state"], result.state):
        ...

# Fix:
if not hasattr(result, "state") or not result.state:
    logger.error("No state in callback for %s — possible CSRF", pending_key)
    return
if not secrets.compare_digest(info["state"], result.state):
    logger.error("State mismatch for %s — possible CSRF", pending_key)
    return
```

#### Note: MCP server version was stale

Previously reported version as `0.5.0` at `mcp_server.py:186`. Fixed during review to `0.6.0`.

### 5. Test coverage — PASS

- 408 tests, all pass (verified: `python -m pytest tests/ -q` → 408 passed in 52.38s).
- OAuth-specific test breakdown:
  - `test_oauth_flow.py`: 14 tests (CLI flow integration, PKCE, state, timeout, error paths)
  - `test_oauth_exchange.py`: 12 tests (token exchange, error responses, URL-encoded fallback)
  - `test_oauth_refresh.py`: 22 tests (refresh detection, atomic updates, retry, expiry margin)
  - `test_mcp_server.py`: 28 tests (all MCP tools including OAuth, policy gates)
  - `test_oauth.py`: 26 tests (general OAuth flows)
- Additional coverage: broker (18), policy (28+8), vault (24), mutations (23), audit (23), CLI (30).
- Happy paths and error paths covered across all OAuth modules.
- **Gap:** No test for the state-bypass scenario in MCP `oauth_login` (the bypass I found wouldn't be caught by existing tests because they always include state). The fix should include a test.

### 6. Documentation accuracy — PASS

- `README.md`: "What's New in 0.6.0" section, MCP tool table with `oauth_login`/`oauth_refresh`, OAuth subsection, common commands — accurate.
- `docs/operator-guide.md`: Full OAuth Setup and Token Lifecycle — accurate CLI flags (`--alias`, `--scope`, `--no-browser`, etc.).
- `docs/architecture.md`: Complete oauth/ subsystem module reference, security posture — accurate.
- `docs/threat-model.md`: Comprehensive OAuth Threat Model (CSRF, code interception, token leakage, refresh theft, replay, thundering-herd, callback spoofing) with mitigations and residual risks — accurate and honest about limitations.
- `docs/migration-0.5-to-0.6.md`: Migration guide covers prerequisites, policy changes, checklist — accurate.
- `CHANGELOG.md`: Full v0.6.0 entry with Added, Changed, Security sections — accurate.
- No em-dashes found (double hyphens used throughout per Tony's style).
- CLI flag references in docs match actual CLI: `--alias`, `--scope` (singular, repeatable), `--no-browser`, `--dry-run`, `--all` — all verified against `cli.py`.
- `pyproject.toml` and `__init__.py` both at `0.6.0` — consistent.

### 7. Backward compatibility — PASS

- No vault schema changes (same `credentials` table, no new columns).
- Same encryption format (`aesgcm-v1`, AES-256-GCM, PBKDF2-HMAC-SHA256).
- Same salt file format and handling.
- Same runtime layout (`~/.hermes/hermes-vault-data`).
- Same environment variable names (`HERMES_VAULT_PASSPHRASE`, etc.).
- New features (OAuth login, auto-refresh) are opt-in — existing API-key credentials are completely unaffected.
- Existing MCP tools unchanged — `oauth_login` and `oauth_refresh` are additive.
- Policy format backward-compatible: legacy `services: [name]` and v2 `services: {name: {actions: [...]}}` both supported.
- Backup format unchanged (`hvbackup-v1`).

---

## Minor Observations (non-blocking)

These are observations, not blockers. Fix at your discretion.

1. **`raw_response` stored in access-token metadata** (`exchange.py:49`): The `to_credential_secret` method stores the full token endpoint JSON response in metadata (`raw_response`). This includes the access_token, refresh_token, and whatever else the provider returned. While everything is encrypted at rest, this is redundant storage — the access token is already the `secret` field, and the refresh token is stored separately. Consider trimming `raw_response` to non-sensitive fields only.

2. **`refresh_token` duplicated in access-token metadata** (`exchange.py:47`): The access token's metadata stores `refresh_token` explicitly. Since the refresh token is already stored as a separate vault record (alias `"refresh"`), this is unnecessary duplication inside encrypted payloads.

3. **`_pending_oauth` stores full broker object** (`mcp_server.py:431`): The `_pending_oauth` dict stores the broker object (containing vault, policy, audit, scanner) alongside PKCE data. The broker object is heavyweight and this holds a reference to the encrypted vault in memory. Not a leak (everything stays in-process), but worth noting for memory-conscious deployments.

4. **Concurrent login race condition** (`mcp_server.py:422`): `_pending_oauth[pending_key]` overwrites on concurrent logins for the same provider+alias. This is documented as a residual risk in the threat model (line 134). Acceptable for v0.6.0.

---

## Required Action Before Release

| # | Severity | Description | File | Fix |
|---|----------|-------------|------|-----|
| 1 | **BLOCK** | State validation bypass in MCP `oauth_login` — callbacks without a state parameter skip CSRF check | `mcp_server.py:487-490` | Require state unconditionally; bail if state is missing instead of skipping. See fix above. |

Once issue #1 is resolved, v0.6.0 is cleared for release. All other checklist items pass.
