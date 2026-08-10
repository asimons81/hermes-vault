# Mutation Surface — Rollback and Recovery Guide

**Hermes Vault v0.24.0 → v0.25.0**
**Branch:** `wt/hermes-vault-mutations-docs` (from `release/v0.24.0`)
**Date:** 2026-08-09
**Scope:** Desktop mutation surface (add / rotate / delete) — rollback procedure per surface, recovery drill, known limits.

Related artifacts:
- `security-architecture.md` §6 (phased plan), §8 (risks R1–R9) — `nexus-wiki/projects/hermes-vault-interactive/security-architecture.md`
- `ux-opportunity-brief.md` §5.3 (recovery guidance), §10 (non-goals) — `nexus-wiki/projects/hermes-vault-interactive/ux-opportunity-brief.md`
- Implementation branches: `wt/hermes-vault-mutations-bridge` (P1, `1b2712e`), `wt/hermes-vault-mutations-adapter` (P2, `5051e18`), `wt/hermes-vault-desktop-mutations-ui` (P3, `954e720`)

---

## 1. What changed and where

Three surfaces are modified. No mutation is possible unless **all three** are installed and the adapter env flag is set.

### 1.1 Bridge — `DesktopBridge` mutation methods (P1)

| Property | Value |
|---|---|
| Source file | `src/hermes_vault/desktop_bridge.py` |
| Install location | `~/.local/share/uv/tools/hermes-vault/lib/python3.12/site-packages/hermes_vault/desktop_bridge.py` |
| Branch | `wt/hermes-vault-mutations-bridge` (`1b2712e`) |

Changes from v0.24.0 baseline:

- **New `allow_mutations` flag** on `DesktopBridge.__init__` (`desktop_bridge.py:591`). When `False` (default), mutation methods return `MUTATIONS_DISABLED` error envelope (`desktop_bridge.py:818-822`).
- **Three mutation methods** — `_method_add` (`:850`), `_method_rotate` (`:885`), `_method_delete` (`:914`). Each:
  - Calls `_require_mutations()` → `MUTATIONS_DISABLED` if `allow_mutations=False`
  - Rejects renderer-supplied `agent_id` (`_reject_renderer_agent_id`, `:836-839`)
  - Validates `request_id` (`_validate_request_id`, `:825-833`)
  - Builds a **writable context** (`_wctx`, `:656-669`) — opens SQLite for write (only gated by `_require_mutations`)
  - Routes through `Broker` → `VaultMutations` (the single audited write path)
  - Traps `AuditIntegrityError` → `AUDIT_INTEGRITY` bridge error
  - Returns metadata-only response (`_mutation_result`, `:978`)
- **`delete` confirmation gate.** Before any write, `_method_delete` resolves the target by `service_or_id`/`alias` and checks `confirmation` matches the credential id or `service:alias` (`:936-950`). Mismatch → `CONFIRMATION_MISMATCH`.
- **`_method_hello` advertises mutations** via `mutations: true` and adds `MUTATION_METHODS` to capabilities (`:675-677`) when `allow_mutations=True`.
- **`run_desktop_bridge`** accepts `allow_mutations: bool = False` (`:1061`) and passes it to the handler.

### 1.2 Adapter — POST mutation routes (P2)

| Property | Value |
|---|---|
| Source file | `plugins/hermes-vault-desktop/dashboard/plugin_api.py` |
| Install location | `~/.hermes/plugins/hermes-vault-desktop/dashboard/plugin_api.py` |
| Branch | `wt/hermes-vault-mutations-adapter` (`5051e18`) |

Changes from v0.24.0 baseline:

- **Three POST routes** — `POST /mutations/add` (`:635`), `POST /mutations/rotate` (`:648`), `POST /mutations/delete` (`:661`). Gated behind `HERMES_VAULT_DESKTOP_MUTATIONS=1` (`:552-555`, returns 404 when not set).
- **Bearer-only auth** on mutation routes. `_require_bearer` (`:452-460`) rejects missing/non-Bearer tokens with 401. No `?token=` query fallback on these routes.
- **Pre-spawn body validation.** `_read_mutation_body` (`:684`) reads, bounds, and parses the body before any child spawn; oversized/invalid JSON → 400.
- **`_validate_mutation_body`** (`:494`) enforces an allowlist of fields per mutation kind.
- **`--allow-mutations` argv** appended to bridge child on mutation routes only (`_run_bridge`, `:359-360`). GET routes never pass this flag.
- **`delete` double-gate.** Adapter rejects missing/empty `confirmation` with 403 BEFORE child spawn (`:674-679`); the bridge enforces the exact-match check.
- **`hello` capability advertisement.** When `HERMES_VAULT_DESKTOP_MUTATIONS=1`, `/hello` overlays `mutations: true` and adds mutation method names to `capabilities` (`:573-578`). This is purely an adapter-level advertisement; the child is still launched WITHOUT `--allow-mutations` on the GET hello route.
- **R1 Host-header hardening.** The adapter validates `Host` against `127.0.0.1`/`localhost` (P2 scope — see `security-architecture.md` risk R1).

### 1.3 Runtime plugin — mutation UI (P3)

| Property | Value |
|---|---|
| Source file | `plugins/hermes-vault-desktop/desktop/plugin.js` |
| Install location | `~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js` |
| Branch | `wt/hermes-vault-desktop-mutations-ui` (`954e720`) |
| v0.24.0 baseline | 502 lines (commit `8a79a25`) |
| v0.25.0 post-mutation | 1210 lines |

Changes:

- **`mutationsEnabled` gate.** Derived from `helloQ.data.mutations === true` (`:1087`). When `false`, all mutation dialogs show a disabled-state message directing the operator to the adapter flag.
- **Add / rotate / delete dialogs** with masked secret fields, confirmation text, audit result display, error-state taxonomy (`mutationErrorDetails`, `:332`).
- **6-tab IA** (Credentials → Access Requests → Leases → Policy → Audit → Operations).
- **Read-only mode preserved.** When `mutationsEnabled` is false, the Add button is hidden (`:878`), mutation dialogs are disabled, but all read-only tabs continue working (gate I8).

---

## 2. Rollback procedures

### 2.1 Plugin UI — restore v0.24.0 plugin.js

The desktop page stays read-only after rollback (invariant I8). Mutations simply stop being offered.

```bash
# Restore the v0.24.0 plugin.js from git (commit 8a79a25)
cd /home/tony/workspace/hermes-vault
git show 8a79a25:plugins/hermes-vault-desktop/desktop/plugin.js \
  > ~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js
```

The desktop plugin reloads on next page navigation to `/hermes-vault`. Verify: the Add button is gone; Approve/Deny buttons throw "read-only integration does not perform Vault mutations."

To re-enable the mutation UI later, reinstall from branch:

```bash
cd /home/tony/workspace/hermes-vault
git worktree add /tmp/hermes-vault-mutations-ui -b wt/hermes-vault-desktop-mutations-ui
cd /tmp/hermes-vault-mutations-ui
cp plugins/hermes-vault-desktop/desktop/plugin.js \
  ~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js
```

### 2.2 Adapter — disable mutation routes

**Option A: remove the env flag (zero-downtime, recommended)**

```bash
# The mutation routes return 404 when the env var is unset/empty.
# Set it to anything other than 1/true/yes/on to disable.
unset HERMES_VAULT_DESKTOP_MUTATIONS
# Restart the adapter (managed by the desktop plugin process)
```

Read-only GET routes (`/hello`, `/overview`, `/credentials`, `/leases`, `/policy`, `/requests`, `/audit`, `/integrity`) are unaffected. The `/hello` route stops advertising mutations, which gates the P3 UI.

**Option B: reinstall v0.24.0 plugin_api.py**

```bash
cd /home/tony/workspace/hermes-vault
git show 8a79a25:plugins/hermes-vault-desktop/dashboard/plugin_api.py \
  > ~/.hermes/plugins/hermes-vault-desktop/dashboard/plugin_api.py
```

This removes the POST routes and R1 Host-header hardening entirely. The adapter reverts to GET-only (8 routes). Note: you lose the R1 hardening — the Host header is no longer validated on GET routes either.

### 2.3 Bridge — disable or revert mutations

**Option A: disable mutations (zero-downtime)**

Stop passing `--allow-mutations` to the bridge child. On the adapter, this is controlled by the `HERMES_VAULT_DESKTOP_MUTATIONS` env flag (see §2.2). On the CLI, omit `--allow-mutations`:

```bash
# Without --allow-mutations, the bridge returns MUTATIONS_DISABLED
hermes-vault desktop-bridge  # no --allow-mutations → read-only
```

No `MUTATIONS_DISABLED` error is fired for read methods — only add/rotate/delete are gated.

**Option B: revert to v0.24.0 bridge package**

```bash
# Reinstall the v0.24.0 release from PyPI
uv tool install --force hermes-vault==0.24.0

# Or if using pipx:
pipx install --force hermes-vault==0.24.0
```

`hermes-vault update` follows the same semantics (it reinstalls the last tagged release).

---

## 3. Recovery for real credentials

### Backup before any mutation

```bash
hermes-vault backup --output ~/vault-backups/hermes-vault-$(date +%Y%m%d-%H%M).json
```

### Restore drill (dry-run first)

```bash
# Verify the backup is decryptable
hermes-vault backup-verify ~/vault-backups/hermes-vault-<timestamp>.json

# Dry-run restore — inspects the backup, prints what would change, writes nothing
hermes-vault restore --input ~/vault-backups/hermes-vault-<timestamp>.json --dry-run
```

### Live restore (CLI-only)

```bash
hermes-vault restore --input ~/vault-backups/hermes-vault-<timestamp>.json
```

Restore is CLI-only. The desktop never offers restore — it is explicitly excluded from the mutation surface (see `ux-opportunity-brief.md` §10 non-goals).

### Post-restore actions

1. Run `hermes-vault audit-verify` to confirm the integrity chain is healthy.
2. Run `hermes-vault verify --all` to re-check credential validity.
3. Restart any running MCP servers: `pkill -HUP -f 'hermes-vault mcp'`.

### Delete recovery

Deletion is **destructive and irreversible** (no soft-delete, no undo). If a credential was deleted unintentionally:

1. If you have a recent backup (made before the delete), restore it (see above).
2. If you do not, re-add the credential: `hermes-vault add <service> --alias <name> --secret <value>`.
3. Check lease impact: `hermes-vault leases` — active leases referencing the deleted credential will become stale (see §5).

The mutation surface enforces typed confirmation before deletion (the adapter rejects missing `confirmation` with 403, and the bridge requires it to match the credential id or `service:alias`). A backup reminder is displayed in the desktop delete dialog.

---

## 4. Data-safety behavior

### Deny-by-default

Every mutation method in `VaultMutations` (`mutations.py`) is deny-by-default:

- **Non-operator agents** must have the capability (`add_credential`) and service action (`add_credential` / `rotate` / `delete`) in policy (`mutations.py:77-93`).
- **Operator agent** bypasses policy but still audits every mutation (operator agent id = `"operator"`, `mutations.py:36`).
- The desktop bridge stamps `OPERATOR_AGENT_ID` on all mutation calls (`desktop_bridge.py:872`, `:901`, `:954`). Renderer-supplied `agent_id` is rejected (`:836-839`).

### Audit integrity backstop

On `AuditIntegrityError` (corrupted chain), `_record_mutation` **rolls back the credential write** (`mutations.py:124-137`, `:190-199`; `:252-263` differs slightly — delete doesn't roll back because the credential was already removed, but the audit entry fails to seal):

- `add_credential` integrity failure → credential deleted from vault, `allowed=False`, reason: "audit integrity: <error>. Run `hermes-vault audit-verify` to inspect the chain; the credential was not persisted."
- `rotate_credential` integrity failure → "the rotated secret is unchanged" — rotation did not persist.
- `delete_credential` integrity failure → credential IS deleted (the vault op succeeded), but the audit entry failed to seal. The result is `allowed=False` and the operator should investigate.

The bridge maps `AuditIntegrityError` to `AUDIT_INTEGRITY` error code (`desktop_bridge.py:879-880`, `:908-909`, `:960-961`). The adapter maps `AUDIT_INTEGRITY` to HTTP 409 (`plugin_api.py:343`).

### After a failed mutation

```bash
# 1. Check integrity chain
hermes-vault audit-verify

# 2. Inspect recent audit for the failed operation
hermes-vault audit --limit 20

# 3. Verify the credential state
hermes-vault list | grep <service>
```

---

## 5. Lease impact

### Post-delete behavior (risk R4)

Deleting a credential does **NOT** auto-revoke leases referencing it (`vault.delete` at `vault.py:618` removes only the credential row; no lease cascade). This is risk R4 from `security-architecture.md` §8.

After deleting a credential:

1. **Active leases become stale.** The lease record persists but the credential it references no longer exists.
2. **Brokered env for that credential fails.** `Broker.get_ephemeral_env()` will fail because the credential can't be resolved.
3. **Inspect leases:**
   ```bash
   hermes-vault leases
   # Look for leases where the service matches the deleted credential
   ```
4. **Revoke stale leases manually:**
   ```bash
   hermes-vault lease revoke <lease-id>
   ```

The desktop UI surfaces lease count alongside credentials so the operator can inspect before deletion (agent-dependent leases visible in the Leases tab).

---

## 6. Known limits

### R5 — Rotate idempotency

Rotating a credential with the **same secret twice** succeeds both times (no server-side rejection). `request_id` is echoed in the response (`desktop_bridge.py:999`) and stored in audit metadata (`mutations.py` call), making duplicates observable via the audit log, but not rejected.

Mitigation: inspect `hermes-vault audit --limit 50` for duplicate `request_id` values after a rotation. If you see the same `request_id` twice with the same `action: rotate_credential`, the operation was unintentionally duplicated.

### R6 — Renderer memory zeroization

Full memory zeroization of the secret field is **not feasible** in JavaScript/Electron (the plugin renders in the desktop's renderer process). The mitigation implemented in P3:

- The secret is held only in component state during form submission.
- State is cleared on dialog close / error.
- No secret in query keys, `ctx.storage`, `localStorage`, `console.log`, or DOM persistence.
- The bridge never serializes raw secrets in any response (`raw_values_returned: False`; mutation responses use `CREDENTIAL_FIELDS` + presence flags only).

This is an accepted risk (`security-architecture.md` R6). The operator guide documents the limitation.

### R7 — Agent-scoped mutations

The desktop mutation surface is **operator-only**. There is no path for agent-scoped add/rotate/delete through the bridge (the bridge rejects `agent_id` from the renderer). If agent-scoped mutations are needed in the future, reuse MCP binding semantics (`mcp_server.py:323-350`).

### R8 — Bridge protocol version

Mutation methods were added without bumping `PROTOCOL_VERSION` (still v1). They are additive and gated; the read surface is unchanged (invariant I8). If the read surface ever changes shape, bump `PROTOCOL_VERSION` (`desktop_bridge.py:67`) and verify `UNSUPPORTED_PROTOCOL` handling (already present at `:609-610`).

---

## 7. How to re-enable / revert the whole feature

### Re-enable (after review + operator approval)

```bash
# 1. Install the mutation-capable bridge
uv tool install --force hermes-vault

# 2. Install the mutation adapter
# (Assuming the adapter ships as part of the plugin package)
cp /home/tony/workspace/hermes-vault/plugins/hermes-vault-desktop/dashboard/plugin_api.py \
  ~/.hermes/plugins/hermes-vault-desktop/dashboard/plugin_api.py

# 3. Enable the adapter env flag
export HERMES_VAULT_DESKTOP_MUTATIONS=1

# 4. Install the mutation UI plugin
cp /home/tony/workspace/hermes-vault/plugins/hermes-vault-desktop/desktop/plugin.js \
  ~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js
```

### Full revert (restore v0.24.0 state across all three surfaces)

```bash
# 1. Disable the adapter flag
unset HERMES_VAULT_DESKTOP_MUTATIONS

# 2. Reinstall v0.24.0 bridge
uv tool install --force hermes-vault==0.24.0

# 3. Restore v0.24.0 adapter (commit 8a79a25)
cd /home/tony/workspace/hermes-vault
git show 8a79a25:plugins/hermes-vault-desktop/dashboard/plugin_api.py \
  > ~/.hermes/plugins/hermes-vault-desktop/dashboard/plugin_api.py

# 4. Restore v0.24.0 plugin.js
git show 8a79a25:plugins/hermes-vault-desktop/desktop/plugin.js \
  > ~/.hermes/desktop-plugins/hermes-vault-desktop/plugin.js
```

After revert: the desktop page works read-only; Add button is absent; Approve/Deny buttons throw the read-only error; `/hello` does not advertise mutations.

---

## References

- `nexus-wiki/projects/hermes-vault-interactive/security-architecture.md` — full threat model, 22-row test matrix, invariants I1–I10, risks R1–R9
- `nexus-wiki/projects/hermes-vault-interactive/ux-opportunity-brief.md` — operator jobs, IA, add/rotate/delete flows, stale signals, recovery guidance (§5.3), non-goals (§10)
- `docs/operator-guide.md` — general operator guide for hermes-vault
- `docs/threat-model.md` — broader vault threat model (not desktop-specific)
- `docs/mcp-server.md` — MCP integration and mutation surface documentation

**Source verification:** All file paths, line numbers, and behaviors were verified by direct inspection of the P1 (`wt/hermes-vault-mutations-bridge`, `1b2712e`), P2 (`wt/hermes-vault-mutations-adapter`, `5051e18`), and P3 (`wt/hermes-vault-desktop-mutations-ui`, `954e720`) branches on 2026-08-09.
