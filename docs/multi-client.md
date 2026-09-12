# Single-Host Multi-Client Deployment Guide

**Audience:** operators running more than one agent (Hermes instances, Claude
Code, Codex, custom MCP clients, cron jobs) on **one Linux/macOS host** who
want them to share a single Hermes Vault safely.

**Status of server mode:** Hermes Vault is local-first by design. There is no
server mode, no multi-vault sync, and no network listener for the store (the
optional dashboard binds to 127.0.0.1 only). Multi-client here means N local
processes on one host — not a shared vault over the network. See
[What NOT to do](#what-not-to-do) before you wire anything exotic.

**Related issues:** #84 (multi-client deploy), #85 (SSO/OIDC — answered in
[bitwarden-comparison.md](bitwarden-comparison.md#ssooidc-85) and our
[non-goals](#explicit-non-goals)).

---

## The mental model

One vault = one `HERMES_VAULT_HOME` directory containing:

```
~/.hermes/hermes-vault-data/     (or any HERMES_VAULT_HOME you choose)
├── vault.db                      # SQLite store: encrypted payloads + plaintext metadata + audit log
├── master_key_salt.bin           # PBKDF2 salt — paired 1:1 with vault.db (never rotate one without the other)
└── policy.yaml                   # THE authorization boundary: which agent may do what
```

Three facts drive every recommendation below:

1. **Authorization is enforced in `policy.yaml`, not in the client.** Broker
   access (`get_ephemeral_env`), leases (v0.26.0 F-01 ownership checks), MCP
   tool calls, and mutations all evaluate policy **inside the vault process**
   before any secret is released. A client that lies about its identity still
   hits the policy wall — the `agent_id` is a policy key, not a credential.
2. **The vault is a single SQLite file.** Concurrent processes are safe for
   normal operations (short, transactional writes), but every client that
   holds unlock material can open the database. Keep the client count small
   and the OS account single.
3. **The store is bound to its salt.** `vault.db` and `master_key_salt.bin`
   are a pair. v0.26.0's restore preflight blocks salt-mismatched restores,
   but the guard can't help you if you copy files around manually — see
   [What NOT to do](#what-not-to-do).

---

## Supported topologies

| Topology | Verdict | Notes |
|---|---|---|
| N clients, one OS user, one vault home | **Supported** — the intended pattern | This guide |
| N clients, different OS users, one vault home | **Not supported** | Permission model is owner-only (0600/0700); no group mode exists |
| Clients on different hosts sharing one store (NFS/SMB/S3-sync/Dropbox) | **Never** | SQLite + network filesystems corrupt; no file locking across hosts; key material on shared storage defeats the design |
| A central "vault server" proxying secrets to many hosts | **Out of scope** | Standing non-goal since v0.22.0; see [non-goals](#explicit-non-goals) |

---

## Recipe: one vault, N agent clients (same OS user)

### 1. Install once

```bash
uv tool install git+https://github.com/asimons81/hermes-vault.git
# or: pipx install git+https://github.com/asimons81/hermes-vault.git
hermes-vault --version
```

All clients invoke the same binary. Different client *config files* point at
the same `HERMES_VAULT_HOME`; you never need per-client installs.

### 2. Initialize the vault once

```bash
export HERMES_VAULT_HOME=~/.hermes/hermes-vault-data
hermes-vault setup            # or: first `hermes-vault list` initializes it
```

Verify permissions are owner-only:

```bash
stat -c "%a %n" $HERMES_VAULT_HOME $HERMES_VAULT_HOME/vault.db $HERMES_VAULT_HOME/master_key_salt.bin
# 700 ...  600 vault.db  600 master_key_salt.bin
```

### 3. Give every client its own policy identity

This is the whole game. A "client" in policy terms is an `agent_id` — the key
policy.yaml authorizes. One policy file, one section per agent:

```yaml
# ~/.hermes/hermes-vault-data/policy.yaml
agents:
  hermes:                        # main Hermes agent: broad but bounded
    services: [openai, anthropic, github]
    service_actions:
      openai:    { actions: [get_env, verify, metadata] }
      anthropic: { actions: [get_env, verify, metadata] }
      github:    { actions: [get_env, metadata] }
    capabilities: [list_credentials]
    raw_secret_access: false     # secrets only via ephemeral env
    ephemeral_env_only: true
    max_ttl_seconds: 900

  coder:                         # a coding agent: narrower
    services: [github]
    service_actions:
      github: { actions: [get_env] }
    capabilities: []
    raw_secret_access: false
    ephemeral_env_only: true
    max_ttl_seconds: 900

  nightly-cron:                  # unattended job: narrowest, short TTLs
    services: [openai]
    service_actions:
      openai: { actions: [get_env] }
    capabilities: []
    raw_secret_access: false
    ephemeral_env_only: true
    max_ttl_seconds: 300
```

Rules of thumb (they show up in `hermes-vault policy doctor` findings when
you break them):

- **Both lists matter.** A service in `service_actions` but missing from
  `services` is **denied** — keep them in sync.
- **Deny by default.** An agent with no entry gets nothing. Start empty and
  add on demand.
- **`ephemeral_env_only: true` + `raw_secret_access: false`** for anything
  that runs unattended or executes model-controlled code.
- **TTLs short** (300–900s). Leases expire at env handoff as of v0.26.0
  (F-03); don't hand out day-long leases to agents.
- After editing policy, restart MCP clients so they pick it up
  (`pkill -HUP -f 'hermes-vault mcp'` for managed servers).

Validate before trusting it:

```bash
hermes-vault policy doctor
hermes-vault doctor                     # v0.26.0: full install/recovery sweep
hermes-vault agent context hermes          # what one agent can actually access
```

### 4. Wire each client to the vault

Every client gets: the same `HERMES_VAULT_HOME`, its **own** `agent_id`, and
unlock material from the operator (env var, keyring, or prompt — never baked
into a repo or container image).

**CLI / cron style** (explicit per invocation):

```bash
HERMES_VAULT_HOME=~/.hermes/hermes-vault-data \
HERMES_VAULT_PASSPHRASE="$(pass show vault-passphrase)" \
hermes-vault broker env openai --agent nightly-cron --ttl 300
```

**MCP style** (one MCP server process per client; identity comes from the
binding env vars, not a CLI flag):

```bash
# one launcher per client — e.g. /usr/local/bin/vault-mcp-coder
export HERMES_VAULT_HOME=~/.hermes/hermes-vault-data
export HERMES_VAULT_MCP_ALLOWED_AGENTS='coder'
export HERMES_VAULT_MCP_DEFAULT_AGENT='coder'
exec hermes-vault mcp
```

```json
// e.g. Claude Desktop / any generic MCP host
{
  "mcpServers": {
    "hermes-vault-coder": {
      "command": "/usr/local/bin/vault-mcp-coder"
    }
  }
}
```

With the binding set, the server denies any `agent_id` outside the allowed
list **before** policy evaluation, and bare resource reads resolve to the
default agent (v0.26.0 P4) instead of erroring. Clients that pass explicit
per-call `agent_id` (Hermes Agent does) can share a single unbound server —
policy still scopes every call.

Don't share one bound server across clients with different privileges; each
client process gets its own launcher with its own identity.

**`hermes-vault run`** (v0.26.0) is the tidiest CLI pattern for one-shot
jobs: it injects the secrets into the child process env only, for the
process's lifetime, under policy:

```bash
hermes-vault run --agent nightly-cron --service openai -- python ./nightly_job.py
```

### 5. Back up once (not per client)

```bash
hermes-vault backup --output ~/vault-backups/hermes-vault-$(date +%Y%m%d).json
hermes-vault backup-verify ~/vault-backups/hermes-vault-$(date +%Y%m%d).json
```

The backup is bound to the salt pair — store the salt file alongside it or
note its location (see `docs/safe-recovery.md`). Schedule a weekly backup and
a monthly verify; the health dashboard tracks the last backup audit row.

### 6. Monitor the shared surface

```bash
hermes-vault health          # composite: vault, backup age, leases, policy, oauth, audit
hermes-vault audit-verify    # Ed25519-signed audit chain integrity
hermes-vault policy doctor   # drift findings
```

The audit log is the shared record of who got what — review it when adding or
removing clients. Every broker grant, lease, and mutation is there with the
agent_id that requested it.

---

## Leases and concurrency on a shared vault

- Leases are per `agent_id`. Since v0.26.0 (F-01) non-operator callers only
  see/renew/revoke **their own** leases — enforced in the DB query, not the
  client.
- Expired leases are denied at env handoff (F-03). `hermes-vault lease list`
  shows what's live per agent.
- Normal concurrent CLI/MCP usage is safe: writes are short transactions.
  Avoid running `restore`, `rotate`, or `migrate-crypto` while clients are
  actively drawing secrets — those are operator windows.

---

## What NOT to do

These are the patterns that corrupt stores or silently destroy the security
model. All of them have broken real vaults:

1. **Never put the store on network storage.** No NFS, SMB, sshfs, S3-synced
   folders, Dropbox/Drive, or "sync the vault.db" schemes. SQLite requires
   real file locks; network filesystems fake them, and you get corruption
   that looks like random `database disk image is malformed` errors. Worse,
   `master_key_salt.bin` sitting on shared storage defeats the local-first
   threat model entirely. One host means one machine that can fsync.
2. **Never share one vault home across OS users.** The permission model is
   owner-only (0600 store, 0700 home). Group-readable modes are not
   supported; a second OS user either can't read the store (broken client)
   or you widened permissions for it (broken security). Use per-user vault
   homes instead — each with its own policy and salt pair.
3. **Never let two processes run key-material operations concurrently.**
   `rotate`, `restore`, `audit-checkpoint repair`, and `migrate-crypto`
   rewrite the store or its key binding. Run them from a maintenance window,
   one at a time, with clients paused.
4. **Never copy `vault.db` without its salt.** The pair is cryptographic.
   Restoring a db against the wrong salt is the classic brick; v0.26.0's
   restore preflight blocks it, but manual file copies bypass preflight.
   Copy both files or use `hermes-vault backup`.
5. **Never bake the passphrase into client config.** If it's in a file a
   client can read, the client can unlock everything directly, and policy is
   theater. Use the operator-controlled env/launcher pattern (see the
   [operator guide](operator-guide.md)).

---

## Explicit non-goals

- **Server mode / multi-host sharing** — standing non-goal since v0.22.0. A
  network-facing vault is a different product with a different threat model.
- **Multi-tenant RBAC** — policy.yaml is a single-operator authorization
  boundary, not an multi-tenant isolation system.
- **OIDC/SSO login** (#85) — not on the roadmap today. The demand signal is
  one zero-comment issue; the auth-authority redesign it would require is
  not justified. Revisit if the question recurs. See
  [bitwarden-comparison.md](bitwarden-comparison.md#ssooidc-85) for the
  reasoning and what to use instead today.

If you genuinely need multi-host secret sharing today: run one vault per host
and distribute secrets via your existing provisioning (not by syncing store
files), or evaluate a purpose-built server product (Infisical, HashiCorp
Vault) — the Bitwarden comparison doc covers where Hermes Vault deliberately
stops.
