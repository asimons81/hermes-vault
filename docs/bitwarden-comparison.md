# Hermes Vault vs. Bitwarden — an honest comparison

**Why this exists:** issue #84 asked "How will this work with bitwarden? How
does it improve on bitwarden only?" — fair questions that deserve a
verifiable answer instead of marketing. This page makes only claims you can
check, each with a source and a date.

**Claim freshness:** Bitwarden facts verified against Bitwarden's public help
center on **2026-09-11** (sources linked per row). Hermes Vault facts
verified against this repository at **v0.26.0** (file references given).
Bitwarden ships continuously — re-verify their side before making decisions
based on this table. Our side changes only with releases.

**The one-sentence version:** Bitwarden is an excellent password manager for
humans; Hermes Vault is a credential broker for AI agents and automation on
one host. They solve overlapping-but-different problems, and since v0.26.0
you can import from Bitwarden directly
([`import bitwarden`](#moving-between-them-import)), so the choice is not
either/or.

---

## Side-by-side

| Dimension | Hermes Vault (v0.26.0) | Bitwarden (verified 2026-09-11) |
|---|---|---|
| **Primary job** | Broker credentials to agents/automation on one host, under per-agent policy | Store and autofill passwords/passkeys for humans across devices |
| **Architecture** | Local-first: encrypted SQLite store on your disk, no server, no account (`src/hermes_vault/vault.py`) | Cloud-synced vault (official hosted or self-hosted server); clients sync through it |
| **Cryptography** | AES-256-GCM per credential, AAD-bound v2 envelopes; PBKDF2-SHA256 390,000 iterations (`src/hermes_vault/crypto.py`: `PBKDF2_ITERATIONS = 390_000`) | AES-256-CBC + HMAC; PBKDF2-SHA256 600,000 default iterations, optional Argon2id KDF ([white paper](https://bitwarden.com/help/bitwarden-security-white-paper/)) |
| **Who can read a secret** | Processes you explicitly authorize via `policy.yaml` — deny-by-default, per agent, per service, per action | Anyone with the master password (or an unlocked client session/org grant) |
| **Agent/automation access** | The core product: MCP server, broker `get_env`, TTL'd leases, `run` child-env injection | Not a first-class concept; CLI + `bw serve`/SDKs exist but carry no per-agent authorization |
| **Per-agent authorization** | Yes — policy engine with services, actions, capabilities, TTL caps, raw-secret denial (`src/hermes_vault/policy.py`) | No per-agent model; org collections gate human members |
| **Audit trail** | Every grant/lease/mutation logged; Ed25519-signed integrity chain since v0.21.0, tamper-evident (`src/hermes_vault/audit_integrity/`) | Event logs in org plans; no cryptographic per-user integrity chain |
| **Secret delivery to processes** | Ephemeral env (never raw secret by default), leases with expiry enforced at handoff (v0.26.0), MCP tools, child-process env injection | Manual copy/paste, browser extension autofill, CLI `bw get` |
| **Credential verification** | Built-in verifiers hit provider endpoints; statuses (valid/expired/invalid) tracked per credential | Vault Health reports (paid tiers) check breaches/reused/weak — different axis |
| **Human UX** | Terminal CLI + local dashboard; deliberately no browser extension/autofill/mobile app | Best-in-class: browser extensions, mobile/desktop apps, autofill, passkeys |
| **Cross-device sync** | None — by design; the store stays on one host (see [multi-client guide](multi-client.md)) | Core feature (zero-knowledge sync) |
| **Sharing/teams** | Not supported — single-operator model | Organizations, collections, groups (free & paid tiers) |
| **Passkey/TOTP management** | TOTP seeds can ride an imported secret (documented convention); no authenticator UI | Full passkey storage and TOTP authenticator across clients |
| **Recovery story** | Salt-paired backups with decryptability proof, restore preflight receipts, non-destructive audit repair, `doctor` (v0.26.0) | Master password reset flow (cloud account model) |
| **Cost** | Free, MIT-licensed, self-hosted by definition | Free tier generous; paid tiers for orgs/health reports ([pricing](https://bitwarden.com/pricing/)) |

---

## Where Bitwarden wins (said plainly)

If your problem is "I am a human with 300 logins across 5 devices" —
Bitwarden is the better tool, full stop:

- **Sync and ubiquity.** Zero-knowledge sync, mature clients everywhere,
  autofill that actually works day-to-day.
- **Human-grade features.** Passkeys, TOTP authenticator, secure notes with
  attachments, send/expiring shares, emergency access, breach monitoring.
- **Team sharing.** Organizations and collections are a real product;
  Hermes Vault has nothing equivalent and doesn't try to.
- **KDF flexibility.** Argon2id option and a higher default PBKDF2
  iteration count than ours. (Our 390,000 figure is not "better" — it's a
  different local-performance tradeoff for an unattended-launcher model.)

## Where Hermes Vault wins (with receipts)

If your problem is "I run AI agents and automation on a machine and need to
hand them credentials without handing them the keys to everything":

- **Deny-by-default per-agent policy.** An agent gets exactly the services,
  actions, and TTL you wrote in `policy.yaml` — evaluated inside the vault
  process, not trusted from the client. Bitwarden has no equivalent boundary
  between "the thing asking" and "the whole vault".
- **Secrets as ephemeral material, not files.** Default path is a
  short-lived environment injection (`broker env`, leases enforced at
  handoff since v0.26.0), never a plaintext file the agent can exfiltrate
  later. `imported_from` provenance tags every credential.
- **A signed audit chain.** You can prove after the fact which agent got
  which service when — tamper-evident since v0.21.0. For anyone running
  agents against production credentials, this is the difference between
  "trust me" and evidence.
- **MCP-native.** First-class Model Context Protocol server: agents
  discover and request credentials through the same policy path as
  everything else.
- **No account, no cloud, no sync surface.** The threat model is "one host,
  one operator" — there is no server to attack because there is no server.

## Where neither wins (honest limits of ours)

- **Multi-host fleets.** Neither Bitwarden's sync nor Hermes Vault addresses
  "N machines, one policy authority" well — Bitwarden because agents aren't
  members, we because local-first means local. If you need fleet secret
  infrastructure, look at purpose-built server products (HashiCorp Vault,
  Infisical).
- **TOTP depth.** We preserve TOTP seeds inside imported secrets; we don't
  generate codes, and agents shouldn't hold second factors for interactive
  services anyway.
- **SSO/OIDC (#85).** Not supported, not on the near-term roadmap — see
  [below](#ssooidc-85).

---

## Moving between them: import

v0.26.0 ships a Bitwarden import bridge:

```bash
bw export --format json --output bw-export.json   # from Bitwarden
hermes-vault import bitwarden --file bw-export.json --dry-run
hermes-vault import bitwarden --file bw-export.json --yes
rm bw-export.json                                  # it is plaintext — delete it
```

What maps where (full rules in `src/hermes_vault/bitwarden.py` docstring):
logins → credentials (username→alias, password→secret, TOTP seed preserved
in the secret, custom fields→encrypted metadata, notes→plaintext notes,
folders→service-name prefixes), secure notes → note credentials. Card and
identity items are skipped with a reason — nothing silently dropped. The
planned import previews without touching the vault; apply goes through the
audited mutation path with a summary audit event; collisions are resolved by
an explicit `--on-collision skip|rename|fail` policy.

The export file is **plaintext** — Bitwarden's own guidance is to delete it
immediately after use ([export docs](https://bitwarden.com/help/export-your-data/));
the CLI warns and the docs repeat it. Keep Bitwarden as the human-facing
vault; import the machine-usable subset into Hermes Vault for agents.

There is no Hermes Vault → Bitwarden exporter for machine credentials
(their importer covers 1Password/Chrome/LastPass/etc., not us). Round-trip
fidelity would be partial anyway (custom-field metadata and per-agent
policy have no Bitwarden equivalent); `hermes-vault export --with-secrets`
JSON is the honest escape hatch if you need raw values out.

## SSO/OIDC (#85)

Asked: "Would this in future be able to work with an OAuth 2.0 / SSO
provider — like Pocket ID?"

Not today, and not in the near-term plan. The demand signal so far is a
single zero-comment issue, while an OIDC auth authority is a large,
risk-heavy subsystem (token validation, key rotation, per-IdP quirks,
recovery paths when the IdP is down). What Hermes Vault does have today:
OAuth **client** flows for provider credentials (`hermes-vault oauth login`
— that's the opposite direction: we hold tokens, we aren't an IdP), and
operator-controlled unlock material (passphrase via env/launcher) that a
provisioning system can rotate.

The v0.26.0 scope decision (2026-09-10) was docs-first: answer the question,
build only if it recurs with real demand. If you need SSO-bound agent
credentials today, the pattern that works is an IdP in front of your
provisioning, distributing short-lived provider tokens into the vault via
`hermes-vault add`/`rotate` — the vault stays the enforcement point for
per-agent access.

---

*Hermes Vault claims: verified against this repository at v0.26.0 (file
paths inline). Bitwarden claims: verified against Bitwarden's public help
center on 2026-09-11 — [export formats](https://bitwarden.com/help/export-your-data/),
[security white paper](https://bitwarden.com/help/bitwarden-security-white-paper/).
Found something stale or wrong? Open an issue with what changed — this page
is meant to be falsifiable.*
