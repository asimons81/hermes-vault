# `hermes-vault run` — child-process env injection (P8)

`hermes-vault run` runs a child process with vault-backed environment
variables injected **only into that child's environment, for its lifetime** —
the exact contract CrewAI / LangChain / MCP `env:` blocks speak.

```bash
hermes-vault run --agent hermes -- python agent.py
hermes-vault run --agent hermes --service openai -- python agent.py
hermes-vault run --agent hermes --service openai --alias primary -- python agent.py
hermes-vault run --agent deploy-bot --service github --service openrouter -- npx some-tool
```

## Semantics

- **Child-process env only.** Secrets are never placed in argv, never
  printed, never logged, and never written to the audit record (audit rows
  carry variable *names*, not values). When the child exits, the values are
  gone with its environment.
- **Same broker path as `broker env`.** Each service resolves through
  `Broker.get_ephemeral_env()` verbatim: policy check, TTL clamp,
  `require_lease_for_env` lease ownership + expiry (v0.26.0 authorization
  enforcement), OAuth freshness, and expiry-at-handoff all apply unchanged.
- **Deny-by-default.** A service outside the agent's policy is denied — the
  child never spawns. **Operator authority bypass is a non-goal**: an
  operator invoking `run` is bound by the same policy as any agent id they
  pass.
- **All-or-nothing.** With multiple `--service` flags, the first denial
  aborts before any env is materialized, and a target-variable collision
  between two services (same variable, different values) fails closed
  instead of silently overwriting.
- **Auto mode.** With no `--service`, `run` injects every service the agent
  may `get_env` on **that has a stored credential** — policy is still the
  boundary; vault services the policy cannot see never resolve.

## Options

| Option | Meaning |
|---|---|
| `--agent ID` | Agent identity the env is resolved for. Defaults to `HERMES_VAULT_MCP_DEFAULT_AGENT` when omitted (the same default-binding mechanism MCP uses). |
| `--service S` (repeatable) | Service to inject. Omit for auto mode. |
| `--alias A` | Credential alias; requires exactly one `--service`. |
| `--ttl N` | Requested TTL in seconds for policy evaluation; clamped to the agent's `max_ttl_seconds`. |
| `--verbose` | Print which variables (names only) were injected to stderr. |

## Exit codes

- `0`–`255`: the child's own exit code (shell conventions preserved:
  killed-by-signal-N reports `128+N`, not-found `127`, not-executable `126`).
- `1`: broker denial (policy denial, lease requirement unmet, expired
  credential, no authorized services with credentials) — the child never
  spawned.
- `2`: usage error (no command after `--`, `--alias` without exactly one
  `--service`, `--ttl <= 0`, or no agent id resolvable from `--agent` /
  `HERMES_VAULT_MCP_DEFAULT_AGENT`).

## Hygiene guarantees

- **Key material never reaches the child.** `HERMES_VAULT_PASSPHRASE` and
  the per-profile `HERMES_VAULT_PASSPHRASE_<PROFILE>` variables are stripped
  from the child environment even when the operator's shell exports them —
  injecting policy-scoped credentials while leaking the master-key
  passphrase would grant strictly more access than intended.
- **Audit trail.** Every run writes a `run_env_inject` audit row (service
  and variable names, command name, TTL; denials carry the broker reason).
  Each injected service additionally writes its own `get_ephemeral_env`
  allow row through the broker — the existing audit surfaces show the same
  picture as a manual `broker env` flow.

## Using it from agent frameworks

CrewAI / LangChain / MCP `env:` blocks expect a plain environment; `run` is
the bridge from the vault to those blocks:

```bash
# A LangChain/CrewAI tool subprocess with vault-injected env:
hermes-vault run --agent hermes --service openai -- \
  python -m my_agent.entrypoint

# An MCP stdio server that needs a vault-backed token:
hermes-vault run --agent mcp-worker --service github -- \
  npx -y @some/mcp-server
```

No `.env` files, no exported shell vars, no secret in the process table's
argv — the child's env dies with the child.
