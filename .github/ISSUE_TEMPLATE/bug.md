---
name: Bug report
about: Report a reproducible Hermes Vault problem
title: "bug: "
labels: "bug, needs: repro"
assignees: ""
---

## Summary

What broke?

## Expected behavior

What did you expect Hermes Vault to do?

## Actual behavior

What happened instead?

## Reproduction steps

1.
2.
3.

## Environment

- Hermes Vault version:
- Install method: uv tool / pipx / editable install / pip / source checkout / other
- Python version:
- OS/runtime: Linux / macOS / WSL / Windows / other
- Shell:

## Command and output

Paste the exact command and redacted output.

```text
# command
# output
```

## Vault/runtime context

Do not upload vault databases, passphrases, raw tokens, provider token responses, or unredacted `.env` files.

- `HERMES_VAULT_HOME` location shape, not contents:
- Custom `HERMES_VAULT_POLICY`? yes/no
- Dashboard involved? yes/no
- MCP involved? yes/no
- OAuth involved? yes/no

## Additional context

Screenshots are welcome for dashboard UI bugs, but redact credential metadata if needed and never show secret material.
