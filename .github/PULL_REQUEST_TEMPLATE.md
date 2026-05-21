## Summary

What changed and why?

## Changed areas

Check all that apply.

- [ ] CLI
- [ ] Vault storage / crypto / backup
- [ ] Policy / broker / mutations
- [ ] Scanner / detectors
- [ ] Verifier
- [ ] MCP server
- [ ] OAuth
- [ ] Dashboard
- [ ] Docs only
- [ ] Tests only
- [ ] Packaging / release workflow

## Tests run

Paste exact commands and summarize results.

```text
python -m pytest tests/ -q
```

## Docs

- [ ] README/docs updated
- [ ] Changelog updated when user-facing behavior changed
- [ ] Not needed, because:

## Security and secret handling

- [ ] No real tokens, passphrases, vault databases, provider responses, or unredacted `.env` contents are included
- [ ] Audit output and logs do not include raw secrets
- [ ] Browser/dashboard responses do not expose raw secrets, raw OAuth tokens, or encrypted payloads
- [ ] Policy, broker, and mutation paths were not bypassed
- [ ] Security-sensitive changes are called out below

Security notes:

## Compatibility

Does this change CLI flags, config env vars, policy YAML, backup format, generated skills, MCP schemas, or dashboard API responses?

## Dashboard/UI evidence

If dashboard UI changed, attach screenshots captured with fake/demo credentials only.

## Reviewer notes

Anything maintainers should review closely?
