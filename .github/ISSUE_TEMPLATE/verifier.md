---
name: Verifier request
about: Request credential verification support for a service/provider
title: "verifier: "
labels: "enhancement, area: vault-core"
assignees: ""
---

## Service/provider

Name the service and link to its public API/auth documentation.

## Credential type

What kind of credential should Hermes Vault verify?

- API key
- OAuth access token
- OAuth refresh token
- Personal access token
- Other:

## Safe verification endpoint

Which endpoint can confirm validity with the least privilege and lowest side effects?

- Endpoint URL:
- HTTP method:
- Required scopes/permissions:
- Expected success response:
- Expected expired/invalid response:
- Rate limit notes:

## Environment variable mapping

What env vars should `broker env` materialize for this service?

```text
SERVICE_API_KEY=
SERVICE_TOKEN=
```

## Failure classification

How should Hermes Vault distinguish invalid credentials from network failures, missing scopes, endpoint misconfiguration, and rate limits?

## Test fixtures

Describe fake responses or mocked HTTP interactions that can test the verifier without real credentials.

Do not paste real credentials, bearer tokens, refresh tokens, provider token responses, or account-specific data.
