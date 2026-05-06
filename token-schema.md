# OAuth Token Storage Schema Design

> Hermes Vault v0.6.0 — OAuth + Auto-Refresh sprint.
> Target artifact: `token-schema.md` in workspace.

---

## 1. New Credential Types

Two new values for `CredentialRecord.credential_type` and the `credentials` table:

| Value | Purpose |
|---|---|
| `oauth_access_token` | Short-lived bearer token for API calls. |
| `oauth_refresh_token` | Long-lived token used to obtain new access tokens. |

These are string values stored in the existing `credential_type TEXT NOT NULL` column. No database schema change is required.

---

## 2. Access Token Schema

Stored as a `CredentialSecret` in the encrypted payload. The token string itself goes into `secret`; everything else lives in `metadata`.

```json
{
  "secret": "ya29.a0AfH6SMBx...",
  "metadata": {
    "token_type": "Bearer",
    "expires_at": "2026-05-05T20:15:30+00:00",
    "scopes": ["openid", "email", "profile"],
    "issued_at": "2026-05-05T19:15:30+00:00",
    "id_token": "eyJhbGciOiJSUzI1NiIs...",
    "provider": "google"
  }
}
```

### Field semantics

| Key | Type | Required | Description |
|---|---|---|---|
| `secret` | string | Yes | The raw access token value. |
| `token_type` | string | Yes | Usually `"Bearer"`. Dictates the `Authorization` header prefix. |
| `expires_at` | ISO-8601 datetime | Yes | Absolute UTC expiry. Used by the broker to decide proactive refresh. |
| `scopes` | list[string] | No | Granted scopes. Vault record-level `scopes` is also populated for indexing/querying. |
| `issued_at` | ISO-8601 datetime | No | When the token was minted. Useful for telemetry and debugging drift. |
| `id_token` | string | No | OIDC ID token (JWT) if returned by the provider. |
| `provider` | string | No | Normalized service name (e.g., `"google"`, `"github"`). Redundant with `service` but handy inside the payload. |

### Record-level mapping

```python
record = CredentialRecord(
    service="google",
    alias="default",
    credential_type="oauth_access_token",
    scopes=["openid", "email", "profile"],
    expiry=datetime.fromisoformat("2026-05-05T20:15:30+00:00"),
    status=CredentialStatus.active,
)
```

The `expiry` column at the record level mirrors `metadata.expires_at` for fast filtering without decryption. The broker checks `record.expiry` first, decrypts only when refresh is needed.

---

## 3. Refresh Token Schema

```json
{
  "secret": "1//04dK...",
  "metadata": {
    "associated_access_token_service": "google",
    "associated_access_token_alias": "default",
    "rotation_counter": 3,
    "provider": "google",
    "family_id": "google-default"
  }
}
```

### Field semantics

| Key | Type | Required | Description |
|---|---|---|---|
| `secret` | string | Yes | The raw refresh token value. |
| `associated_access_token_service` | string | Yes | Service name of the paired access token. Enables lookup without querying by credential type. |
| `associated_access_token_alias` | string | Yes | Alias of the paired access token. Default `"default"`. |
| `rotation_counter` | integer | No | Incremented every time the refresh token is rotated. For audit/debugging. |
| `provider` | string | No | Normalized provider name. |
| `family_id` | string | No | Stable identifier for the token family. If the provider rotates refresh tokens, `family_id` stays constant while `secret` changes. Enables tracing lineage across rotations. |

### Record-level mapping

```python
record = CredentialRecord(
    service="google",
    alias="refresh",
    credential_type="oauth_refresh_token",
    scopes=["openid", "email", "profile"],  # inherited from access token
    status=CredentialStatus.active,
    # expiry is None -- refresh tokens typically don't have an explicit expiry
)
```

**Alias convention:** Access token uses `"default"` (or user-supplied alias). Refresh token uses `"refresh"` by convention, scoped to the same `service`. This makes the pair deterministic: `service="google", alias="default"` for access, `service="google", alias="refresh"` for refresh.

---

## 4. Relationship Between Access and Refresh Tokens

### 4.1. Storage relationship

Both tokens share the same `service` name (e.g., `"google"`). They are differentiated by `alias` and `credential_type`.

```
service="google", alias="default",  credential_type="oauth_access_token"
service="google", alias="refresh",  credential_type="oauth_refresh_token"
```

This leverages the existing `(service, alias)` unique-ish lookup (vault returns the most-recently-updated match) without adding new tables or foreign keys.

### 4.2. Logical relationship

The refresh token's `metadata` stores the paired access token's `service` and `alias` for explicit cross-reference. This is defensive: if a user renames an alias or duplicates a service, the metadata still points to the intended partner.

### 4.3. Lifecycle coupling

| Event | Access token action | Refresh token action |
|---|---|---|
| Initial login | Created with `expiry` set. | Created alongside it. |
| Proactive refresh | Replaced in-place (`rotate` or `replace_existing=True`). `expiry` and `secret` updated. | May be replaced if provider returns a new one (`rotation_counter++`). |
| Access revoked by user | `status=invalid`. | `status=invalid` (cascade). |
| Refresh fails permanently | `status=expired`. | `status=invalid`. User must re-auth. |
| Manual delete of access | Deleted. | Deleted automatically (cascade). |
| Manual delete of refresh | Blocked -- must delete access token first, or cascade. | Deleted. Access token left in `expired` state. |

### 4.4. Lookup helpers (future implementation)

```python
def get_refresh_token_for_access(vault: Vault, service: str, alias: str = "default") -> CredentialRecord | None:
    """Find the refresh token paired with a given access token."""
    return vault._find_by_service_alias(service, "refresh")

def get_access_token_for_service(vault: Vault, service: str, alias: str = "default") -> CredentialRecord | None:
    """Find the access token for a service+alias."""
    # vault.get_credential is type-agnostic; callers filter by credential_type
    rec = vault.resolve_credential(service, alias=alias)
    if rec and rec.credential_type == "oauth_access_token":
        return rec
    return None
```

---

## 5. Migration Path

### 5.1. Database layer

No migration required. The `credentials` table already has:

- `credential_type TEXT NOT NULL` — free-form string, new values are backward compatible.
- `expiry TEXT` — nullable ISO-8601 string, already used for existing credentials.
- `scopes TEXT NOT NULL` — JSON list, already populated for existing credentials.

### 5.2. Code layer

No breaking changes to `CredentialRecord` or `CredentialSecret` models. The new types are additive.

### 5.3. Existing credentials

Existing credentials with `credential_type="api_key"` (or any other type) are unaffected. The broker will skip OAuth-specific logic for non-OAuth types.

### 5.4. Policy layer

No policy changes needed. The existing `ServiceAction.get_credential`, `rotate`, `delete`, etc., apply uniformly. If future work adds OAuth-specific actions (e.g., `refresh_token`), they are added to `ServiceAction` as new enum values.

### 5.5. Audit layer

Existing audit logging covers all mutations. No schema changes needed. Future work may log `refresh_token` as a distinct action string for clarity.

---

## 6. Security Considerations

### 6.1. Refresh token rotation

Google and some other providers issue a new refresh token on every refresh exchange. The vault must:

1. Detect a new `refresh_token` in the token exchange response.
2. Replace the old refresh token's `secret` in-place (using `Vault.rotate`).
3. Increment `metadata.rotation_counter`.
4. Update `updated_at` to reflect the rotation.
5. Log the rotation event (audit).

If the provider does NOT rotate (e.g., GitHub), `rotation_counter` stays flat and `secret` is unchanged.

### 6.2. Binding to service

Both tokens are bound to a normalized `service` name. The broker must reject requests where the access token's `metadata.provider` does not match the `service` field (defense against import/export tampering or vault corruption).

### 6.3. Encryption at rest

Both token values are encrypted inside `CredentialSecret.secret` using the existing AES-GCM scheme. The `metadata` dict is also inside the encrypted payload. At no point does a raw token sit in the SQLite database unencrypted.

### 6.4. Expiry handling

- `expiry` on the record level is used for fast filtering (no decryption required).
- The broker treats `expiry` as a hint. Before returning an access token as an env var, the broker checks `expires_at` against `utc_now()`. If within a configurable proactive-refresh window (default 5 minutes), the broker attempts refresh first.
- If refresh fails and the token is not yet expired, the broker returns it with a warning in metadata.
- If refresh fails and the token IS expired, the broker returns a `deny` decision with `reason="token_expired"`.

### 6.5. Scope narrowing

If a refresh returns a token with fewer scopes than originally granted, the vault updates both the record-level `scopes` and the payload `metadata.scopes`. This prevents an agent from assuming scopes that were revoked server-side.

### 6.6. CSRF / state persistence

This schema design does NOT cover the PKCE `state` and `code_verifier` used during the initial OAuth flow. Those are ephemeral in-memory values during login and are never stored in the vault. The survey document covers their handling in the callback server.

### 6.7. Token family tracking

The `family_id` field in refresh token metadata enables tracing a token's lineage even after multiple rotations. Proposed generation:

```python
family_id = f"{service}-{alias}-{uuid4().hex[:8]}"
```

This is stable for the lifetime of the user's grant. If the user revokes and re-auths, a new `family_id` is minted.

### 6.8. Alias squatting prevention

If a user (or malicious agent) tries to add a credential with `alias="refresh"` and `credential_type="api_key"`, the vault allows it today because alias is not type-scoped. **Recommendation:** The OAuth broker layer should treat `alias="refresh"` as reserved when `credential_type != "oauth_refresh_token"` and reject such additions for OAuth-managed services.

---

## 7. Summary of Changes Required

| Layer | Change | Breaking? |
|---|---|---|
| Database schema | None. New `credential_type` values fit existing `TEXT` column. | No |
| `CredentialRecord` model | None. Existing fields cover all needs. | No |
| `CredentialSecret` model | None. `metadata` dict is extensible. | No |
| Vault class | None. `add_credential`, `rotate`, `resolve_credential` already handle arbitrary types. | No |
| Mutations class | None. Existing actions apply. | No |
| Broker (future work) | Add proactive refresh logic, token-type dispatch, expiry checks. | No |
| Policy (future work) | May add `ServiceAction.refresh_token`. | No |
| Audit (future work) | May log `refresh_token` as distinct action. | No |

---

## 8. Open Questions

1. **Should we enforce the `alias="refresh"` convention at the vault level, or leave it to the OAuth broker layer?**
   - Proposal: Enforce at broker layer only. The vault remains type-agnostic.

2. **Should the refresh token store `scopes` at the record level, or only in access token metadata?**
   - Proposal: Store at record level for both. Queries like "list all credentials with `profile` scope" should include refresh tokens.

3. **Should we add a `token_family` table for formal relational tracking, or keep it denormalized in metadata?**
   - Proposal: Keep denormalized for now. A separate table is justified only if we support multiple concurrent access tokens per service (rare for CLI use cases).

4. **How does the broker behave when `expires_at` is missing or malformed?**
   - Proposal: Treat as "unknown expiry" -- skip proactive refresh, return the token with a warning. Do not fail the request.

5. **Should expired access tokens be auto-deleted or kept for debugging?**
   - Proposal: Keep them with `status=expired`. A future cleanup cron can purge old expired tokens. The broker never returns `expired` tokens.
