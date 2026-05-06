# Survey: OAuth 2.0 PKCE Patterns in CLI Tools

> For Hermes Vault MCP server and CLI auth flows. Research collected 2026-05-05.

---

## 1. Why PKCE for CLI?

Traditional OAuth 2.0 authorization code flow assumes a confidential client -- a server that can keep a `client_secret` safe. CLI tools run on user machines, making them public clients. A `client_secret` baked into a distributed binary is extractable and worthless.

PKCE (RFC 7636, pronounced "pixy") solves this by replacing the static `client_secret` with a per-flow cryptographic verifier. It was originally designed for mobile apps but is now the recommended flow for all public clients, including CLI tools. The OAuth 2.1 draft makes PKCE mandatory for public clients.

**Key benefit:** Even if an attacker intercepts the authorization code, they cannot exchange it for tokens without the verifier.

---

## 2. PKCE S256 Flow (Step-by-Step)

### 2.1. Initiation (CLI generates secrets)

```python
import secrets, hashlib, base64

code_verifier = base64.urlsafe_b64encode(
    secrets.token_bytes(32)
).rstrip(b'=').decode('ascii')  # 43 chars

code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode('ascii')
```

- `code_verifier`: 43-char URL-safe base64, high entropy
- `code_challenge`: SHA256 hash of verifier, URL-safe base64
- Method: `S256` (plain is deprecated and should never be used)

### 2.2. Authorization Request (browser redirect)

```
https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code&
  client_id=MY_CLIENT_ID&
  redirect_uri=http://localhost:8085/callback&
  scope=openid%20email%20profile&
  state=RANDOM_STATE&
  code_challenge=CHALLENGE_HASH&
  code_challenge_method=S256
```

**`state` parameter:** Critical for CSRF protection. Must be:
- Cryptographically random (≥128 bits)
- Stored server-side (or in the callback handler)
- Validated exactly on callback receipt
- Rejected immediately if missing or mismatched

### 2.3. Localhost Callback (browser → CLI)

The browser redirects to `http://localhost:PORT/callback?code=AUTH_CODE&state=RETURNED_STATE`. A temporary HTTP server running on the CLI captures this.

### 2.4. Token Exchange

```python
import httpx

response = httpx.post(
    "https://oauth2.googleapis.com/token",
    data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": auth_code,
        "redirect_uri": redirect_uri,      # must match exactly
        "code_verifier": code_verifier,      # the secret from step 1
    }
)
tokens = response.json()
# access_token, refresh_token, expires_in, id_token (OIDC)
```

**Why no `client_secret`?** Because this is a public client. The `code_verifier` proves the same party initiated the flow and is now completing it.

### 2.5. Refresh Flow

```python
response = httpx.post(
    "https://oauth2.googleapis.com/token",
    data={
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": stored_refresh_token,
    }
)
```

Note: Refresh token is typically long-lived. Some providers rotate refresh tokens on each use (Google does this for some client types). Store the new refresh token if returned.

---

## 3. Localhost Callback Server Design

### 3.1. Port Selection Strategy

| Strategy | Pros | Cons |
|----------|------|------|
| Fixed port (e.g., 8085) | Simple, predictable | Fails if port in use |
| Random ephemeral port | Never conflicts | Must register `http://localhost:PORT` with OAuth provider for every possible port |
| Fallback range (try 8085, 8086, ...) | Balanced | Slightly more code, still needs provider registration |

**Reality check:** Most OAuth providers require pre-registration of `redirect_uri` values. You cannot use truly random ports unless you register `http://localhost:*` (rarely supported) or a large range. Common practice: pick one port, handle "address in use" with a clear error message, or try a small fallback range.

**GitHub's approach:** `http://localhost:PORT/callback` where PORT is either user-specified or from a default. If the port is taken, they error out and ask the user to specify another.

### 3.2. Server Lifecycle

```python
import asyncio
from aiohttp import web

auth_code = None
server_error = None

async def callback_handler(request):
    global auth_code, server_error
    returned_state = request.query.get("state")
    if returned_state != expected_state:
        server_error = "CSRF: state mismatch"
        return web.Response(text="Error: state mismatch. You may close this tab.")
    auth_code = request.query.get("code")
    if auth_code:
        return web.Response(text="Success! You may close this tab.")
    # Handle error from OAuth provider
    server_error = request.query.get("error", "unknown")
    return web.Response(text=f"Error: {server_error}. You may close this tab.")

async def start_callback_server(port=8085):
    app = web.Application()
    app.router.add_get("/callback", callback_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", port)
    await site.start()
    return runner
```

**Critical details:**
- Bind to `localhost` (127.0.0.1 or ::1), NOT `0.0.0.0`. Binding to all interfaces exposes the callback to other machines on the network.
- Set a timeout (e.g., 120 seconds). If no callback arrives, shut down the server and tell the user the flow timed out.
- Serve a simple HTML success page so the user knows they can close the browser.
- Handle `error` query params from the OAuth provider (access_denied, invalid_scope, etc.).

### 3.3. Server Shutdown Patterns

```python
# Pattern 1: asyncio timeout
await asyncio.wait_for(wait_for_callback(), timeout=120)

# Pattern 2: threading + queue
import queue, threading
callback_queue = queue.Queue()

def run_server():
    server = http.server.HTTPServer(("localhost", port), CallbackHandler)
    server.timeout = 120
    server.handle_request()  # blocks until one request
    callback_queue.put(handler_instance.captured_code)

threading.Thread(target=run_server, daemon=True).start()
code = callback_queue.get(timeout=120)
```

**aiohttp vs stdlib `http.server`:**
- `aiohttp`: More ergonomic for async CLI tools, better HTML response handling
- `http.server`: Zero dependency, perfectly adequate for a single-request callback

For Hermes Vault (Python CLI), `http.server` is fine since we don't need async for the rest of the flow. But if the CLI grows async patterns, `aiohttp` or `tornado` align better.

---

## 4. Python Library Landscape

### 4.1. `authlib` (recommended)

```python
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc7636 import create_s256_code_challenge

client = OAuth2Client(client_id="my-client")

# PKCE built-in
uri, state = client.create_authorization_url(
    "https://accounts.google.com/o/oauth2/v2/auth",
    redirect_uri="http://localhost:8085/callback",
    scope="openid email",
    code_challenge_method="S256",
)

# After callback capture:
tokens = client.fetch_token(
    "https://oauth2.googleapis.com/token",
    authorization_response=callback_url,
    code_verifier=client.code_verifier,  # auto-generated during create_authorization_url
)
```

**Pros:** Full OAuth 2.0 / OIDC / JWT spec coverage, actively maintained, handles PKCE automatically, refresh token rotation built-in.
**Cons:** Heavy-ish dependency, but pulls in only what it needs.

### 4.2. `requests-oauthlib` (legacy, PKCE added late)

```python
from requests_oauthlib import OAuth2Session

client = OAuth2Session(client_id, redirect_uri="http://localhost:8085/callback")
client.code_verifier = code_verifier  # must set manually

# PKCE support exists but is less ergonomic than authlib
```

**Verdict:** Works, but `authlib` is the modern, cleaner choice. `requests-oauthlib` is in maintenance mode.

### 4.3. Raw `httpx` / `requests`

Totally viable. As shown in section 2, the PKCE flow is ~50 lines of code. For a tool like Hermes Vault that already shells out and has minimal dependencies, raw `httpx` keeps the dependency tree small.

**Tradeoff matrix:**

| Approach | Lines of code | Dependencies | Maintenance burden | Recommendation |
|----------|---------------|--------------|-------------------|----------------|
| `authlib` | ~20 | `authlib`, `cryptography` | Low (library handles spec churn) | **For multi-provider support** |
| Raw `httpx` | ~80 | `httpx` only | Medium (handle provider quirks yourself) | **For 1-2 providers, lean tool** |
| `requests-oauthlib` | ~40 | `requests`, `oauthlib` | Medium | Skip -- use authlib instead |

**For Hermes Vault:** We currently have Google refresh tokens and may add more providers. Starting with raw `httpx` for the MCP server keeps dependencies minimal. If we expand to 3+ OAuth providers, migrating to `authlib` pays off.

---

## 5. UX Patterns from Real CLI Tools

### 5.1. `gh auth login` (GitHub CLI)

```
$ gh auth login
? What account do you want to log into? GitHub.com
? What is your preferred protocol for Git operations on this host? HTTPS
? How would you like to authenticate GitHub CLI? Login with a web browser

! First copy your one-time code: ABCD-1234
Press Enter to open https://github.com/login/device in your browser...
```

**Wait -- that's DEVICE flow, not PKCE.** GitHub CLI supports both:
- Web browser flow: opens browser to `https://github.com/login/oauth/authorize` with PKCE, callback to `localhost`
- Device flow: for headless / no-browser scenarios

**Key UX element:** If the browser doesn't open, provide the URL for manual copy-paste. Always have a fallback.

### 5.2. `gcloud auth login`

Uses OAuth 2.0 with localhost callback (PKCE under the hood). Pattern:

```
$ gcloud auth login
Your browser has been opened to visit:

    https://accounts.google.com/o/oauth2/auth?...

Waiting for authorization...
```

**Key UX element:** Auto-opens the browser (`webbrowser` module in Python). If that fails, prints the URL. The localhost server blocks until the callback arrives or times out.

### 5.3. `aws sso login`

AWS SSO uses OIDC with device flow (similar to GitHub's device code flow):

```
$ aws sso login
Attempting to automatically open the SSO authorization page in your default browser.
If the browser does not open or you wish to use a different device to authorize this request,
open the following URL:

https://device.sso.us-east-1.amazonaws.com/

Then enter the code:

ABCD-WXYZ
```

**Why device flow for AWS?** Because AWS SSO runs across multiple accounts/roles and the device flow lets you authenticate once, then the CLI polls for tokens. It's not PKCE but serves the same "CLI on a user machine" use case.

### 5.4. `google-cloud-sdk` (gcloud)

When running headless (no browser available):

```
Go to the following link in your browser:

    https://accounts.google.com/o/oauth2/auth?...

Enter verification code: [waits for user to paste code from browser]
```

This is the older "copy the code" pattern, not PKCE. Modern `gcloud` uses localhost callback when a browser is available.

---

## 6. Synthesized UX Recommendations

### 6.1. Happy Path (browser available)

```
$ hermes-vault auth login google
Opening browser for Google authorization...
If your browser doesn't open automatically, visit:
  https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=http://localhost:8085/callback&...

Waiting for callback on localhost:8085...
Authorization successful. Credentials stored in vault.
```

### 6.2. Headless / No Browser Fallback

If `$DISPLAY` is unset and no browser can be opened, fall back to:

```
$ hermes-vault auth login google
No browser detected. Please visit this URL and authorize:
  https://accounts.google.com/o/oauth2/v2/auth?...

Then paste the authorization code here: [waits for input]
```

This requires the OAuth provider to support out-of-band (OOB) redirect URIs. Google deprecated OOB in 2022 for security reasons, so for Google specifically, device flow is the better fallback.

### 6.3. Device Flow as Headless Fallback

```
$ hermes-vault auth login google --device
Go to https://www.google.com/device and enter code: ABCD-EFGH
Waiting for authorization...
Authorization successful. Credentials stored in vault.
```

**Note:** Device flow requires the OAuth provider to support it. Google supports it. GitHub supports it. Not all providers do.

---

## 7. Security Considerations

### 7.1. Localhost Binding

- **Bind to 127.0.0.1 only.** Never 0.0.0.0.
- **Validate the `state` parameter rigorously.** Reject with an error page if it doesn't match.
- **Use a one-time state.** Generate fresh state per auth attempt. Don't reuse or derive from predictable data.
- **Short-lived server.** 120 seconds max. Kill it after first request regardless of success/failure.

### 7.2. Code Verifier Storage

The `code_verifier` must be stored in memory only during the flow. Never:
- Write it to disk
- Log it
- Pass it via command-line arguments (visible in `ps`)
- Include it in error messages

### 7.3. Token Storage

Once tokens are obtained:
- Store `access_token` encrypted at rest (Hermes Vault already does this)
- Store `refresh_token` with higher protection -- it is long-lived and equivalent to credentials
- Set an `expires_at` timestamp and refresh proactively, not reactively
- On refresh token rotation, replace the old one immediately

### 7.4. Redirect URI Registration

The OAuth provider must have `http://localhost:PORT/callback` pre-registered. Using a port the provider doesn't know about will cause an `redirect_uri_mismatch` error.

---

## 8. Provider-Specific Quirks

### 8.1. Google

- Authorization endpoint: `https://accounts.google.com/o/oauth2/v2/auth`
- Token endpoint: `https://oauth2.googleapis.com/token`
- Supports PKCE (required for new clients as of 2022)
- Supports device flow
- `redirect_uri` must be pre-registered in Google Cloud Console
- Refresh tokens are rotated on use for some client types
- `access_type=offline` parameter is required to get a refresh token

### 8.2. GitHub

- Authorization endpoint: `https://github.com/login/oauth/authorize`
- Token endpoint: `https://github.com/login/oauth/access_token`
- Supports PKCE (recommended, not strictly required)
- Supports device flow (`gh auth login` uses this for headless)
- `redirect_uri` must be registered in GitHub App / OAuth App settings

### 8.3. Microsoft / Entra ID

- Authorization endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
- Token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
- PKCE is supported and recommended
- `localhost` redirect URIs work but may require explicit admin consent configuration

---

## 9. Token Refresh Architecture

### 9.1. Proactive vs Reactive Refresh

| Pattern | When it triggers | Pros | Cons |
|---------|-----------------|------|------|
| Proactive | Before use, if `expires_at - now < threshold` (e.g., 5 min) | Never serves stale tokens | Extra overhead on every credential request |
| Reactive | On 401/403 from API, then refresh and retry | Minimal overhead | First request fails, adds latency |
| Background | Cron job refreshes all near-expiry tokens | Clean separation | Needs scheduling infra |

**Recommendation for Hermes Vault:** Proactive refresh in the broker. When `broker env <service>` is called, check `expires_at`. If within 5 minutes of expiry (or already expired), refresh first, then return the new token.

### 9.2. Refresh Token Loss Recovery

If a refresh token is lost, expired, or revoked, the only recovery is full re-authentication via the PKCE flow again. The CLI should detect this (`invalid_grant` error on refresh) and prompt the user:

```
Google refresh token is invalid or expired. Please re-authenticate:
$ hermes-vault auth login google
```

---

## 10. Hermes Vault Integration Recommendations

### 10.1. New CLI Command

```
hermes-vault auth login <service>
hermes-vault auth login google
hermes-vault auth login github
hermes-vault auth logout <service>
```

### 10.2. Credential Type

Store OAuth credentials as a structured type:

```yaml
service: google
credential_type: oauth_token_set
alias: primary
data:
  access_token: "ya29..."
  refresh_token: "1//..."
  expires_at: 1778028600
  token_type: "Bearer"
  scope: "openid email profile"
```

### 10.3. MCP Server Extension

Add a new MCP tool: `initiate_oauth_flow`

```json
{
  "name": "initiate_oauth_flow",
  "arguments": {
    "agent_id": "hermes",
    "service": "google",
    "port": 8085
  }
}
```

Returns: `{"authorization_url": "...", "callback_port": 8085, "state": "..."}`

Then a second tool: `complete_oauth_flow`

```json
{
  "name": "complete_oauth_flow",
  "arguments": {
    "agent_id": "hermes",
    "service": "google",
    "callback_url": "http://localhost:8085/callback?code=...&state=..."
  }
}
```

Or, more practically, have the CLI own the full flow and just call `add` after completion. MCP is stateless; a two-phase flow over MCP is awkward. Better: CLI runs the PKCE flow locally, captures tokens, then stores them via `hermes-vault add`.

### 10.4. Implementation Order

1. **Phase 1:** Raw `httpx` implementation for Google only. Add `hermes-vault auth login google` command.
2. **Phase 2:** Abstract provider config (endpoints, scopes, client IDs) into YAML.
3. **Phase 3:** Add GitHub, Microsoft, etc. Migrate to `authlib` if provider count > 2.
4. **Phase 4:** Proactive refresh in broker. `broker env google` auto-refreshes if near expiry.
5. **Phase 5:** Device flow fallback for headless environments.

---

## 11. References

- RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
- RFC 6749: The OAuth 2.0 Authorization Framework
- RFC 8252: OAuth 2.0 for Native Apps (recommends PKCE + localhost)
- Google Identity: Using OAuth 2.0 for Installed Applications
- GitHub Docs: Authorizing OAuth Apps
- Authlib documentation: https://docs.authlib.org/

---

*End of survey. Produced for Hermes Vault MCP server auth flow design.*
