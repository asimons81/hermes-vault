# Hermes Vault -- OAuth PKCE Login Flow Architecture

> Version: 0.1.0-draft  
> Scope: CLI-only PKCE login for operator-initiated OAuth flows. No headless/agent-autonomous OAuth yet.  
> Target integration: hermes-vault v0.6.0+

---

## 1. Overview

Hermes Vault currently stores `oauth_access_token` credentials via manual `add` or `import`. This architecture adds an operator-facing `hermes-vault oauth login` command that performs a full RFC-7636 PKCE flow, exchanges the authorization code for tokens, and stores the resulting access token (plus refresh token and metadata) in the vault as an audited credential mutation.

Design constraints inherited from the existing vault:
- All writes go through `VaultMutations` (policy check + audit log).
- Raw secrets are encrypted at rest via `crypto.py` (AES-GCM).
- CLI uses a Click/Typer hybrid (`HermesGroup`).
- Runtime state lives under `~/.hermes/hermes-vault-data`.
- No raw secrets in logs or console output.

---

## 2. Command Design

### 2.1 New subcommand group

```
hermes-vault oauth login <provider> [--alias <name>] [--port <n>] [--timeout <seconds>] [--no-browser]
```

Registration in `cli.py`:
```python
oauth_app = typer.Typer(help="OAuth operations.")
_typer_app.add_typer(oauth_app, name="oauth")
```

### 2.2 Arguments and options

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | `str` | required | Canonical service ID (e.g. `google`, `github`, `openai`). Must exist in the provider registry. |
| `--alias` | `str` | `"default"` | Vault alias for the stored credential. |
| `--port` | `int` | `0` | Callback server port. `0` means OS-assigned ephemeral port. |
| `--timeout` | `int` | `120` | Seconds to wait for the OAuth callback before aborting. |
| `--no-browser` | `bool` | `False` | Skip auto-opening the browser; print the authorization URL instead. |
| `--scopes` | `list[str]` | provider default | Override requested OAuth scopes. |

### 2.3 Future commands (out of scope for T2/T3, noted for registry design)

- `hermes-vault oauth refresh <provider> [--alias <name>]` -- use `refresh_token` to obtain a new `access_token`.
- `hermes-vault oauth logout <provider> [--alias <name>]` -- delete the OAuth credential from the vault.

---

## 3. Provider Registry

A lightweight YAML registry maps canonical service IDs to their OAuth endpoints and defaults. Stored at `~/.hermes/hermes-vault-data/oauth-providers.yaml`, seeded from a baked-in defaults file on first use.

### 3.1 Schema

```yaml
providers:
  google:
    name: "Google"
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: "https://oauth2.googleapis.com/token"
    default_scopes:
      - "openid"
      - "email"
    scope_separator: " "          # space or comma
    use_pkce: true                # false for providers that don't support PKCE (rare)
    extra_params:                 # static query params for the auth URL
      access_type: "offline"
      prompt: "consent"

  github:
    name: "GitHub"
    authorization_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    default_scopes:
      - "repo"
      - "read:org"
    scope_separator: " "
    use_pkce: true
    extra_params: {}
```

### 3.2 Runtime loading

```python
class OAuthProviderRegistry:
    def __init__(self, path: Path, defaults_path: Path | None = None) -> None:
        ...
    def get(self, service: str) -> OAuthProvider | None:
        ...
```

- If the user config file is missing, copy the built-in defaults and write it.
- Allows users to add custom providers without code changes.

### 3.3 `OAuthProvider` model

```python
class OAuthProvider(BaseModel):
    name: str
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    default_scopes: list[str]
    scope_separator: str = " "
    use_pkce: bool = True
    extra_params: dict[str, str] = Field(default_factory=dict)
```

---

## 4. PKCE Flow -- Core Modules

New package: `src/hermes_vault/oauth/`

```
src/hermes_vault/oauth/
  __init__.py
  pkce.py           -- code_verifier / code_challenge (S256)
  state.py          -- state parameter generation and validation
  callback.py       -- ephemeral HTTP server + request handler
  exchange.py       -- token exchange HTTP client
  providers.py      -- OAuthProvider + registry
  flow.py           -- high-level orchestrator (LoginFlow)
```

### 4.1 `pkce.py` -- PKCEGenerator

```python
import secrets
import hashlib
import base64

class PKCEGenerator:
    @staticmethod
    def generate_verifier(length: int = 128) -> str:
        """Generate a code_verifier: random [A-Za-z0-9-._~] string."""
        return base64.urlsafe_b64encode(
            secrets.token_bytes(length)
        ).rstrip(b"=").decode("ascii")

    @staticmethod
    def generate_challenge(verifier: str) -> str:
        """S256 code_challenge from verifier."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
```

- `length=128` matches the RFC 7636 recommended maximum (43-128 chars after encoding).
- No external crypto deps -- stdlib only.

### 4.2 `state.py` -- StateManager

State is an unguessable nonce used for CSRF protection. Because the flow is operator-local and single-process, state can be held in memory (no persistent store needed).

```python
import secrets

class StateManager:
    def __init__(self) -> None:
        self._state: str | None = None

    def generate(self) -> str:
        self._state = secrets.token_urlsafe(32)
        return self._state

    def validate(self, incoming: str) -> bool:
        if self._state is None:
            return False
        return secrets.compare_digest(self._state, incoming)

    def clear(self) -> None:
        self._state = None
```

- `secrets.compare_digest` prevents timing attacks.
- State is cleared immediately after validation (one-time use).

### 4.3 `callback.py` -- CallbackServer

An ephemeral `HTTPServer` bound to `127.0.0.1` only. Handles exactly one GET request on `/callback`, extracts query parameters, then signals the main thread and shuts down.

#### Port selection strategy

1. If `--port` is non-zero, try binding to it.
2. If that fails (already in use), abort with a clear error telling the user to pick another port.
3. If `--port` is `0`, bind to `("127.0.0.1", 0)` and let the OS assign an ephemeral port.
4. Read the actual assigned port via `server.server_address[1]` and construct the `redirect_uri`.

#### Server implementation

```python
import http.server
import socketserver
import threading
from dataclasses import dataclass

@dataclass
class CallbackResult:
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    # Shared mutable state -- set by the server factory before each run
    result: CallbackResult | None = None
    event: threading.Event | None = None

    def do_GET(self):
        # Parse query string
        # Populate CallbackHandler.result
        # Send 200 OK with a simple HTML success / failure page
        # Set CallbackHandler.event to unblock the main thread
        pass

    def log_message(self, format, *args):
        # Suppress default HTTP access logging to avoid leaking state/code
        pass

class CallbackServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, timeout: int = 120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.result: CallbackResult = CallbackResult()
        self._event = threading.Event()
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the server in a background thread. Returns the actual port."""
        CallbackHandler.result = self.result
        CallbackHandler.event = self._event
        self._server = socketserver.TCPServer((self.host, self.port), CallbackHandler)
        actual_port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def wait(self) -> CallbackResult:
        """Block until callback or timeout. Returns the result."""
        if not self._event.wait(timeout=self.timeout):
            self.result.error = "timeout"
            self.result.error_description = f"No callback received within {self.timeout}s"
        self.shutdown()
        return self.result

    def shutdown(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
```

#### HTML response pages

The handler serves a minimal HTML page so the user sees immediate feedback in the browser:

- **Success**: "Authorization complete. You can close this tab and return to the terminal."
- **Error/Denied**: "Authorization failed: {error_description}. Return to the terminal for details."

No JavaScript, no external assets. Plain inline HTML.

---

## 5. Token Exchange

### 5.1 `exchange.py` -- TokenExchanger

```python
import requests

class TokenExchanger:
    def __init__(self, provider: OAuthProvider) -> None:
        self.provider = provider

    def exchange(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> TokenResponse:
        """POST the authorization code to the provider's token endpoint."""
        ...
```

- Uses `requests` (already a project dependency via verifier paths).
- Sends `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, plus optional `client_id` / `client_secret`.
- Returns a `TokenResponse` dataclass.

### 5.2 `TokenResponse` model

```python
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    # Raw JSON preserved for provider-specific extra fields
    raw: dict[str, Any] = Field(default_factory=dict)
```

### 5.3 Client credentials handling

Some providers (e.g., Google) require a `client_id` (and sometimes `client_secret`) even for PKCE public clients. Rather than hardcoding secrets in the registry, the operator can supply them via environment variables:

```
HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_ID
HERMES_VAULT_OAUTH_<PROVIDER>_CLIENT_SECRET   # optional
```

Example: `HERMES_VAULT_OAUTH_GOOGLE_CLIENT_ID`

The CLI reads these at runtime and passes them to `TokenExchanger`. If a provider requires a `client_id` and none is found, the CLI errors early with a clear message.

---

## 6. High-Level Flow Orchestrator (`flow.py`)

The `LoginFlow` class ties everything together so `cli.py` stays thin.

```python
class LoginFlow:
    def __init__(
        self,
        provider: OAuthProvider,
        alias: str = "default",
        port: int = 0,
        timeout: int = 120,
        no_browser: bool = False,
        scopes: list[str] | None = None,
        console: Console | None = None,
    ) -> None:
        ...

    def run(self) -> CredentialRecord:
        """
        1. Generate PKCE params + state.
        2. Start callback server, get actual port.
        3. Build authorization URL.
        4. Open browser (or print URL).
        5. Wait for callback.
        6. Validate state.
        7. Exchange code for tokens.
        8. Store in vault via VaultMutations.add_credential.
        9. Return the CredentialRecord.
        """
        ...
```

### 6.1 Step-by-step sequence

```
Operator runs: hermes-vault oauth login google --alias work

1. Registry lookup: google -> OAuthProvider
2. PKCEGenerator -> verifier, challenge
3. StateManager -> state nonce
4. CallbackServer.start() -> actual_port
5. redirect_uri = f"http://127.0.0.1:{actual_port}/callback"
6. Build auth URL with response_type=code, client_id, scope, state, code_challenge, redirect_uri, plus provider.extra_params
7. if not no_browser:
       webbrowser.open(auth_url)
   else:
       print("Open this URL: {auth_url}")
8. Console spinner: "Waiting for authorization..."
9. callback_result = server.wait()
10. If callback_result.error == "timeout": raise OAuthTimeoutError
11. If callback_result.error == "access_denied": raise OAuthDeniedError
12. If not state_manager.validate(callback_result.state): raise OAuthStateMismatchError
13. token_response = TokenExchanger.exchange(...)
14. Build secret payload:
    - secret = token_response.access_token
    - metadata = {"refresh_token": ..., "token_type": ..., "raw": ...}
15. mutations.add_credential(
    agent_id=OPERATOR_AGENT_ID,
    service=provider.canonical_id,
    secret=secret,
    credential_type="oauth_access_token",
    alias=alias,
    scopes=token_response.scope.split() if token_response.scope else requested_scopes,
   )
   -- VaultMutations automatically sets expiry if the record payload includes an 'expires_at' hint.
   -- For OAuth, we explicitly set record.expiry based on token_response.expires_in.
16. Console success message with credential ID and alias.
```

---

## 7. Error Handling

| Scenario | Detection | User-facing behavior |
|----------|-----------|---------------------|
| **Timeout** | `CallbackServer.wait()` returns after `timeout` with `error="timeout"` | Console: `[red]Timed out after {timeout}s. No authorization callback received.[/red]` Exit code 1. |
| **User denied** | Callback query param `error=access_denied` | Console: `[red]Authorization denied by user or provider.[/red]` Exit code 1. |
| **Invalid state** | `StateManager.validate()` returns `False` | Console: `[red]Security error: state parameter mismatch (possible CSRF). Aborting.[/red]` Exit code 1. |
| **Network failure (token exchange)** | `requests` raises `ConnectionError`, `Timeout`, etc. | Console: `[red]Token exchange failed: {exc}[/red]` Exit code 1. |
| **Port in use (explicit --port)** | `socketserver.TCPServer` raises `OSError` on bind | Console: `[red]Port {port} is already in use. Try --port 0 for auto-assignment or choose a different port.[/red]` Exit code 1. |
| **Missing client_id** | Registry indicates `requires_client_id: true` and env var is absent | Console: `[red]Provider '{provider}' requires a client_id. Set HERMES_VAULT_OAUTH_{provider}_CLIENT_ID.[/red]` Exit code 1. |
| **Unknown provider** | `OAuthProviderRegistry.get()` returns `None` | Console: `[red]Unknown OAuth provider '{provider}'. Run hermes-vault oauth providers to see supported options.[/red]` Exit code 1. |
| **Token endpoint returns error** | HTTP 200 with JSON `error` field, or HTTP 4xx/5xx | Console: `[red]Token endpoint error: {error} -- {error_description}[/red]` Exit code 1. |

All errors abort the flow before any credential is written. No partial state is left in the vault.

---

## 8. CLI UX Details

### 8.1 Spinner / progress

Use `rich.console.Console` + `rich.status.Status`:

```python
with console.status("[bold green]Waiting for browser authorization...", spinner="dots"):
    result = server.wait()
```

Status text updates at key points:
- "Starting local callback server..."
- "Opening browser..."
- "Waiting for authorization..."
- "Exchanging code for tokens..."
- "Storing credential..."

### 8.2 Browser auto-open

```python
import webbrowser

if not no_browser:
    opened = webbrowser.open(auth_url, new=2)  # new tab
    if not opened:
        console.print(f"[yellow]Could not open browser automatically. Open this URL:[/yellow]\n{auth_url}")
else:
    console.print(f"Open this URL in your browser:\n{auth_url}")
```

### 8.3 Success output

```
[green]Stored OAuth credential [cyan]{record.id}[/cyan] for [bold]google[/bold] alias 'work'.[/green]
[yellow]Access token expires in {expires_in}s. Run `hermes-vault oauth refresh google --alias work` before expiry.[/yellow]
```

If no `expires_in` is provided by the provider, omit the expiry line.

---

## 9. Vault Integration

### 9.1 Credential storage

The resulting credential is stored exactly like any other:

```python
mutations.add_credential(
    agent_id=OPERATOR_AGENT_ID,
    service=provider.canonical_id,
    secret=token_response.access_token,
    credential_type="oauth_access_token",
    alias=alias,
    scopes=scopes,
)
```

After `add_credential` returns, we call `vault.set_expiry(...)` if `token_response.expires_in` is present, computing:

```python
expiry = datetime.now(timezone.utc) + timedelta(seconds=token_response.expires_in)
```

### 9.2 Refresh token handling

The `refresh_token` is **not** the primary secret, but it must be stored securely for future `oauth refresh` commands. We store it inside the encrypted `CredentialSecret.metadata` dict:

```python
secret = CredentialSecret(
    secret=token_response.access_token,
    metadata={
        "refresh_token": token_response.refresh_token,
        "token_type": token_response.token_type,
        "raw_response": token_response.raw,
    },
)
```

This keeps the access token as the top-level secret (what the Broker returns) while bundling the refresh token in the same encrypted payload.

### 9.3 Policy implications

`oauth_access_token` is already a known `credential_type` in detectors and tests. No policy schema changes are required for T2/T3. When `oauth refresh` is added later, it will need a new `ServiceAction` (e.g., `refresh`) or be treated as a rotate mutation.

---

## 10. Security Considerations

| Concern | Mitigation |
|---------|------------|
| CSRF / authorization code interception | `state` parameter validated with `secrets.compare_digest`. Single-use, cleared after validation. |
| Code interception by another local process | `redirect_uri` is `127.0.0.1` with an ephemeral port. Port is printed in the terminal so the operator knows what to expect. The callback handler only processes the first request and then shuts down. |
| Secret logging | Callback handler suppresses HTTP access logs. Token exchange response is never printed. Only the credential ID and alias are printed on success. |
| Browser history leaking `code` | Unavoidable for localhost flows, but the code is short-lived (single-use, bound to the PKCE verifier) and the server shuts down immediately after exchange. |
| TLS for token endpoint | Handled by `requests` (HTTPS only). Token endpoint URLs in the registry must use `https://`. |
| Client secret in env vars | Optional. PKCE is designed for public clients; a `client_secret` is only required by providers that haven't fully embraced public clients. |

---

## 11. File Layout (new code)

```
src/hermes_vault/oauth/
  __init__.py
  pkce.py
  state.py
  callback.py
  exchange.py
  providers.py
  flow.py
  errors.py          # OAuthFlowError, OAuthTimeoutError, OAuthDeniedError, OAuthStateMismatchError

src/hermes_vault/cli.py
  # Add oauth_app registration and @oauth_app.command("login") handler

data/
  oauth-default-providers.yaml   # baked-in provider defaults (shipped with package)
```

---

## 12. Open Questions / Future Work

1. **Headless/agent flows**: This design is operator-interactive. A future `oauth refresh` triggered by the Broker would need a non-interactive path using stored `refresh_token` without a browser.
2. **Token rotation on expiry**: The verifier layer could be extended to detect `invalid_or_expired` OAuth tokens and auto-trigger refresh if a `refresh_token` is present in metadata.
3. **Multiple OAuth identities per provider**: The alias system already supports this (`--alias work`, `--alias personal`).
4. **Device Authorization Grant**: Some environments (e.g., SSH-only servers) can't open a browser. A future `oauth login --device-code` could support the device flow as an alternative.

---

## 13. Glossary

| Term | Meaning |
|------|---------|
| PKCE | Proof Key for Code Exchange (RFC 7636) |
| `code_verifier` | High-entropy secret generated by the client |
| `code_challenge` | `BASE64URL(SHA256(code_verifier))` |
| `state` | Unguessable nonce for CSRF protection |
| `redirect_uri` | `http://127.0.0.1:<port>/callback` -- where the provider redirects after authorization |

---

*End of architecture document. Implementation task (T3) consumes this plus `token-schema.md`.*
