"""OAuth flow exceptions and safe provider-error formatting."""

from __future__ import annotations

import re


_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(access_token|refresh_token|client_secret|device_code|code|id_token)"
    r"([=:\"]\s*)([^&\s,\"'}]+)"
)
_TOKEN_SHAPE_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)


def sanitize_oauth_error_detail(value: object, *, max_length: int = 300) -> str:
    """Return provider error text safe enough for logs and user-facing output."""
    text = "" if value is None else str(value)
    text = _SENSITIVE_VALUE_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", text)
    text = _TOKEN_SHAPE_RE.sub("[redacted]", text)
    text = " ".join(text.split())
    if len(text) > max_length:
        return text[:max_length].rstrip() + "..."
    return text


def format_oauth_provider_error(prefix: str, detail: object = "") -> str:
    safe_detail = sanitize_oauth_error_detail(detail)
    return f"{prefix} - {safe_detail}" if safe_detail else prefix


class OAuthFlowError(RuntimeError):
    """Base exception for all OAuth flow errors."""
    pass


class OAuthTimeoutError(OAuthFlowError):
    """Raised when no callback is received within the timeout window."""
    pass


class OAuthDeniedError(OAuthFlowError):
    """Raised when the user or provider denies authorization."""
    pass


class OAuthStateMismatchError(OAuthFlowError):
    """Raised when the state parameter returned from the provider doesn't match."""
    pass


class OAuthNetworkError(OAuthFlowError):
    """Raised when network communication with the provider fails."""
    pass


class OAuthProviderError(OAuthFlowError):
    """Raised when the token endpoint returns an error."""
    pass


class OAuthMissingClientIdError(OAuthFlowError):
    """Raised when the provider requires a client_id but none is configured."""
    pass


class OAuthUnknownProviderError(OAuthFlowError):
    """Raised when the requested provider is not in the registry."""
    pass
