"""OAuth flow exceptions.
"""


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
