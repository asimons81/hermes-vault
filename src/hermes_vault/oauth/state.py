"""OAuth state parameter generation and validation for CSRF protection."""

import secrets


class StateManager:
    """Manages the CSRF-protecting state parameter.

    State is held in memory only (single-process operator flow).
    It is cleared immediately after validation.
    """

    def __init__(self) -> None:
        self._state: str | None = None

    def generate(self) -> str:
        """Generate a new state nonce."""
        self._state = secrets.token_urlsafe(32)
        return self._state

    def validate(self, incoming: str | None) -> bool:
        """Validate an incoming state value with timing-safe comparison.

        Returns False if no state has been generated or if it doesn't match.
        Clears the stored state after comparison (single-use).
        """
        try:
            if self._state is None or incoming is None:
                return False
            return secrets.compare_digest(self._state, incoming)
        finally:
            self._state = None

    def clear(self) -> None:
        """Explicitly clear the stored state."""
        self._state = None

    @property
    def current(self) -> str | None:
        """Access the current state value (for debugging / logging only)."""
        return self._state
