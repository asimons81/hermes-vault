"""PKCE S256 code_verifier and code_challenge generation.

RFC 7636: Proof Key for Code Exchange by OAuth Public Clients
"""

import base64
import hashlib
import secrets


class PKCEGenerator:
    """Generates PKCE code_verifier and code_challenge (S256)."""

    DEFAULT_LENGTH = 128

    @staticmethod
    def generate_verifier(length: int = DEFAULT_LENGTH) -> str:
        """Generate a code_verifier: random URL-safe base64 string.

        The verifier is un-padded base64url of `length` random bytes.
        After encoding this typically yields ~171 characters (for length=128).
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).rstrip(b"=").decode("ascii")

    @staticmethod
    def generate_challenge(verifier: str) -> str:
        """Generate the S256 code_challenge from a verifier."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
