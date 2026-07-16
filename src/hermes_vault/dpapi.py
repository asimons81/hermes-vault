"""DPAPI master-key wrapping for Hermes Vault (Windows only).

This module is a thin wrapper over ``win32crypt`` so the
``pywin32`` dependency stays optional. Importing this module is
always safe on POSIX; the actual ``import win32crypt`` is deferred
to the protect/unprotect call sites so a missing ``pywin32`` on a
non-Windows system never raises at import time.

The on-disk envelope is the ``DPAPI_HEADER`` magic followed by the
bytes returned by ``win32crypt.CryptProtectData``. Detection is
strict: any file smaller than the 4-byte header is treated as legacy
salt (16 random bytes start with ``b"HVDP"`` ~1 in 4 billion times,
and such a file would only have 12 bytes of "envelope" — too short
for any real DPAPI output). See ``should_use_dpapi``.
"""

from __future__ import annotations

from pathlib import Path

from hermes_vault import _platform


# Envelope magic header. 4 bytes "HVDP" prepended to every DPAPI-wrapped
# master key so the on-disk format is self-describing.
DPAPI_HEADER = b"HVDP"

# Envelope version tag, exported for symmetry with crypto.CRYPTO_VERSION.
# Not currently embedded in the envelope itself (the header is the
# only magic); keep it alongside the header for future migrations.
DPAPI_ENVELOPE_VERSION = "dpapi-v1"

# Sidecar filename referenced in the spec. Currently unused (entropy is
# the user account by design on Windows) but reserved so a future
# non-default entropy override has a stable path.
DPAPI_ENTROPY_FILENAME = "dpapi_entropy.bin"


def is_available() -> bool:
    """True iff DPAPI is usable on this process (Windows + pywin32 importable).

    Delegates to :func:`hermes_vault._platform.dpapi_available` so the
    availability rule lives in one place.
    """
    return _platform.dpapi_available()


def protect_master_key(plaintext_key: bytes) -> bytes:
    """Wrap *plaintext_key* with DPAPI. Returns envelope bytes.

    The returned bytes begin with :data:`DPAPI_HEADER` and can later
    be passed back to :func:`unprotect_master_key`. Raises
    :class:`RuntimeError` on POSIX or when ``pywin32`` is missing.
    """
    if not is_available():
        raise RuntimeError(
            "DPAPI is not available on this platform. "
            "Install pywin32 on Windows or unset HERMES_VAULT_DPAPI."
        )
    # Deferred import so pywin32 is a true optional dependency.
    import win32crypt  # noqa: PLC0415  -- intentional lazy import

    # CryptProtectData accepts six positional args at runtime:
    # data, description, optional entropy, reserved, prompt struct, flags.
    return DPAPI_HEADER + win32crypt.CryptProtectData(
        plaintext_key, None, None, None, None, 0,
    )


def unprotect_master_key(envelope: bytes) -> bytes:
    """Unwrap a DPAPI envelope and return the original plaintext bytes.

    Real pywin32 accepts five positional arguments for
    ``CryptUnprotectData`` and returns ``(description, data)``. The small
    compatibility branch also accepts a raw-bytes result from test doubles or
    older wrappers so callers always receive bytes.

    Raises :class:`ValueError` if the envelope does not start with
    :data:`DPAPI_HEADER`. Raises :class:`RuntimeError` when DPAPI is
    not usable here or the platform wrapper returns an unexpected shape.
    """
    if not is_available():
        raise RuntimeError(
            "DPAPI is not available on this platform. "
            "Install pywin32 on Windows or unset HERMES_VAULT_DPAPI."
        )
    if not envelope.startswith(DPAPI_HEADER):
        raise ValueError("Not a Hermes Vault DPAPI envelope.")
    # Deferred import so pywin32 is a true optional dependency.
    import win32crypt  # noqa: PLC0415  -- intentional lazy import

    result = win32crypt.CryptUnprotectData(
        envelope[len(DPAPI_HEADER):], None, None, None, 0,
    )
    if isinstance(result, tuple):
        if len(result) != 2:
            raise RuntimeError("DPAPI returned an unexpected result shape.")
        _description, plaintext = result
    else:
        plaintext = result
    if not isinstance(plaintext, bytes):
        raise RuntimeError("DPAPI returned non-byte plaintext.")
    return plaintext


def should_use_dpapi(salt_path: Path) -> bool:
    """True iff the existing file at *salt_path* is a DPAPI envelope.

    Used by :class:`hermes_vault.vault.Vault` on every key load so
    the DPAPI path stays opt-in for existing vaults (no silent
    migration of legacy 16-byte salt files).

    The strict length check (``len(raw) > len(DPAPI_HEADER)``) makes
    the rule deterministic: a 16-byte random salt that happens to
    begin with the 4-byte magic would only have 12 bytes of
    "envelope" remaining — too short for any real DPAPI output — so
    we treat it as legacy. This is the mitigation for risk #6 in
    the DPAPI spec.
    """
    if not salt_path.exists():
        return False
    try:
        raw = salt_path.read_bytes()
    except OSError:
        return False
    # Strict length gate prevents mis-detection of a tiny legacy file
    # whose first 4 bytes happen to match the magic.
    if len(raw) <= len(DPAPI_HEADER):
        return False
    return raw.startswith(DPAPI_HEADER)
