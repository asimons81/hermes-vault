from __future__ import annotations

import base64
import getpass
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hermes_vault import _platform
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CRYPTO_VERSION = "aesgcm-v1"
CRYPTO_VERSION_V2 = "aesgcm-v2"
NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 390_000

# Write-side cutover point for Issue #60. New credential writes use this
# version label. Keeping it at ``CRYPTO_VERSION`` (aesgcm-v1) means every
# decrypt path is versioned and v1-compatible before any v2 ciphertext is
# produced by default. Flip to ``CRYPTO_VERSION_V2`` (or set the
# HERMES_VAULT_CRYPTO_VERSION env var) to begin writing AAD-bound v2 rows.
WRITE_CRYPTO_VERSION = CRYPTO_VERSION

# Canonical AAD domain/kind/version marker. Bound into every v2 AAD so the
# same metadata bytes cannot be replayed as AAD for a different product,
# record kind, or envelope version (AAD reuse prevention, issue #60).
AAD_DOMAIN = "hermes-vault"
AAD_KIND = "credential-aad"
AAD_VERSION = "v2"

# DPAPI envelope magic. Re-exported here so crypto and dpapi share one
# constant. See hermes_vault.dpapi for the wrapping semantics.
DPAPI_HEADER = b"HVDP"
DPAPI_ENVELOPE_VERSION = "dpapi-v1"


class MissingPassphraseError(RuntimeError):
    pass


class MissingKeyMaterialError(RuntimeError):
    pass


class CorruptKeyMaterialError(RuntimeError):
    pass


@dataclass(frozen=True)
class PassphraseResult:
    passphrase: str
    source: str


def profile_passphrase_env_name(profile_name: str = "default") -> str:
    suffix = re.sub(r"[^A-Za-z0-9]", "_", profile_name or "default").upper()
    return f"HERMES_VAULT_PASSPHRASE_{suffix}"


def resolve_passphrase_with_source(
    explicit_passphrase: str | None = None,
    prompt: bool = False,
    profile_name: str = "default",
) -> PassphraseResult:
    if explicit_passphrase:
        return PassphraseResult(explicit_passphrase, "explicit")

    profile_env = profile_passphrase_env_name(profile_name)
    profile_env_passphrase = os.environ.get(profile_env)
    if profile_env_passphrase:
        return PassphraseResult(profile_env_passphrase, f"env:{profile_env}")

    env_passphrase = os.environ.get("HERMES_VAULT_PASSPHRASE")
    if env_passphrase:
        return PassphraseResult(env_passphrase, "env:HERMES_VAULT_PASSPHRASE")

    if prompt:
        secret = getpass.getpass("Hermes Vault passphrase: ")
        if secret:
            return PassphraseResult(secret, "prompt")

    hint = f" or {profile_env}" if profile_name and profile_name != "default" else ""
    raise MissingPassphraseError(
        f"No Hermes Vault passphrase available. Set HERMES_VAULT_PASSPHRASE{hint} or use an interactive prompt."
    )


def resolve_passphrase(
    explicit_passphrase: str | None = None,
    prompt: bool = False,
    profile_name: str = "default",
) -> str:
    return resolve_passphrase_with_source(
        explicit_passphrase=explicit_passphrase,
        prompt=prompt,
        profile_name=profile_name,
    ).passphrase


def load_or_create_salt(path: Path, create_if_missing: bool = False) -> bytes:
    if path.exists():
        salt = path.read_bytes()
        if len(salt) != SALT_SIZE:
            raise CorruptKeyMaterialError(
                f"Salt file {path} has invalid size {len(salt)}; expected {SALT_SIZE} bytes."
            )
        return salt
    if not create_if_missing:
        raise MissingKeyMaterialError(f"Salt file is missing at {path}. Restore the salt before opening the vault.")
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_SIZE)
    path.write_bytes(salt)
    _platform.secure_file(path)
    return salt


def load_or_create_master_key(
    salt_path: Path,
    passphrase: str,
    *,
    enable_dpapi: bool = True,
) -> bytes:
    """Derive the 32-byte master key, persisting it as either a legacy 16-byte
    salt file or a DPAPI envelope of the 32-byte key.

    On-disk format is auto-detected by the 4-byte :data:`DPAPI_HEADER`
    magic. A legacy 16-byte salt file (random bytes) is read directly
    and :func:`derive_key` is called. A file beginning with the magic
    is unwrapped via DPAPI and the original 32-byte key is returned.

    When *enable_dpapi* is True and no file exists yet, a new DPAPI
    envelope is written. When *enable_dpapi* is False, the legacy
    16-byte salt path is used. The caller decides which behaviour
    applies (typically from :func:`hermes_vault.dpapi.should_use_dpapi`
    or an explicit env-var opt-in).

    Backward compatibility: a legacy vault with a 16-byte salt and no
    opt-in continues to work without intervention; the magic-header
    check returns False for any 16-byte file (see
    :func:`hermes_vault.dpapi.should_use_dpapi` for the strict length
    gate that prevents mis-detection).
    """
    # Deferred import keeps dpapi's win32crypt off the cold import
    # path. The reference is also kept module-local so tests can
    # monkeypatch hermes_vault.dpapi before this function runs.
    from hermes_vault import dpapi  # noqa: PLC0415  -- intentional deferred import

    if salt_path.exists():
        raw = salt_path.read_bytes()
        if raw.startswith(DPAPI_HEADER):
            # New path: DPAPI envelope. The dpapi module enforces the
            # length gate (it would have rejected a 16-byte file that
            # happened to begin with the magic), so reaching this
            # branch implies raw is a real envelope.
            return dpapi.unprotect_master_key(raw)
        # Legacy path: raw 16-byte salt. Reuse the existing helper to
        # preserve the size check and the CorruptKeyMaterialError path.
        salt = load_or_create_salt(salt_path, create_if_missing=False)
        return derive_key(passphrase, salt)

    if not enable_dpapi:
        # Legacy create path -- unchanged from load_or_create_salt.
        return derive_key(passphrase, load_or_create_salt(salt_path, create_if_missing=True))

    # DPAPI create path. When the caller explicitly opted in
    # (enable_dpapi=True) but DPAPI is not actually usable here
    # (POSIX without pywin32, or Windows with pywin32 missing), this
    # is a hard error: the caller is asking for a feature that the
    # current environment cannot provide. The Vault constructor
    # handles the soft opt-in (env var) by downgrading to
    # enable_dpapi=False with a stderr warning; this branch is
    # reached only when enable_dpapi was passed explicitly.
    if not dpapi.is_available():
        raise RuntimeError(
            "DPAPI is enabled but not available. Install pywin32 on Windows "
            "or pass enable_dpapi=False to fall back to the legacy path."
        )
    # Derive a key from a freshly-generated salt, then wrap the key
    # bytes with DPAPI. The salt embedded inside the envelope is
    # ephemeral; only the wrapped 32-byte key is persisted. This
    # matches the spec: the on-disk file is a DPAPI envelope, not a
    # 16-byte salt.
    ephemeral_salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, ephemeral_salt)
    envelope = dpapi.protect_master_key(key)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    salt_path.write_bytes(envelope)
    _platform.secure_file(salt_path)
    return key


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_secret(secret: str, key: bytes) -> str:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(encoded: str, key: bytes) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


def current_write_version() -> str:
    """Return the crypto version label for NEW credential writes.

    Honors the ``HERMES_VAULT_CRYPTO_VERSION`` env var as a feature flag;
    otherwise falls back to :data:`WRITE_CRYPTO_VERSION` (the explicit
    in-code cutover point). Unknown labels fail closed.
    """
    override = os.environ.get("HERMES_VAULT_CRYPTO_VERSION", "").strip()
    if override:
        if override not in (CRYPTO_VERSION, CRYPTO_VERSION_V2):
            raise ValueError(f"Unsupported HERMES_VAULT_CRYPTO_VERSION: {override!r}")
        return override
    return WRITE_CRYPTO_VERSION


def credential_aad_metadata(
    record_id: str,
    service: str,
    alias: str,
    credential_type: str,
    scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Build the authorization metadata bound into a v2 credential AAD.

    Fields are the same ones the broker consumes at policy time, so a
    relabeled row can never decrypt (issue #60).
    """
    return {
        "id": record_id,
        "service": service,
        "alias": alias,
        "credential_type": credential_type,
        "scopes": scopes or [],
    }


def build_canonical_aad(metadata: Mapping[str, Any]) -> bytes:
    """Deterministic canonical AAD for credential authorization metadata.

    Serialization is stable: keys are sorted, list values are sorted, JSON is
    compact (no whitespace) and ASCII-escaped, and the whole body is prefixed
    with a domain/kind/version marker so identical field values cannot be
    replayed as AAD for a different product, record kind, or envelope
    version. Any change to a bound field changes the AAD and therefore fails
    authenticated decryption (issue #60).
    """
    normalized: dict[str, Any] = {}
    for key in sorted(metadata):
        value = metadata[key]
        if isinstance(value, (list, tuple)):
            normalized[key] = sorted(str(item) for item in value)
        elif isinstance(value, str):
            normalized[key] = value
        elif value is None:
            normalized[key] = None
        elif isinstance(value, bool):
            normalized[key] = value
        else:
            raise TypeError(f"Unsupported AAD metadata type for {key!r}: {type(value).__name__}")
    marker = f"{AAD_DOMAIN}:{AAD_KIND}:{AAD_VERSION}"
    body = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"{marker}:{body}".encode("utf-8")


def encrypt_secret_v2(secret: str, key: bytes, aad_metadata: Mapping[str, Any]) -> str:
    """AAD-bound AES-GCM encryption (v2 envelope).

    The canonical AAD is derived from *aad_metadata* via
    :func:`build_canonical_aad`; the ciphertext cannot be decrypted without
    the exact same bound metadata.
    """
    nonce = os.urandom(NONCE_SIZE)
    aad = build_canonical_aad(aad_metadata)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode("utf-8"), aad)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret_v2(encoded: str, key: bytes, aad_metadata: Mapping[str, Any]) -> str:
    """AAD-bound AES-GCM decryption (v2 envelope)."""
    raw = base64.b64decode(encoded.encode("ascii"))
    nonce = raw[:NONCE_SIZE]
    ciphertext = raw[NONCE_SIZE:]
    aad = build_canonical_aad(aad_metadata)
    return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")


def encrypt_secret_versioned(
    secret: str,
    key: bytes,
    version: str,
    aad_metadata: Mapping[str, Any] | None = None,
) -> str:
    """Encrypt using the envelope version explicitly.

    ``aesgcm-v1`` keeps the legacy AAD=None format (byte-for-byte identical
    to :func:`encrypt_secret`); ``aesgcm-v2`` binds the canonical AAD.
    """
    if version == CRYPTO_VERSION:
        return encrypt_secret(secret, key)
    if version == CRYPTO_VERSION_V2:
        if aad_metadata is None:
            raise ValueError("aesgcm-v2 encryption requires authorization metadata for AAD")
        return encrypt_secret_v2(secret, key, aad_metadata)
    raise ValueError(f"Unsupported crypto version: {version!r}")


def decrypt_secret_versioned(
    encoded: str,
    key: bytes,
    version: str,
    aad_metadata: Mapping[str, Any] | None = None,
) -> str:
    """Decrypt routing on the row's envelope version label.

    ``aesgcm-v1`` legacy rows keep AAD=None reads unchanged (existing
    ciphertexts and backups keep working). ``aesgcm-v2`` rows require the
    exact authorization metadata that was bound at write time. Unknown
    version labels fail closed with ``ValueError``.
    """
    if version == CRYPTO_VERSION:
        return decrypt_secret(encoded, key)
    if version == CRYPTO_VERSION_V2:
        if aad_metadata is None:
            raise ValueError("aesgcm-v2 decryption requires authorization metadata for AAD")
        return decrypt_secret_v2(encoded, key, aad_metadata)
    raise ValueError(f"Unsupported crypto version: {version!r}")
