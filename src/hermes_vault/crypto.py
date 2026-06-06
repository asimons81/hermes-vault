from __future__ import annotations

import base64
import getpass
import os
import re
from dataclasses import dataclass
from pathlib import Path

from hermes_vault import _platform
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CRYPTO_VERSION = "aesgcm-v1"
NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 390_000

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
