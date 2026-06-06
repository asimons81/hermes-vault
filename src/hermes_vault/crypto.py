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
