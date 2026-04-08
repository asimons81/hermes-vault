from __future__ import annotations

import base64
import getpass
import os
from pathlib import Path

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


def resolve_passphrase(explicit_passphrase: str | None = None, prompt: bool = False) -> str:
    if explicit_passphrase:
        return explicit_passphrase
    env_passphrase = os.environ.get("HERMES_VAULT_PASSPHRASE")
    if env_passphrase:
        return env_passphrase
    if prompt:
        secret = getpass.getpass("Hermes Vault passphrase: ")
        if secret:
            return secret
    raise MissingPassphraseError(
        "No Hermes Vault passphrase available. Set HERMES_VAULT_PASSPHRASE or use an interactive prompt."
    )


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
    path.chmod(0o600)
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
