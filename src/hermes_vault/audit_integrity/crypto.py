from __future__ import annotations

import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENTRY_SIGNING_CONTEXT = b"hermes-vault/audit-entry-signing/ed25519-v1"
CHECKPOINT_SIGNING_CONTEXT = b"hermes-vault/audit-checkpoint-signing/ed25519-v1"
KEY_DERIVATION_VERSION = "hkdf-sha256-ed25519-v1"
ENTRY_SIGNATURE_VERSION = "ed25519-entry-v1"
CHECKPOINT_SIGNATURE_VERSION = "ed25519-checkpoint-v1"


def digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def digest_hex(value: bytes) -> str:
    return digest(value).hex()


def derive_seed(master_key: bytes, context: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(master_key)


def private_key(master_key: bytes, context: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(derive_seed(master_key, context))


def public_key_b64(master_key: bytes, context: bytes) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return base64.b64encode(private_key(master_key, context).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def sign(master_key: bytes, context: bytes, payload: bytes) -> str:
    return base64.b64encode(private_key(master_key, context).sign(payload)).decode("ascii")


def verify(public_key: str, signature: str, payload: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(base64.b64decode(signature, validate=True), payload)
    except (ValueError, TypeError):
        return False
    except Exception:
        return False
    return True