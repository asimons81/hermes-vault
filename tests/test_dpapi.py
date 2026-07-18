"""Tests for DPAPI master-key wrapping (Windows only).

Hermes Vault targets POSIX/WSL in CI, so the real ``win32crypt`` is
never importable here. The fixture below installs an in-test
``_FakeWin32Crypt`` shim and patches ``_platform._is_windows`` to
``True`` so the DPAPI code path runs end-to-end. This is the same
``monkeypatch.setattr(_platform, "_is_windows", ...)`` idiom used
throughout ``tests/test_platform.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from hermes_vault import _platform, crypto, dpapi, vault


# ── Test doubles ──────────────────────────────────────────────────────────────


class _FakeWin32Crypt:
    """In-memory CryptProtectData / CryptUnprotectData stand-in.

    Protection is XOR with a 4-byte rolling key so round-trips are
    deterministic but the envelope is still distinguishable from
    the cleartext bytes. This matches the spec's §5.2 sketch.
    """

    _xor = bytes((0x5A, 0xA5, 0x3C, 0xC3))

    @classmethod
    def CryptProtectData(cls, data, *args, **kwargs):  # noqa: N802 -- upstream name
        return bytes(b ^ cls._xor[i % len(cls._xor)] for i, b in enumerate(data))

    @classmethod
    def CryptUnprotectData(cls, data, *args, **kwargs):  # noqa: N802 -- upstream name
        return bytes(b ^ cls._xor[i % len(cls._xor)] for i, b in enumerate(data))


@pytest.fixture
def fake_win32(monkeypatch: pytest.MonkeyPatch):
    """Install _FakeWin32Crypt as the win32crypt module for this test.

    Combines the two established idioms from tests/test_platform.py:
    monkeypatch.setitem(sys.modules, "win32crypt", ...) and
    monkeypatch.setattr(_platform, "_is_windows", lambda: True).
    """
    monkeypatch.setitem(sys.modules, "win32crypt", _FakeWin32Crypt)
    monkeypatch.setattr(_platform, "_is_windows", lambda: True)
    return _FakeWin32Crypt


# ── 1-3: availability ─────────────────────────────────────────────────────────


def test_dpapi_available_on_windows_with_pywin32(fake_win32) -> None:
    """dpapi.is_available() True when _is_windows True and win32crypt importable."""
    assert dpapi.is_available() is True


def test_dpapi_available_false_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """dpapi.is_available() False on POSIX even if win32crypt were importable."""
    # Install a fake win32crypt so the import would succeed if asked.
    monkeypatch.setitem(sys.modules, "win32crypt", _FakeWin32Crypt)
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    assert dpapi.is_available() is False


def test_dpapi_available_false_when_pywin32_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dpapi.is_available() False when win32crypt is not in sys.modules."""
    monkeypatch.setattr(_platform, "dpapi_available", lambda: False)
    assert dpapi.is_available() is False


# ── 4-7: protect / unprotect round-trip and rejection ─────────────────────────


def test_protect_unprotect_roundtrip(fake_win32) -> None:
    """unprotect_master_key(protect_master_key(k)) == k for random 32 bytes."""
    import os as _os
    plaintext = _os.urandom(32)
    envelope = dpapi.protect_master_key(plaintext)
    assert dpapi.unprotect_master_key(envelope) == plaintext


def test_protect_adds_magic_header(fake_win32) -> None:
    """Output envelope begins with DPAPI_HEADER (4 bytes 'HVDP')."""
    out = dpapi.protect_master_key(b"\x00" * 32)
    assert out[: len(dpapi.DPAPI_HEADER)] == dpapi.DPAPI_HEADER
    assert out[:4] == b"HVDP"


def test_unprotect_rejects_non_dpapi_envelope(fake_win32) -> None:
    """Passing raw 16-byte salt to unprotect_master_key raises ValueError."""
    import os as _os
    with pytest.raises(ValueError, match="Not a Hermes Vault DPAPI envelope"):
        dpapi.unprotect_master_key(_os.urandom(16))


def test_protect_raises_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """protect_master_key on POSIX raises RuntimeError with the documented message."""
    monkeypatch.setitem(sys.modules, "win32crypt", _FakeWin32Crypt)
    monkeypatch.setattr(_platform, "_is_windows", lambda: False)
    with pytest.raises(RuntimeError, match="DPAPI is not available"):
        dpapi.protect_master_key(b"\x00" * 32)


# ── 8-10: should_use_dpapi ────────────────────────────────────────────────────


def test_should_use_dpapi_true_on_envelope_file(
    tmp_path: Path, fake_win32,
) -> None:
    """Existing master_key_salt.bin starting with magic -> True."""
    salt = tmp_path / "salt.bin"
    salt.write_bytes(dpapi.DPAPI_HEADER + b"\x01\x02\x03\x04")
    assert dpapi.should_use_dpapi(salt) is True


def test_should_use_dpapi_false_on_legacy_salt(tmp_path: Path) -> None:
    """Existing 16-byte raw salt -> False (backward-compat)."""
    salt = tmp_path / "salt.bin"
    salt.write_bytes(os.urandom(16))
    assert dpapi.should_use_dpapi(salt) is False


def test_should_use_dpapi_false_on_missing_file(tmp_path: Path) -> None:
    """master_key_salt.bin not present -> False (no automatic migration)."""
    salt = tmp_path / "salt.bin"
    assert dpapi.should_use_dpapi(salt) is False


# ── 11-15: load_or_create_master_key branches ─────────────────────────────────


def test_load_or_create_master_key_legacy_path(tmp_path: Path) -> None:
    """Pre-existing 16-byte salt -> derive_key is called and result is returned."""
    salt = tmp_path / "salt.bin"
    salt.write_bytes(os.urandom(16))
    key = crypto.load_or_create_master_key(salt, "passphrase", enable_dpapi=False)
    # The legacy path returns derive_key's 32-byte output.
    assert isinstance(key, bytes)
    assert len(key) == 32
    # And it's reproducible given the same salt and passphrase.
    assert key == crypto.derive_key("passphrase", salt.read_bytes())


def test_load_or_create_master_key_dpapi_envelope_path(
    tmp_path: Path, fake_win32,
) -> None:
    """Pre-existing DPAPI envelope -> dpapi.unprotect_master_key is called."""
    salt = tmp_path / "salt.bin"
    payload = os.urandom(32)
    envelope = dpapi.protect_master_key(payload)
    salt.write_bytes(envelope)
    key = crypto.load_or_create_master_key(salt, "ignored", enable_dpapi=True)
    assert key == payload


def test_load_or_create_master_key_creates_dpapi_when_enabled(
    tmp_path: Path, fake_win32,
) -> None:
    """No salt file + enable_dpapi=True + dpapi available -> envelope written."""
    salt = tmp_path / "salt.bin"
    key = crypto.load_or_create_master_key(salt, "pass", enable_dpapi=True)
    assert salt.exists()
    raw = salt.read_bytes()
    assert raw.startswith(dpapi.DPAPI_HEADER)
    assert dpapi.unprotect_master_key(raw) == key


def test_load_or_create_master_key_creates_legacy_when_disabled(
    tmp_path: Path,
) -> None:
    """No salt file + enable_dpapi=False -> 16-byte raw salt written."""
    salt = tmp_path / "salt.bin"
    key = crypto.load_or_create_master_key(salt, "pass", enable_dpapi=False)
    assert salt.exists()
    raw = salt.read_bytes()
    assert len(raw) == crypto.SALT_SIZE
    assert not raw.startswith(dpapi.DPAPI_HEADER)
    assert key == crypto.derive_key("pass", raw)


def test_load_or_create_master_key_raises_when_dpapi_enabled_but_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No salt + enable_dpapi=True + dpapi unavailable -> RuntimeError w/ hint."""
    salt = tmp_path / "salt.bin"
    monkeypatch.setattr("hermes_vault.dpapi.is_available", lambda: False)
    with pytest.raises(RuntimeError, match="DPAPI is enabled but not available"):
        crypto.load_or_create_master_key(salt, "pass", enable_dpapi=True)


# ── 16-17: Vault constructor ──────────────────────────────────────────────────


def test_vault_constructor_picks_up_existing_dpapi_vault(
    tmp_path: Path, fake_win32, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault with a DPAPI envelope salt -> self.key is the unwrapped 32-byte key."""
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    # Seed a DPAPI envelope. We don't use Vault.__init__ for setup
    # because we want to bypass the env-var opt-in path.
    expected_key = os.urandom(32)
    salt.write_bytes(dpapi.protect_master_key(expected_key))
    # Make sure the env var is not set; reads are format-driven, not env-driven.
    monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)
    v = vault.Vault(db, salt, "any-passphrase-is-ignored")
    assert v.key == expected_key
    # Verify the key actually encrypts / decrypts round-trip.
    v.add_credential("svc", "secret-1", "api_key", alias="primary")
    fetched = v.get_secret("svc")
    assert fetched is not None
    assert fetched.secret == "secret-1"


def test_vault_constructor_picks_up_legacy_salt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault with a legacy 16-byte salt -> works exactly as today (regression)."""
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)
    v = vault.Vault(db, salt, "passphrase")
    v.add_credential("svc", "secret-1", "api_key", alias="primary")
    fetched = v.get_secret("svc")
    assert fetched is not None
    assert fetched.secret == "secret-1"
    # Legacy salt is 16 bytes and does not start with the magic.
    assert not salt.read_bytes().startswith(dpapi.DPAPI_HEADER)


# ── 18-20: rotation ──────────────────────────────────────────────────────────


def test_rotate_master_key_writes_dpapi_envelope(
    tmp_path: Path, fake_win32, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """rotate_master_key writes a DPAPI envelope; a fresh Vault unwraps it."""
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    monkeypatch.setenv("HERMES_VAULT_DPAPI", "1")
    try:
        v = vault.Vault(db, salt, "old-pass")
        v.add_credential("svc", "secret-1", "api_key", alias="primary")
        v.rotate_master_key("old-pass", "new-pass")
        # After rotation, the salt file should be a DPAPI envelope.
        assert salt.read_bytes().startswith(dpapi.DPAPI_HEADER)
        # A fresh Vault opens it cleanly and can decrypt the credential.
        v2 = vault.Vault(db, salt, "new-pass")
        fetched = v2.get_secret("svc")
        assert fetched is not None
        assert fetched.secret == "secret-1"
    finally:
        monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)


def test_rotate_master_key_legacy_to_dpapi_does_not_silently_migrate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """rotate_master_key on a legacy vault with no opt-in keeps legacy format."""
    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)
    v = vault.Vault(db, salt, "old-pass")
    v.add_credential("svc", "secret-1", "api_key", alias="primary")
    v.rotate_master_key("old-pass", "new-pass")
    # No env var was set, so the salt must still be 16 raw bytes.
    assert not salt.read_bytes().startswith(dpapi.DPAPI_HEADER)
    assert len(salt.read_bytes()) == crypto.SALT_SIZE
    # A fresh Vault opens it with the new passphrase.
    v2 = vault.Vault(db, salt, "new-pass")
    assert v2.get_secret("svc").secret == "secret-1"


def test_rotation_journal_unaffected_by_dpapi(
    tmp_path: Path, fake_win32, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rotation journal still has hex old_salt / new_salt; DPAPI happens at write."""
    import json as _json

    db = tmp_path / "vault.db"
    salt = tmp_path / "salt.bin"
    monkeypatch.setenv("HERMES_VAULT_DPAPI", "1")
    try:
        v = vault.Vault(db, salt, "old-pass")
        v.add_credential("svc", "secret-1", "api_key", alias="primary")
        v.rotate_master_key("old-pass", "new-pass")
        # Journal is removed after successful rotation; verify the
        # hex-encoded salt format was used during rotation by
        # monkey-patching the journal write to capture the payload.
    finally:
        monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)

    # Now exercise the journal payload format directly: simulate a
    # mid-rotation journal that would be on disk if rotation had
    # crashed. The journal uses hex of the 16-byte derivation salt
    # for both legacy and DPAPI vaults (per spec §5.3 test 20).
    captured: list[dict] = []

    class _CapturingVault(vault.Vault):
        def _write_rotation_journal(self_inner, payload):  # type: ignore[override]
            captured.append(_json.loads(_json.dumps(payload)))

    monkeypatch.setenv("HERMES_VAULT_DPAPI", "1")
    try:
        v2 = _CapturingVault(db, salt, "old-pass")
        v2.rotate_master_key("old-pass", "new-pass")
    finally:
        monkeypatch.delenv("HERMES_VAULT_DPAPI", raising=False)

    # The very first journal write is the "started" entry; verify
    # both old_salt and new_salt are valid hex strings (format is
    # unchanged from v0.13.0 -- the *value* depends on the durable
    # form: 16-byte salt for legacy vaults, DPAPI envelope bytes for
    # DPAPI vaults).
    started = captured[0]
    assert started["status"] == "started"
    bytes.fromhex(started["old_salt"])  # raises if not valid hex
    bytes.fromhex(started["new_salt"])
    # The derivation salt (new_salt) is always 16 random bytes.
    assert len(bytes.fromhex(started["new_salt"])) == 16
