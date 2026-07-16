from __future__ import annotations

import sys

from hermes_vault import _platform, dpapi


class _RealShapeWin32Crypt:
    @staticmethod
    def CryptUnprotectData(data, optional_entropy, reserved, prompt_struct, flags):
        assert optional_entropy is None
        assert reserved is None
        assert prompt_struct is None
        assert flags == 0
        return ("Hermes Vault", bytes(data))


def test_unprotect_master_key_normalizes_real_pywin32_tuple(monkeypatch) -> None:
    monkeypatch.setattr(_platform, "dpapi_available", lambda: True)
    monkeypatch.setitem(sys.modules, "win32crypt", _RealShapeWin32Crypt)

    plaintext = b"x" * 32
    envelope = dpapi.DPAPI_HEADER + plaintext

    assert dpapi.unprotect_master_key(envelope) == plaintext
