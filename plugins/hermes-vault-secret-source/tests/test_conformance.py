from __future__ import annotations

import pytest

from test_plugin import FetchResult, _load_plugin, _valid_env


class SecretSourceConformance:
    @pytest.fixture
    def source(self):
        raise NotImplementedError

    @pytest.fixture
    def minimal_cfg(self):
        return {"enabled": True}

    def test_name_is_lowercase_identifier(self, source):
        assert source.name
        assert source.name == source.name.lower()
        assert source.name.replace("_", "").isalnum()

    def test_label_present(self, source):
        assert source.label

    def test_shape_valid(self, source):
        assert source.shape in ("mapped", "bulk")

    def test_fetch_never_raises_on_malformed_config(self, source, tmp_path):
        for cfg in ({}, {"enabled": True}, {"enabled": True, "env": "not-a-dict"}, None):
            result = source.fetch(cfg if isinstance(cfg, dict) else {}, tmp_path)
            assert isinstance(result, FetchResult)

    def test_fetch_unconfigured_reports_error_not_secrets(self, source, tmp_path, minimal_cfg):
        result = source.fetch(minimal_cfg, tmp_path)
        assert isinstance(result, FetchResult)
        if not result.ok:
            assert result.error_kind is not None
            assert not result.secrets

    def test_disabled_by_default(self, source):
        assert source.is_enabled({}) is False
        assert source.is_enabled({"enabled": False}) is False

    def test_timeout_is_positive(self, source, minimal_cfg):
        assert source.fetch_timeout_seconds(minimal_cfg) > 0

    def test_protected_vars_are_valid_names(self, source, minimal_cfg):
        for var in source.protected_env_vars(minimal_cfg):
            assert _valid_env(var)


class TestHermesVaultConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        plugin = _load_plugin()
        return plugin.HermesVaultSource()
