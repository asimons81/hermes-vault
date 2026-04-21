from __future__ import annotations

from hermes_vault.service_ids import (
    ALIASES,
    CANONICAL_IDS,
    get_env_var_map,
    is_canonical,
    normalize,
)


def test_normalize_passes_through_canonical_ids() -> None:
    for sid in CANONICAL_IDS:
        assert normalize(sid) == sid


def test_normalize_maps_known_aliases() -> None:
    assert normalize("open_ai") == "openai"
    assert normalize("open-ai") == "openai"
    assert normalize("gh") == "github"
    assert normalize("gmail") == "google"
    assert normalize("google_docs") == "google"
    assert normalize("google_drive") == "google"
    assert normalize("mini_max") == "minimax"
    assert normalize("mini-max") == "minimax"
    assert normalize("supa") == "supabase"


def test_normalize_is_case_insensitive() -> None:
    assert normalize("OpenAI") == "openai"
    assert normalize("GITHUB") == "github"
    assert normalize("Google_Docs") == "google"


def test_normalize_strips_whitespace() -> None:
    assert normalize("  openai  ") == "openai"
    assert normalize("\tgithub\n") == "github"


def test_normalize_preserves_unknown_custom_services() -> None:
    assert normalize("my_custom_api") == "my_custom_api"
    assert normalize("internal-tool") == "internal-tool"


def test_is_canonical_recognizes_known_ids() -> None:
    assert is_canonical("openai") is True
    assert is_canonical("github") is True
    assert is_canonical("google") is True


def test_is_canonical_rejects_unknown() -> None:
    assert is_canonical("my_custom_api") is False
    assert is_canonical("gmail") is False  # alias, not canonical


def test_get_env_var_map_known_service() -> None:
    m = get_env_var_map("openai")
    assert "OPENAI_API_KEY" in m
    assert m["OPENAI_API_KEY"] == "{secret}"


def test_get_env_var_map_github_has_both_tokens() -> None:
    m = get_env_var_map("github")
    assert "GITHUB_TOKEN" in m
    assert "GH_TOKEN" in m


def test_get_env_var_map_unknown_falls_back_to_generic() -> None:
    m = get_env_var_map("my_custom_api")
    assert "HERMES_VAULT_SECRET" in m


def test_all_aliases_point_to_canonical_ids() -> None:
    for alias, canonical in ALIASES.items():
        assert canonical in CANONICAL_IDS, f"Alias '{alias}' maps to non-canonical '{canonical}'"
