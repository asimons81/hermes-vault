from __future__ import annotations

import pytest

from hermes_vault.detectors import classify_env_name, guess_from_env_name, parse_env_map


REQUIRED_HINTS = {
    "OPENROUTER_API_KEY": ("openrouter", "api_key"),
    "FAL_KEY": ("fal", "api_key"),
    "FAL_API_KEY": ("fal", "api_key"),
    "REPLICATE_API_TOKEN": ("replicate", "personal_access_token"),
    "ELEVENLABS_API_KEY": ("elevenlabs", "api_key"),
    "RESEND_API_KEY": ("resend", "api_key"),
    "TAVILY_API_KEY": ("tavily", "api_key"),
    "BRAVE_SEARCH_API_KEY": ("brave-search", "api_key"),
    "CLOUDFLARE_API_TOKEN": ("cloudflare", "personal_access_token"),
    "VERCEL_TOKEN": ("vercel", "personal_access_token"),
    "HF_TOKEN": ("huggingface", "personal_access_token"),
    "HUGGINGFACE_HUB_TOKEN": ("huggingface", "personal_access_token"),
    "GROQ_API_KEY": ("groq", "api_key"),
    "XAI_API_KEY": ("xai", "api_key"),
    "GEMINI_API_KEY": ("gemini", "api_key"),
    "GOOGLE_API_KEY": ("google", "api_key"),
    "PERPLEXITY_API_KEY": ("perplexity", "api_key"),
    "SERPAPI_API_KEY": ("serpapi", "api_key"),
}


def test_exact_new_env_hints() -> None:
    for name, expected in REQUIRED_HINTS.items():
        decision = classify_env_name(name)
        assert decision.action == "import"
        assert (decision.service, decision.credential_type) == expected
        assert decision.source == "hint"


def test_suffix_inference_api_key() -> None:
    decision = classify_env_name("MY_VENDOR_API_KEY")
    assert decision.action == "import"
    assert decision.service == "my-vendor"
    assert decision.credential_type == "api_key"


def test_suffix_inference_token() -> None:
    decision = classify_env_name("MY_VENDOR_TOKEN")
    assert decision.action == "import"
    assert decision.service == "my-vendor"
    assert decision.credential_type == "personal_access_token"


def test_suffix_inference_auth_token() -> None:
    decision = classify_env_name("MY_VENDOR_AUTH_TOKEN")
    assert decision.action == "import"
    assert decision.service == "my-vendor"
    assert decision.credential_type == "personal_access_token"


def test_suffix_inference_access_token() -> None:
    decision = classify_env_name("MY_VENDOR_ACCESS_TOKEN")
    assert decision.action == "import"
    assert decision.service == "my-vendor"
    assert decision.credential_type == "oauth_access_token"


def test_next_public_is_skipped() -> None:
    decision = classify_env_name("NEXT_PUBLIC_API_KEY")
    assert decision.action == "skip"
    assert "public" in decision.reason


def test_database_urls_and_passwords_skip_with_map_hint() -> None:
    for name in ["DATABASE_URL", "APP_DATABASE_URL", "DB_URL", "APP_DB_URL", "PASSWORD", "APP_PASSWORD", "JWT_SECRET", "SESSION_SECRET"]:
        decision = classify_env_name(name)
        assert decision.action == "skip"
        assert "--map" in decision.reason


def test_unknown_name_skip_has_reason() -> None:
    decision = classify_env_name("SOMETHING_ELSE")
    assert decision.action == "skip"
    assert "--map" in decision.reason


def test_guess_from_env_name_backcompat() -> None:
    assert guess_from_env_name("OPENROUTER_API_KEY") == ("openrouter", "api_key")
    assert guess_from_env_name("NEXT_PUBLIC_API_KEY") is None


def test_parse_env_map_valid() -> None:
    assert parse_env_map("CUSTOM_VENDOR_TOKEN=custom-vendor:personal_access_token") == (
        "CUSTOM_VENDOR_TOKEN",
        "custom-vendor",
        "personal_access_token",
    )
    assert parse_env_map("hf_token=hf:personal_access_token") == (
        "HF_TOKEN",
        "huggingface",
        "personal_access_token",
    )


@pytest.mark.parametrize("value", ["NOPE", "=svc:type", "KEY=svc", "KEY=:type", "KEY=svc:"])
def test_parse_env_map_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        parse_env_map(value)
