"""Canonical service ID registry for Hermes Vault.

Every service referenced by vault, broker, policy, detector, verifier, and
CLI flows passes through this module.  The canonical ID is the **single
source of truth** for how a service is named across the system.

Design decisions
----------------
* Canonical IDs are lowercase, hyphenated where needed (e.g. ``minimax``).
* Legacy / drifted aliases are mapped to canonical IDs via ``ALIASES``.
* ``normalize()`` is the single entry-point -- always call it before storage
  or lookup.
* Unknown service names are **not** rejected outright -- custom services
  (e.g. internal tools) may legitimately appear in policies.  They are
  returned as-is after lowering/trimming.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical IDs
# ---------------------------------------------------------------------------

CANONICAL_IDS: frozenset[str] = frozenset(
    {
        "anthropic",
        "bailian",
        "brave-search",
        "cloudflare",
        "commandcode",
        "crof-ai",
        "deepseek",
        "elevenlabs",
        "evolink",
        "fal",
        "fireworks",
        "gemini",
        "generic",
        "github",
        "google",
        "groq",
        "huggingface",
        "inception",
        "kilocode",
        "kimi",
        "kimi-coding",
        "minimax",
        "mistral",
        "nahcrof-dedicated",
        "netlify",
        "neuralwatt",
        "ninerouter",
        "openai",
        "openrouter",
        "perplexity",
        "replicate",
        "resend",
        "serpapi",
        "serper",
        "supabase",
        "synthetic",
        "tavily",
        "telegram",
        "trinity",
        "venice",
        "vercel",
        "voyage",
        "xai",
        "xiaomi",
        "zai",
    }
)

# ---------------------------------------------------------------------------
# Legacy alias -> canonical ID mapping
#
# Add entries whenever a drifted or legacy name is discovered in the wild.
# The key must be **lower-cased** (normalise before lookup).
# ---------------------------------------------------------------------------

ALIASES: dict[str, str] = {
    # common drift
    "open_ai": "openai",
    "open-ai": "openai",
    "gh": "github",
    "github_pat": "github",
    "anthropic_ai": "anthropic",
    "evo_link": "evolink",
    "evo-link": "evolink",
    # google product names that map to the google service
    "gmail": "google",
    "google_docs": "google",
    "google_drive": "google",
    "google_oauth": "google",
    # minimax variants
    "mini_max": "minimax",
    "mini-max": "minimax",
    # supabase variants
    "supa": "supabase",
    "supabase_db": "supabase",
    # common AI/dev service drift
    "hf": "huggingface",
    "huggingface_hub": "huggingface",
    "huggingface-hub": "huggingface",
    "brave_search": "brave-search",
    "brave": "brave-search",
    "cloudflare_api": "cloudflare",
    "cloudflare-api": "cloudflare",
    "x_ai": "xai",
    "x-ai": "xai",
    # generic aliases
    "bearer": "generic",
    "token": "generic",
}


def normalize(service: str) -> str:
    """Return the canonical service ID for *service*.

    Rules (applied in order):
    1. Strip and lower-case the input.
    2. If the result is in ``ALIASES``, return the mapped canonical ID.
    3. If the result is already a canonical ID, return it as-is.
    4. Otherwise return the cleaned string unchanged (custom service).
    """
    cleaned = service.strip().lower()
    if cleaned in ALIASES:
        return ALIASES[cleaned]
    return cleaned


def is_canonical(service: str) -> bool:
    """Return True if *service* is a known canonical ID."""
    return service.strip().lower() in CANONICAL_IDS


def get_env_var_map(service: str) -> dict[str, str]:
    """Return the environment-variable template for a canonical service.

    Unknown services get the generic ``HERMES_VAULT_SECRET`` mapping.
    """
    mapping: dict[str, dict[str, str]] = {
        "openai": {"OPENAI_API_KEY": "{secret}"},
        "anthropic": {"ANTHROPIC_API_KEY": "{secret}"},
        "github": {"GITHUB_TOKEN": "{secret}", "GH_TOKEN": "{secret}"},
        "google": {"GOOGLE_OAUTH_ACCESS_TOKEN": "{secret}", "GOOGLE_API_KEY": "{secret}"},
        "minimax": {"MINIMAX_API_KEY": "{secret}"},
        "supabase": {"SUPABASE_ACCESS_TOKEN": "{secret}"},
        "telegram": {"TELEGRAM_BOT_TOKEN": "{secret}"},
        "netlify": {"NETLIFY_AUTH_TOKEN": "{secret}"},
        "openrouter": {"OPENROUTER_API_KEY": "{secret}"},
        "fal": {"FAL_KEY": "{secret}", "FAL_API_KEY": "{secret}"},
        "replicate": {"REPLICATE_API_TOKEN": "{secret}"},
        "elevenlabs": {"ELEVENLABS_API_KEY": "{secret}"},
        "evolink": {"EVOLINK_API_KEY": "{secret}"},
        "resend": {"RESEND_API_KEY": "{secret}"},
        "tavily": {"TAVILY_API_KEY": "{secret}"},
        "brave-search": {"BRAVE_SEARCH_API_KEY": "{secret}"},
        "cloudflare": {"CLOUDFLARE_API_TOKEN": "{secret}"},
        "vercel": {"VERCEL_TOKEN": "{secret}"},
        "huggingface": {"HF_TOKEN": "{secret}", "HUGGINGFACE_HUB_TOKEN": "{secret}"},
        "groq": {"GROQ_API_KEY": "{secret}"},
        "xai": {"XAI_API_KEY": "{secret}"},
        "gemini": {"GEMINI_API_KEY": "{secret}"},
        "perplexity": {"PERPLEXITY_API_KEY": "{secret}"},
        "serpapi": {"SERPAPI_API_KEY": "{secret}"},
        "deepseek": {"DEEPSEEK_API_KEY": "{secret}"},
        "fireworks": {"FIREWORKS_API_KEY": "{secret}"},
        "commandcode": {"COMMANDCODE_API_KEY": "{secret}"},
        "inception": {"INCEPTION_API_KEY": "{secret}"},
        "kilocode": {"KILOCODE_API_KEY": "{secret}"},
        "kimi": {"KIMI_API_KEY": "{secret}"},
        "kimi-coding": {"KIMI_CODING_API_KEY": "{secret}"},
        "nahcrof-dedicated": {"NAHCROF_DEDICATED_API_KEY": "{secret}"},
        "neuralwatt": {"NEURALWATT_API_KEY": "{secret}"},
        "synthetic": {"SYNTHETIC_API_KEY": "{secret}"},
        "trinity": {"TRINITY_API_KEY": "{secret}"},
        "venice": {"VENICE_API_KEY": "{secret}"},
        "xiaomi": {"XIAOMI_API_KEY": "{secret}"},
        "zai": {"ZAI_API_KEY": "{secret}"},
        "crof-ai": {"CROF_AI_API_KEY": "{secret}"},
        "voyage": {"VOYAGE_API_KEY": "{secret}"},
        "mistral": {"MISTRAL_API_KEY": "{secret}"},
        "serper": {"SERPER_API_KEY": "{secret}"},
        "bailian": {"BAILIAN_API_KEY": "{secret}"},
        "ninerouter": {"NINEROUTER_API_KEY": "{secret}"},
    }
    return mapping.get(service, {"HERMES_VAULT_SECRET": "{secret}"})
