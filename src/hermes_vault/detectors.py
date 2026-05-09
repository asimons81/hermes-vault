from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from hermes_vault.service_ids import normalize


@dataclass(frozen=True)
class DetectorPattern:
    service: str
    credential_type: str
    pattern: re.Pattern[str]
    recommendation: str


@dataclass(frozen=True)
class EnvImportDecision:
    name: str
    action: str
    service: str | None = None
    credential_type: str | None = None
    reason: str = ""
    source: str = ""


DETECTORS: list[DetectorPattern] = [
    DetectorPattern(
        service="openai",
        credential_type="api_key",
        pattern=re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        recommendation="Import this OpenAI key into Hermes Vault and remove plaintext copies.",
    ),
    DetectorPattern(
        service="anthropic",
        credential_type="api_key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        recommendation="Move this Anthropic key into Hermes Vault and remove plaintext copies.",
    ),
    DetectorPattern(
        service="github",
        credential_type="personal_access_token",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        recommendation="Move this GitHub token into Hermes Vault and remove plaintext copies.",
    ),
    DetectorPattern(
        service="google",
        credential_type="oauth_access_token",
        pattern=re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b"),
        recommendation="Move this Google OAuth token into Hermes Vault and stop storing it in plaintext.",
    ),
    DetectorPattern(
        service="generic",
        credential_type="bearer_token",
        pattern=re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{20,})"),
        recommendation="Review and import this bearer token into Hermes Vault if it is active.",
    ),
]

# Map env-var names -> (canonical_service, credential_type).
# env var names are always UPPER so keys here are UPPER.
ENV_NAME_HINTS: dict[str, tuple[str, str]] = {
    "OPENAI_API_KEY": ("openai", "api_key"),
    "ANTHROPIC_API_KEY": ("anthropic", "api_key"),
    "GITHUB_TOKEN": ("github", "personal_access_token"),
    "GH_TOKEN": ("github", "personal_access_token"),
    "GOOGLE_OAUTH_ACCESS_TOKEN": ("google", "oauth_access_token"),
    "MINIMAX_API_KEY": ("minimax", "api_key"),
    "SUPABASE_ACCESS_TOKEN": ("supabase", "personal_access_token"),
    "TELEGRAM_BOT_TOKEN": ("telegram", "bot_token"),
    "NETLIFY_AUTH_TOKEN": ("netlify", "personal_access_token"),
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

PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_",)
BROAD_SECRET_EXACT_NAMES = {
    "DATABASE_URL",
    "DB_URL",
    "APP_SECRET",
    "SECRET_KEY",
    "JWT_SECRET",
    "SESSION_SECRET",
    "AUTH_SECRET",
    "PASSWORD",
}
BROAD_SECRET_SUFFIXES = (
    "_DATABASE_URL",
    "_DB_URL",
    "_PASSWORD",
    "_APP_SECRET",
    "_SECRET_KEY",
    "_JWT_SECRET",
    "_SESSION_SECRET",
    "_AUTH_SECRET",
)


def detect_matches(text: str) -> list[tuple[DetectorPattern, str]]:
    findings: list[tuple[DetectorPattern, str]] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            secret = match.group(1) if match.lastindex else match.group(0)
            findings.append((detector, secret))
    return findings


def parse_env_map(value: str) -> tuple[str, str, str]:
    """Parse ENV_NAME=service:credential_type for explicit env imports."""
    if "=" not in value:
        raise ValueError("mapping must use ENV_NAME=service:credential_type")
    env_name, target = value.split("=", 1)
    env_name = env_name.strip().upper()
    if not env_name:
        raise ValueError("mapping env name is empty")
    if ":" not in target:
        raise ValueError("mapping target must use service:credential_type")
    service, credential_type = target.split(":", 1)
    service = service.strip()
    credential_type = credential_type.strip()
    if not service:
        raise ValueError("mapping service is empty")
    if not credential_type:
        raise ValueError("mapping credential type is empty")
    return env_name, normalize(service), credential_type


def _service_from_env_stem(stem: str) -> str:
    return normalize(stem.strip("_").lower().replace("_", "-"))


def _is_public_config(name: str) -> bool:
    return name.startswith(PUBLIC_ENV_PREFIXES)


def _is_broad_secret(name: str) -> bool:
    if name in BROAD_SECRET_EXACT_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in BROAD_SECRET_SUFFIXES)


def classify_env_name(
    name: str,
    overrides: dict[str, tuple[str, str]] | None = None,
) -> EnvImportDecision:
    """Classify an env var for import or conservative skip reporting."""
    raw_name = name.strip()
    normalized_name = raw_name.upper()
    if not normalized_name:
        return EnvImportDecision(name=raw_name, action="skip", reason="malformed empty env name", source="skip")

    if overrides and normalized_name in overrides:
        service, credential_type = overrides[normalized_name]
        return EnvImportDecision(
            name=raw_name,
            action="import",
            service=normalize(service),
            credential_type=credential_type,
            reason="explicit --map override",
            source="map",
        )

    if _is_public_config(normalized_name):
        return EnvImportDecision(
            name=raw_name,
            action="skip",
            reason="public client config is not imported automatically",
            source="skip",
        )

    if _is_broad_secret(normalized_name):
        return EnvImportDecision(
            name=raw_name,
            action="skip",
            reason="broad DB/password/app secret skipped; use --map ENV=service:type if intentional",
            source="skip",
        )

    hint = ENV_NAME_HINTS.get(normalized_name)
    if hint is not None:
        return EnvImportDecision(
            name=raw_name,
            action="import",
            service=normalize(hint[0]),
            credential_type=hint[1],
            reason="matched known env name hint",
            source="hint",
        )

    suffix_rules: tuple[tuple[str, str], ...] = (
        ("_ACCESS_TOKEN", "oauth_access_token"),
        ("_AUTH_TOKEN", "personal_access_token"),
        ("_API_KEY", "api_key"),
        ("_TOKEN", "personal_access_token"),
    )
    for suffix, credential_type in suffix_rules:
        if normalized_name.endswith(suffix) and len(normalized_name) > len(suffix):
            service = _service_from_env_stem(normalized_name[: -len(suffix)])
            return EnvImportDecision(
                name=raw_name,
                action="import",
                service=service,
                credential_type=credential_type,
                reason=f"inferred from {suffix} suffix",
                source="suffix",
            )

    return EnvImportDecision(
        name=raw_name,
        action="skip",
        reason="no supported env hint or safe credential suffix matched; use --map ENV=service:type if intentional",
        source="skip",
    )


def guess_from_env_name(name: str) -> tuple[str, str] | None:
    """Look up canonical (service, credential_type) from an env-var name."""
    decision = classify_env_name(name)
    if decision.action != "import" or decision.service is None or decision.credential_type is None:
        return None
    return decision.service, decision.credential_type


def fingerprint_secret(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return digest[:16]
