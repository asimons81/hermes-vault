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

# Map env-var names → (canonical_service, credential_type).
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
}


def detect_matches(text: str) -> list[tuple[DetectorPattern, str]]:
    findings: list[tuple[DetectorPattern, str]] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            secret = match.group(1) if match.lastindex else match.group(0)
            findings.append((detector, secret))
    return findings


def guess_from_env_name(name: str) -> tuple[str, str] | None:
    """Look up canonical (service, credential_type) from an env-var name."""
    hint = ENV_NAME_HINTS.get(name.strip().upper())
    if hint is None:
        return None
    # service in ENV_NAME_HINTS is already canonical — normalize defensively
    return normalize(hint[0]), hint[1]


def fingerprint_secret(secret: str) -> str:
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    return digest[:16]
