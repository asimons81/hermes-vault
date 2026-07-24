"""Bulk import and export operations for Hermes Vault.

CSV, JSON, and .env import plus filtered credential export.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from hermes_vault.models import CredentialRecord
from hermes_vault.service_ids import normalize
from hermes_vault.vault import Vault


# ── CSV Import ────────────────────────────────────────────────────────

def parse_csv(source: Path | str, *, service_column: str = "service", secret_column: str = "secret",
              alias_column: str | None = "alias", tag_column: str | None = None) -> list[dict[str, str]]:
    """Parse a CSV file into credential rows."""
    path = Path(source) if isinstance(source, str) else source
    content = path.read_text(encoding="utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        raise ValueError("CSV has no header row")
    rows: list[dict[str, str]] = []
    for row in reader:
        svc = normalize(row.get(service_column, "").strip())
        secret = row.get(secret_column, "").strip()
        if not svc or not secret:
            continue  # skip empty rows
        entry: dict[str, str] = {"service": svc, "secret": secret}
        if alias_column and row.get(alias_column, "").strip():
            entry["alias"] = row[alias_column].strip()
        if tag_column and row.get(tag_column, "").strip():
            entry["tags_csv"] = row[tag_column].strip()
        rows.append(entry)
    return rows


# ── .env Import ───────────────────────────────────────────────────────

def parse_env(source: Path | str) -> list[dict[str, str]]:
    """Parse a .env file into credential rows using known env var maps."""
    path = Path(source) if isinstance(source, str) else source
    entries: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not value or value.startswith("${"):
            continue
        service = _guess_service_from_env_var(key)
        if service:
            entries.append({"service": service, "secret": value, "env_var": key})
    return entries


def _guess_service_from_env_var(env_name: str) -> str | None:
    """Map a known env var name to a canonical service ID."""
    name = env_name.upper().replace("-", "_").replace(".", "_")
    # Direct mappings
    known: dict[str, str] = {
        "OPENAI_API_KEY": "openai",
        "ANTHROPIC_API_KEY": "anthropic",
        "GITHUB_TOKEN": "github",
        "GH_TOKEN": "github",
        "GOOGLE_API_KEY": "google",
        "GOOGLE_OAUTH_ACCESS_TOKEN": "google",
        "XAI_API_KEY": "xai",
        "GROQ_API_KEY": "groq",
        "MISTRAL_API_KEY": "mistral",
        "DEEPSEEK_API_KEY": "deepseek",
        "PERPLEXITY_API_KEY": "perplexity",
        "GEMINI_API_KEY": "gemini",
        "FIREWORKS_API_KEY": "fireworks",
        "ELEVENLABS_API_KEY": "elevenlabs",
        "FAL_KEY": "fal",
        "FAL_API_KEY": "fal",
        "REPLICATE_API_TOKEN": "replicate",
        "RESEND_API_KEY": "resend",
        "TAVILY_API_KEY": "tavily",
        "BRAVE_SEARCH_API_KEY": "brave-search",
        "CLOUDFLARE_API_TOKEN": "cloudflare",
        "VERCEL_TOKEN": "vercel",
        "NETLIFY_AUTH_TOKEN": "netlify",
        "HUGGINGFACE_HUB_TOKEN": "huggingface",
        "HF_TOKEN": "huggingface",
        "SERPAPI_API_KEY": "serpapi",
        "SERPER_API_KEY": "serper",
        "SUPABASE_ACCESS_TOKEN": "supabase",
        "OPENROUTER_API_KEY": "openrouter",
        "VOYAGE_API_KEY": "voyage",
        "TELEGRAM_BOT_TOKEN": "telegram",
        "EVOLINK_API_KEY": "evolink",
        "MINIMAX_API_KEY": "minimax",
        "KIMI_API_KEY": "kimi",
        "KIMI_CODING_API_KEY": "kimi-coding",
        "MOONSHOT_API_KEY": "kimi",
        "VENICE_API_KEY": "venice",
        "SYNTHETIC_API_KEY": "synthetic",
        "TRINITY_API_KEY": "trinity",
        "XIAOMI_API_KEY": "xiaomi",
        "ZAI_API_KEY": "zai",
        "CROF_AI_API_KEY": "crof-ai",
        "BAILIAN_API_KEY": "bailian",
        "NINEROUTER_API_KEY": "ninerouter",
        "COMMANDCODE_API_KEY": "commandcode",
        "KILOCODE_API_KEY": "kilocode",
        "NEURALWATT_API_KEY": "neuralwatt",
        "NAHCROF_DEDICATED_API_KEY": "nahcrof-dedicated",
        "INCEPTION_API_KEY": "inception",
    }
    return known.get(name)


# ── JSON Import ───────────────────────────────────────────────────────

def parse_json_backup(source: Path | str) -> list[dict[str, Any]]:
    """Parse a JSON backup/export file into credential rows."""
    path = Path(source) if isinstance(source, str) else source
    data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if isinstance(data, dict) and "credentials" in data:
        return data["credentials"]
    if isinstance(data, list):
        return data
    raise ValueError("Unrecognized JSON format. Expected a list of credentials or object with 'credentials' key.")


# ── Export ────────────────────────────────────────────────────────────

def export_credentials(
    records: list[CredentialRecord],
    *,
    fmt: str = "json",
    include_secrets: bool = False,
    vault: Vault | None = None,
) -> str:
    """Export credentials in the requested format."""
    if fmt == "json":
        out = []
        for r in records:
            entry: dict[str, Any] = {
                "id": r.id,
                "service": r.service,
                "alias": r.alias,
                "credential_type": r.credential_type,
                "status": r.status.value,
                "tags": r.tags,
                "notes": r.notes,
                "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat(),
                "last_verified_at": r.last_verified_at.isoformat() if r.last_verified_at else None,
                "expiry": r.expiry.isoformat() if r.expiry else None,
            }
            if include_secrets and vault is not None:
                try:
                    cs = vault.get_secret(r.id)
                    if cs:
                        entry["secret"] = cs.secret
                except Exception:
                    entry["secret"] = None
            out.append(entry)
        return json.dumps(out, indent=2, sort_keys=True)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "service", "alias", "credential_type", "status", "tags", "notes",
            "created_at", "last_verified_at", "expiry",
        ])
        writer.writeheader()
        for r in records:
            writer.writerow({
                "service": r.service,
                "alias": r.alias,
                "credential_type": r.credential_type,
                "status": r.status.value,
                "tags": ",".join(r.tags),
                "notes": r.notes or "",
                "created_at": r.created_at.isoformat(),
                "last_verified_at": r.last_verified_at.isoformat() if r.last_verified_at else "",
                "expiry": r.expiry.isoformat() if r.expiry else "",
            })
        return buf.getvalue()

    if fmt == "env":
        lines = []
        for r in records:
            if include_secrets and vault is not None:
                try:
                    cs = vault.get_secret(r.id)
                    secret = cs.secret if cs else ""
                except Exception:
                    secret = ""
            else:
                secret = "REDACTED_USE_EXPORT_WITH_SECRETS"
            env_key = _service_to_env_var(r.service)
            alias_suffix = f"_{r.alias.upper()}" if r.alias and r.alias != "default" else ""
            lines.append(f"# {r.service} ({r.alias})")
            lines.append(f'{env_key}{alias_suffix}={secret}')
            lines.append("")
        return "\n".join(lines)

    raise ValueError(f"Unknown export format: {fmt}")


def _service_to_env_var(service: str) -> str:
    """Map a service ID to its primary env var name."""
    from hermes_vault.service_ids import get_env_var_map, is_canonical
    mapping = get_env_var_map(service)
    if mapping and is_canonical(service):
        for key in sorted(mapping.keys()):
            if not key.startswith("HERMES_"):
                return key
        return next(iter(mapping.keys()))
    return f"{service.upper().replace('-', '_')}_KEY"


# ── Tag Management ────────────────────────────────────────────────────

def set_tags(vault: Vault, credential_id: str, tags: list[str]) -> bool:
    """Set tags on a credential, normalizing and deduplicating."""
    normalized = vault._normalize_tags(tags)
    try:
        conn = vault.db_path
        import sqlite3, json as _json
        with sqlite3.connect(conn) as c:
            c.execute(
                "UPDATE credentials SET tags = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (_json.dumps(normalized), credential_id),
            )
            return True
    except Exception:
        return False


def add_tags(vault: Vault, credential_id: str, tags: list[str]) -> list[str]:
    """Add tags, returning the full new tag list."""
    record = vault.get_credential(credential_id)
    if record is None:
        raise KeyError(f"Credential {credential_id} not found")
    existing = set(record.tags)
    for t in tags:
        stripped = str(t).strip()
        if stripped:
            existing.add(stripped)
    new_tags = sorted(existing)
    set_tags(vault, credential_id, new_tags)
    return new_tags


def remove_tags(vault: Vault, credential_id: str, tags: list[str]) -> list[str]:
    """Remove tags, returning the full new tag list."""
    record = vault.get_credential(credential_id)
    if record is None:
        raise KeyError(f"Credential {credential_id} not found")
    removal = {str(t).strip() for t in tags}
    new_tags = sorted(set(record.tags) - removal)
    set_tags(vault, credential_id, new_tags)
    return new_tags


def list_credentials_by_tag(vault: Vault, tag: str) -> list[CredentialRecord]:
    """List all credentials containing a specific tag."""
    return [r for r in vault.list_credentials() if tag in r.tags]


def list_credentials_by_service(vault: Vault, service: str) -> list[CredentialRecord]:
    """List all credentials for a normalized service."""
    svc = normalize(service)
    return [r for r in vault.list_credentials() if r.service == svc]


def list_unverified_credentials(vault: Vault) -> list[CredentialRecord]:
    """List all credentials that have never been verified."""
    return [r for r in vault.list_credentials() if r.last_verified_at is None]
