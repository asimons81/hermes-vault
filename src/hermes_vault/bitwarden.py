"""Bitwarden export import bridge.

Parses an unencrypted ``bw export --format json`` vault export and maps it
onto Hermes Vault credentials with a dry-run preview, an explicit apply, a
deterministic collision policy, and a summary audit event.

Design constraints (v0.26.0 P9):

* **No secret ever reaches stdout.** Previews show service/alias/type/origin
  and skip reasons only. The export file itself is plaintext — the CLI warns
  loudly and the docs tell operators to delete it after import.
* **Dry-run requires no passphrase and no vault.** Parsing and planning are
  pure functions over the export file.
* **Apply goes through ``VaultMutations.add_credential``** — the single
  audited, policy-checked write path — with ``imported_from="bitwarden"``
  provenance and one summary ``import_bitwarden`` audit event.
* **Collision policy is deterministic and previewable:** ``skip`` (default),
  ``rename``, or ``fail`` — decided before the first vault write so a dry-run
  preview exactly predicts the apply.

Mapping rules
-------------

* ``folders`` become a lowercase slug prefix on the service name
  (``Work/GitHub`` → ``work-github``). Vault has no folder concept; the
  prefix preserves the grouping and keeps per-folder policy possible.
* Login items (type 1) with a non-empty password become credentials. The
  secret is the password; the username becomes the alias (``default`` when
  absent, slugified otherwise, de-duplicated within the import).
* TOTP seeds are appended to the secret as ``<password>\ntotp:<seed>`` so the
  single-secret model never silently drops the second factor. Documented in
  docs/bitwarden-comparison.md; ``otpauth://`` URIs are passed through whole.
* Custom fields become encrypted secret metadata (they ride inside the
  encrypted payload, not the plaintext notes column).
* Item notes become plaintext vault notes (same tradeoff as ``import
  --from-env --notes``: notes are queryable metadata, not secret material).
* Secure-note items (type 2) with non-empty notes become credentials whose
  secret is the note body (service slug from the item name).
* Card (3) and identity (4) items are counted and skipped with a reason —
  they have no machine-usable secret for an agent vault.
* Logins without passwords are skipped with reasons. Nothing is silently
  dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_vault.detectors import detect_matches
from hermes_vault.service_ids import normalize

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(value: str) -> str:
    """Lowercase slug: collapse non-alphanumerics to single hyphens."""
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return re.sub(r"-{2,}", "-", slug)


# ── Export parsing ─────────────────────────────────────────────────────


class BitwardenExportError(ValueError):
    """The file is not a recognizable unencrypted ``bw export`` JSON."""


def load_bitwarden_export(source: Path | str) -> dict[str, Any]:
    """Load and structurally validate an unencrypted Bitwarden JSON export.

    Raises ``BitwardenExportError`` with an actionable message on anything
    that is not the documented ``bw export --format json`` shape.
    """
    path = Path(source) if isinstance(source, str) else source
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError as exc:
        raise BitwardenExportError(
            f"could not parse {path} as JSON: {exc}. "
            "Produce the file with `bw export --format json` (unencrypted)."
        ) from exc
    if not isinstance(data, dict) or "items" not in data or not isinstance(data["items"], list):
        raise BitwardenExportError(
            f"{path} is not a Bitwarden JSON export: expected a JSON object with an 'items' list. "
            "Produce the file with `bw export --format json`."
        )
    if data.get("encrypted") is True or any(not isinstance(i, dict) for i in data["items"]):
        raise BitwardenExportError(
            f"{path} is an ENCRYPTED Bitwarden export — the import bridge only reads the "
            "unencrypted `bw export --format json` format. Re-export choosing the plaintext "
            "JSON option (never store or sync the plaintext file)."
        )
    return data


def _first_uri(login: dict[str, Any]) -> str | None:
    for entry in login.get("uris") or []:
        if isinstance(entry, dict) and entry.get("uri"):
            return str(entry["uri"])
    return None


def _host_service(uri: str) -> str | None:
    """Derive a service slug from a login URI host."""
    try:
        from urllib.parse import urlparse

        host = urlparse(uri).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().removeprefix("www.")
    if not host:
        return None
    # keep the registrable domain (last two labels) — api.github.com → github
    labels = host.split(".")
    return labels[-2] if len(labels) >= 2 else labels[0]


# ── Planned credentials ────────────────────────────────────────────────


@dataclass
class PlannedCredential:
    """One credential the importer intends to write (or would write)."""

    service: str
    alias: str
    secret: str
    credential_type: str = "api_key"
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    origin: str = ""
    item_name: str = ""

    def describe(self) -> str:
        origin = f" [{self.origin}]" if self.origin else ""
        return f"{self.service}:{self.alias} ({self.credential_type}){origin}"


@dataclass
class SkipRecord:
    item_name: str
    reason: str


@dataclass
class BitwardenPlan:
    """Parse + plan result — everything a dry-run needs, no vault required."""

    planned: list[PlannedCredential] = field(default_factory=list)
    skipped: list[SkipRecord] = field(default_factory=list)
    folders: int = 0
    items_seen: int = 0

    @property
    def importable_count(self) -> int:
        return len(self.planned)


# ── Service/alias resolution ───────────────────────────────────────────


def _service_for_login(item: dict[str, Any]) -> str | None:
    """Best-effort service ID for a login item.

    Order: item name → URI host → ``generic``. The name wins because humans
    name Bitwarden entries after the service (``GitHub``, ``OpenAI API``)
    while URIs are often SSO portals that don't identify the API service.
    """
    name = str(item.get("name") or "").strip()
    if name:
        candidate = normalize(_slug(name))
        # A name like "GitHub" or "OpenAI API" → github / openai-api. Use it
        # when the slug matches a canonical ID or alias target; otherwise
        # fall through to the URI hint.
        if candidate in _canonical_or_alias_targets():
            return candidate
    uri = _first_uri(item.get("login") or {})
    if uri:
        host_service = _host_service(uri)
        if host_service:
            mapped = normalize(host_service)
            if mapped in _canonical_or_alias_targets():
                return mapped
            return mapped  # custom service from a concrete hostname
    if name:
        return normalize(_slug(name))  # custom service from the item name
    return None


_canonical_targets_cache: frozenset[str] | None = None


def _canonical_or_alias_targets() -> frozenset[str]:
    global _canonical_targets_cache
    if _canonical_targets_cache is None:
        from hermes_vault.service_ids import ALIASES, CANONICAL_IDS

        _canonical_targets_cache = frozenset(set(CANONICAL_IDS) | set(ALIASES.values()))
    return _canonical_targets_cache


def _alias_for_login(item: dict[str, Any]) -> str:
    username = str((item.get("login") or {}).get("username") or "").strip()
    return _slug(username) if username else "default"


class _AliasUniquifier:
    """De-duplicate aliases within one import (vault scope is service+alias)."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    def unique(self, service: str, alias: str) -> str:
        if (service, alias) not in self._seen:
            self._seen.add((service, alias))
            return alias
        base = alias or "default"
        n = 2
        while (service, f"{base}-{n}") in self._seen:
            n += 1
        unique = f"{base}-{n}"
        self._seen.add((service, unique))
        return unique


# ── Planning ───────────────────────────────────────────────────────────


def plan_bitwarden_import(data: dict[str, Any]) -> BitwardenPlan:
    """Map a parsed Bitwarden export onto planned credentials + skips.

    Pure: no vault, no passphrase, no writes.
    """
    plan = BitwardenPlan(folders=len(data.get("folders") or []))
    folder_names = {
        str(f.get("id")): str(f.get("name") or "") for f in (data.get("folders") or []) if isinstance(f, dict)
    }
    uniquifier = _AliasUniquifier()

    for item in data["items"]:
        if not isinstance(item, dict):
            continue
        plan.items_seen += 1
        name = str(item.get("name") or "").strip() or "(unnamed item)"
        itype = item.get("type")
        folder = folder_names.get(str(item.get("folderId") or ""))
        prefix = _slug(folder) + "-" if folder and _slug(folder) else ""

        if itype == 1:  # login
            login = item.get("login") or {}
            if not isinstance(login, dict):
                login = {}
            password = str(login.get("password") or "")
            if not password:
                plan.skipped.append(SkipRecord(name, "login has no password"))
                continue
            service = _service_for_login(item)
            if service is None:
                plan.skipped.append(SkipRecord(name, "could not derive a service name"))
                continue
            service = normalize(f"{prefix}{service}")
            alias = uniquifier.unique(service, _alias_for_login(item))
            secret = password
            totp = str(login.get("totp") or "").strip()
            if totp:
                seed = totp if totp.startswith("otpauth://") else f"otpauth://totp/{name}?secret={totp}"
                secret = f"{password}\ntotp:{seed}"
            fields = _custom_fields(item)
            notes = _notes(item)
            credential_type = _credential_type_for(password, service)
            plan.planned.append(PlannedCredential(
                service=service,
                alias=alias,
                secret=secret,
                credential_type=credential_type,
                notes=notes,
                metadata=fields,
                origin="login",
                item_name=name,
            ))
        elif itype == 2:  # secure note
            notes = _notes(item)
            if not notes:
                plan.skipped.append(SkipRecord(name, "secure note is empty"))
                continue
            service = normalize(f"{prefix}{_slug(name)}") or "imported-note"
            alias = uniquifier.unique(service, "default")
            plan.planned.append(PlannedCredential(
                service=service,
                alias=alias,
                secret=notes,
                credential_type="note",
                notes=None,
                metadata={},
                origin="secure-note",
                item_name=name,
            ))
        elif itype == 3:
            plan.skipped.append(SkipRecord(name, "card items are not importable (no machine-usable secret)"))
        elif itype == 4:
            plan.skipped.append(SkipRecord(name, "identity items are not importable (no machine-usable secret)"))
        else:
            plan.skipped.append(SkipRecord(name, f"unknown Bitwarden item type {itype!r}"))

    return plan


def _custom_fields(item: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for f in item.get("fields") or []:
        if not isinstance(f, dict):
            continue
        key = str(f.get("name") or "").strip()
        if not key:
            continue
        ftype = f.get("type")
        # Bitwarden field types: 0=text, 1=hidden, 2=boolean, 3=linked.
        # Hidden and text values ride in encrypted metadata; booleans are
        # stringified; linked fields (no value in exports) are skipped.
        if ftype == 3:
            continue
        value = f.get("value")
        if value is None:
            continue
        fields[key] = value if isinstance(value, bool) else str(value)
    return fields


def _notes(item: dict[str, Any]) -> str | None:
    notes = str(item.get("notes") or "").strip()
    return notes or None


def _credential_type_for(secret: str, service: str) -> str:
    """Classify the secret shape when a detector recognizes it."""
    matches = detect_matches(secret)
    for detector, _match in matches:
        if detector.service == service:
            return detector.credential_type
    return "password"


# ── Collision handling ─────────────────────────────────────────────────


@dataclass
class CollisionRecord:
    service: str
    alias: str
    action: str  # "skip" | "rename" | "fail"


@dataclass
class ApplyPlan:
    """Planned writes after collision resolution against the live vault."""

    to_write: list[PlannedCredential] = field(default_factory=list)
    collisions: list[CollisionRecord] = field(default_factory=list)


def resolve_collisions(
    plan: BitwardenPlan,
    existing_pairs: set[tuple[str, str]],
    policy: str,
) -> ApplyPlan:
    """Resolve service+alias collisions against the vault's existing pairs.

    ``policy`` is one of ``skip`` (default; keep the vault row), ``rename``
    (import under a suffixed alias), or ``fail`` (abort with a non-zero
    exit before any write).
    """
    if policy not in ("skip", "rename", "fail"):
        raise ValueError(f"unknown collision policy: {policy!r} (expected skip, rename, or fail)")
    result = ApplyPlan()
    taken = set(existing_pairs)
    for cred in plan.planned:
        if (cred.service, cred.alias) not in taken:
            result.to_write.append(cred)
            taken.add((cred.service, cred.alias))
            continue
        if policy == "fail":
            result.collisions.append(CollisionRecord(cred.service, cred.alias, "fail"))
        elif policy == "rename":
            base = cred.alias or "default"
            n = 2
            while (cred.service, f"{base}-bw{n}") in taken:
                n += 1
            cred.alias = f"{base}-bw{n}"
            result.collisions.append(CollisionRecord(cred.service, cred.alias, "rename"))
            result.to_write.append(cred)
            taken.add((cred.service, cred.alias))
        else:  # skip
            result.collisions.append(CollisionRecord(cred.service, cred.alias, "skip"))
    return result
