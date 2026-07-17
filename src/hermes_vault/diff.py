"""Vault metadata diff — compares two backup dicts and reports credential
additions, removals, and changes.

Never exposes secrets — only metadata deltas.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiffEntry:
    kind: str  # added, removed, changed
    service: str
    alias: str
    resource_type: str = "credential"
    credential_type: str | None = None
    status: str | None = None
    lease_id: str | None = None
    agent_id: str | None = None
    changes: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "kind": self.kind,
            "service": self.service,
            "alias": self.alias,
            "resource_type": self.resource_type,
            "credential_type": self.credential_type,
            "status": self.status,
        }
        if self.lease_id is not None:
            d["lease_id"] = self.lease_id
        if self.agent_id is not None:
            d["agent_id"] = self.agent_id
        if self.changes:
            d["changes"] = self.changes
        return d


def _key(cred: dict) -> str:
    return f"{cred['service']}/{cred['alias']}"


_CHANGE_FIELDS = [
    "status",
    "credential_type",
    "expiry",
    "last_verified_at",
    "created_at",
    "updated_at",
]

_LEASE_CHANGE_FIELDS = [
    "status",
    "ttl_seconds",
    "expires_at",
]


def diff_backups(current: dict, against: dict) -> list[DiffEntry]:
    """Compare two backup dicts (encrypted or metadata-only).

    Returns a list of DiffEntry describing added, removed, and changed
    credentials. No decrypted secrets appear in the output.

    Parameters
    ----------
    current:
        The "current" backup dict (e.g. from vault.export_backup()).
    against:
        The reference backup dict to compare against.
    """
    current_by_key = {_key(c): c for c in current.get("credentials", [])}
    against_by_key = {_key(c): c for c in against.get("credentials", [])}
    current_leases = {str(lease.get("id")): lease for lease in current.get("leases", []) if lease.get("id")}
    against_leases = {str(lease.get("id")): lease for lease in against.get("leases", []) if lease.get("id")}

    entries: list[DiffEntry] = []

    for key, cred in current_by_key.items():
        if key not in against_by_key:
            entries.append(DiffEntry(
                kind="added",
                service=cred.get("service", "?"),
                alias=cred.get("alias", "?"),
                credential_type=cred.get("credential_type"),
                status=cred.get("status"),
            ))
        else:
            ref = against_by_key[key]
            changes = []
            for field in _CHANGE_FIELDS:
                if cred.get(field) != ref.get(field):
                    changes.append({
                        "field": field,
                        "from": str(ref.get(field, "-")),
                        "to": str(cred.get(field, "-")),
                    })
            if changes:
                entries.append(DiffEntry(
                    kind="changed",
                    service=cred.get("service", "?"),
                    alias=cred.get("alias", "?"),
                    credential_type=cred.get("credential_type"),
                    status=cred.get("status"),
                    changes=changes,
                ))

    for key in against_by_key:
        if key not in current_by_key:
            cred = against_by_key[key]
            entries.append(DiffEntry(
                kind="removed",
                service=cred.get("service", "?"),
                alias=cred.get("alias", "?"),
                credential_type=cred.get("credential_type"),
                status=cred.get("status"),
            ))

    for lease_id, lease in current_leases.items():
        if lease_id not in against_leases:
            entries.append(DiffEntry(
                kind="added",
                service=lease.get("service", "?"),
                alias=lease.get("alias", "?"),
                resource_type="lease",
                credential_type="lease",
                status=lease.get("status"),
                lease_id=lease_id,
                agent_id=lease.get("agent_id"),
            ))
        else:
            ref = against_leases[lease_id]
            changes = []
            for field in _LEASE_CHANGE_FIELDS:
                if lease.get(field) != ref.get(field):
                    changes.append({
                        "field": field,
                        "from": str(ref.get(field, "-")),
                        "to": str(lease.get(field, "-")),
                    })
            if changes:
                entries.append(DiffEntry(
                    kind="changed",
                    service=lease.get("service", "?"),
                    alias=lease.get("alias", "?"),
                    resource_type="lease",
                    credential_type="lease",
                    status=lease.get("status"),
                    lease_id=lease_id,
                    agent_id=lease.get("agent_id"),
                    changes=changes,
                ))

    for lease_id, lease in against_leases.items():
        if lease_id not in current_leases:
            entries.append(DiffEntry(
                kind="removed",
                service=lease.get("service", "?"),
                alias=lease.get("alias", "?"),
                resource_type="lease",
                credential_type="lease",
                status=lease.get("status"),
                lease_id=lease_id,
                agent_id=lease.get("agent_id"),
            ))

    entries.sort(
        key=lambda e: (
            {"added": 0, "changed": 1, "removed": 2}[e.kind],
            0 if e.resource_type == "credential" else 1,
            e.service,
            e.alias,
            e.lease_id or "",
        )
    )
    return entries
