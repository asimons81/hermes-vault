from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource, is_valid_env_name, run_secret_cli


_ERROR_KIND_MAP = {
    "NOT_CONFIGURED": ErrorKind.NOT_CONFIGURED,
    "BINARY_MISSING": ErrorKind.BINARY_MISSING,
    "AUTH_FAILED": ErrorKind.AUTH_FAILED,
    "AUTH_EXPIRED": ErrorKind.AUTH_EXPIRED,
    "REF_INVALID": ErrorKind.REF_INVALID,
    "NETWORK": ErrorKind.NETWORK,
    "EMPTY_VALUE": ErrorKind.EMPTY_VALUE,
    "TIMEOUT": ErrorKind.TIMEOUT,
    "INTERNAL": ErrorKind.INTERNAL,
}


class HermesVaultSource(SecretSource):
    name = "hermes_vault"
    label = "Hermes Vault"
    shape = "mapped"
    scheme = "hv"

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        result = FetchResult()
        cfg = cfg if isinstance(cfg, dict) else {}
        env_map = cfg.get("env")
        if not isinstance(env_map, dict) or not env_map:
            result.error = "secrets.hermes_vault.enabled is true but no env map is configured."
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        bindings: list[str] = []
        for env_name, ref in env_map.items():
            if not isinstance(env_name, str) or not is_valid_env_name(env_name):
                result.error = f"Invalid environment variable name in secrets.hermes_vault.env: {env_name!r}"
                result.error_kind = ErrorKind.REF_INVALID
                return result
            if not isinstance(ref, str) or not ref.strip():
                result.error = f"Invalid Hermes Vault reference for {env_name}."
                result.error_kind = ErrorKind.REF_INVALID
                return result
            bindings.append(f"{env_name}={ref.strip()}")

        binary = str(cfg.get("binary") or "hermes-vault")
        agent = str(cfg.get("agent") or "hermes")
        ttl = _positive_int(cfg.get("ttl_seconds"), 900)
        timeout = float(_positive_int(cfg.get("timeout_seconds"), 30))
        extra_env = _extra_env(cfg, home_path)
        allow_env = sorted(self.protected_env_vars(cfg) | _vault_config_env_vars(cfg))

        try:
            proc = run_secret_cli(
                [
                    binary,
                    "--no-banner",
                    "secret-source",
                    "fetch",
                    "--agent",
                    agent,
                    "--ttl",
                    str(ttl),
                    "--format",
                    "json",
                    "--",
                    *bindings,
                ],
                allow_env=allow_env,
                extra_env=extra_env,
                timeout=timeout,
            )
        except RuntimeError as exc:
            result.error = str(exc)
            result.error_kind = ErrorKind.TIMEOUT if "timed out" in str(exc).lower() else ErrorKind.BINARY_MISSING
            result.binary_path = Path(binary)
            return result

        result.binary_path = Path(binary)
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            result.error = "hermes-vault secret-source fetch returned malformed JSON."
            result.error_kind = ErrorKind.INTERNAL
            return result

        _apply_payload_to_result(payload, result)
        if result.secrets:
            result.error = None
            result.error_kind = None
        elif result.error is None:
            result.error = _first_issue_message(payload) or f"hermes-vault exited {proc.returncode} without usable secrets."
            result.error_kind = _first_issue_kind(payload) or ErrorKind.INTERNAL
        return result

    def protected_env_vars(self, cfg: dict):
        protected = {"HERMES_VAULT_PASSPHRASE"}
        profile = _profile_from_cfg_or_env(cfg if isinstance(cfg, dict) else {})
        if profile:
            protected.add(_profile_passphrase_env_name(profile))
        return frozenset(protected)

    def config_schema(self) -> dict:
        return {
            "enabled": {"description": "Enable Hermes Vault secret-source resolution.", "default": False},
            "binary": {"description": "Path or executable name for hermes-vault.", "default": "hermes-vault"},
            "agent": {"description": "Hermes Vault policy agent used for get_env checks.", "default": "hermes"},
            "ttl_seconds": {"description": "TTL requested for policy evaluation.", "default": 900},
            "timeout_seconds": {"description": "CLI invocation timeout.", "default": 30},
            "home": {"description": "Optional HERMES_VAULT_HOME for the child process.", "default": None},
            "policy": {"description": "Optional HERMES_VAULT_POLICY for the child process.", "default": None},
            "profile": {"description": "Optional HERMES_VAULT_PROFILE for the child process.", "default": None},
            "env": {"description": "Explicit ENV_VAR -> hv://service mapping.", "default": {}},
        }


def _apply_payload_to_result(payload: dict[str, Any], result: FetchResult) -> None:
    secrets = payload.get("secrets")
    if isinstance(secrets, dict):
        result.secrets = {
            str(key): value
            for key, value in secrets.items()
            if isinstance(key, str) and is_valid_env_name(key) and isinstance(value, str) and value != ""
        }
    warnings = payload.get("warnings")
    if isinstance(warnings, dict):
        result.warnings.extend(_format_issues(warnings))
    errors = payload.get("errors")
    if isinstance(errors, dict):
        if result.secrets:
            result.warnings.extend(_format_issues(errors))
        else:
            result.error = _first_issue_message(payload)
            result.error_kind = _first_issue_kind(payload)


def _format_issues(issues: dict[str, Any]) -> list[str]:
    formatted: list[str] = []
    for env_name, issue in issues.items():
        if not isinstance(issue, dict):
            continue
        kind = str(issue.get("kind") or "INTERNAL")
        message = str(issue.get("message") or "Hermes Vault secret source issue.")
        formatted.append(f"{env_name}: {kind}: {message}")
    return formatted


def _first_issue_message(payload: dict[str, Any]) -> str | None:
    for bucket_name in ("errors", "warnings"):
        bucket = payload.get(bucket_name)
        if not isinstance(bucket, dict):
            continue
        for issue in bucket.values():
            if isinstance(issue, dict):
                return str(issue.get("message") or "Hermes Vault secret source failed.")
    return None


def _first_issue_kind(payload: dict[str, Any]) -> ErrorKind | None:
    for bucket_name in ("errors", "warnings"):
        bucket = payload.get(bucket_name)
        if not isinstance(bucket, dict):
            continue
        for issue in bucket.values():
            if isinstance(issue, dict):
                return _ERROR_KIND_MAP.get(str(issue.get("kind") or ""))
    return None


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _extra_env(cfg: dict, home_path: Path) -> dict[str, str]:
    extra: dict[str, str] = {}
    home = cfg.get("home")
    policy = cfg.get("policy")
    profile = cfg.get("profile")
    if isinstance(home, str) and home.strip():
        extra["HERMES_VAULT_HOME"] = str(Path(home).expanduser())
    elif home_path:
        extra["HERMES_VAULT_HOME"] = str(home_path)
    if isinstance(policy, str) and policy.strip():
        extra["HERMES_VAULT_POLICY"] = str(Path(policy).expanduser())
    if isinstance(profile, str) and profile.strip():
        extra["HERMES_VAULT_PROFILE"] = profile.strip()
    return extra


def _vault_config_env_vars(cfg: dict) -> frozenset[str]:
    names = {"HERMES_VAULT_HOME", "HERMES_VAULT_POLICY", "HERMES_VAULT_PROFILE", "HERMES_VAULT_DPAPI"}
    return frozenset(names)


def _profile_from_cfg_or_env(cfg: dict) -> str | None:
    profile = cfg.get("profile")
    if isinstance(profile, str) and profile.strip():
        return profile.strip()
    env_profile = os.environ.get("HERMES_VAULT_PROFILE", "").strip()
    return env_profile or None


def _profile_passphrase_env_name(profile: str) -> str:
    from hermes_vault.crypto import profile_passphrase_env_name

    return profile_passphrase_env_name(profile)


def register(ctx):
    ctx.register_secret_source(HermesVaultSource())
