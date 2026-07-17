from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Protocol, cast
from urllib.parse import urlparse
import urllib.error
import urllib.request

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from hermes_vault.config import AppSettings
from hermes_vault.models import VerificationCategory, VerificationResult
from hermes_vault.service_ids import normalize


@dataclass(frozen=True)
class ProviderVerifierConfig:
    service: str
    url: str
    headers: dict[str, str]
    method: str = "GET"
    success_statuses: tuple[int, ...] | None = None
    invalid_statuses: tuple[int, ...] = (400, 401)
    rate_limit_statuses: tuple[int, ...] = (429,)
    permission_statuses: tuple[int, ...] = (403,)
    timeout_seconds: int | None = None


@dataclass(frozen=True)
class VerifierContext:
    timeout_seconds: int
    http_verify: Callable[[ProviderVerifierConfig], VerificationResult]
    classify_http_error: Callable[[str, int, str, dict[str, str] | None], VerificationResult]
    classify_transport_error: Callable[[str, BaseException], VerificationResult]


class CredentialVerifierPlugin(Protocol):
    service_ids: tuple[str, ...]

    def verify(
        self,
        service: str,
        secret: str,
        context: VerifierContext,
    ) -> VerificationResult:
        ...


VerifierCallable = Callable[[str], VerificationResult]


@dataclass(frozen=True)
class RegisteredVerifier:
    service: str
    source: str
    verifier: VerifierCallable
    allow_override: bool = False


@dataclass(frozen=True)
class VerifierDiagnostic:
    level: Literal["info", "warning", "error"]
    service: str | None
    source: str
    message: str


class _FileHttpVerifierModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    url: str
    headers: dict[str, str]
    method: str = "GET"
    success_statuses: tuple[int, ...] | None = None
    invalid_statuses: tuple[int, ...] = (400, 401)
    rate_limit_statuses: tuple[int, ...] = (429,)
    permission_statuses: tuple[int, ...] = (403,)
    timeout_seconds: int | None = None
    allow_override: bool = False

    @field_validator("type")
    @classmethod
    def _validate_type(cls, value: str) -> str:
        if value != "http":
            raise ValueError("only http verifier plugins are supported")
        return value

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST")
        return method

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an http:// or https:// URL")
        return value

    @field_validator("headers")
    @classmethod
    def _validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict) or not value:
            raise ValueError("headers must be a non-empty mapping")
        for header_name, header_value in value.items():
            if not isinstance(header_name, str) or not header_name.strip():
                raise ValueError("header names must be non-empty strings")
            if not isinstance(header_value, str):
                raise ValueError("header values must be strings")
        return value

    @field_validator("success_statuses", "invalid_statuses", "rate_limit_statuses", "permission_statuses")
    @classmethod
    def _validate_statuses(cls, value: tuple[int, ...] | None) -> tuple[int, ...] | None:
        if value is None:
            return None
        for status in value:
            if status < 100 or status > 599:
                raise ValueError("HTTP status codes must be between 100 and 599")
        return value

    @field_validator("timeout_seconds")
    @classmethod
    def _validate_timeout(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("timeout_seconds must be positive")
        return value


class _HttpVerifierPlugin:
    def __init__(self, service: str, config: _FileHttpVerifierModel) -> None:
        self.service_ids: tuple[str, ...] = (service,)
        self.allow_override = config.allow_override
        self._config = config

    def verify(
        self,
        service: str,
        secret: str,
        context: VerifierContext,
    ) -> VerificationResult:
        headers = {
            name: value.replace("{secret}", secret)
            for name, value in self._config.headers.items()
        }
        return context.http_verify(
            ProviderVerifierConfig(
                service=service,
                url=self._config.url,
                headers=headers,
                method=self._config.method,
                success_statuses=self._config.success_statuses,
                invalid_statuses=self._config.invalid_statuses,
                rate_limit_statuses=self._config.rate_limit_statuses,
                permission_statuses=self._config.permission_statuses,
                timeout_seconds=self._config.timeout_seconds,
            )
        )


class Verifier:
    def __init__(
        self,
        timeout_seconds: int = 10,
        *,
        plugin_dir: Path | None = None,
        load_file_plugins: bool = True,
        load_entry_points: bool = True,
        allow_plugin_overrides: bool = False,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.plugin_dir = plugin_dir if plugin_dir is not None else AppSettings().verifier_plugin_dir
        self.allow_plugin_overrides = allow_plugin_overrides
        self._registry: dict[str, RegisteredVerifier] = {}
        self._diagnostics: list[VerifierDiagnostic] = []
        def http_verify(config: ProviderVerifierConfig) -> VerificationResult:
            return self._http_verify(config)

        def classify_http_error(
            service: str,
            status_code: int,
            body: str,
            headers: dict[str, str] | None = None,
        ) -> VerificationResult:
            return self._classify_http_error(service, status_code, body, headers)

        def classify_transport_error(service: str, exc: BaseException) -> VerificationResult:
            return self._classify_transport_error(service, exc)

        self._context = VerifierContext(
            timeout_seconds=self.timeout_seconds,
            http_verify=http_verify,
            classify_http_error=classify_http_error,
            classify_transport_error=classify_transport_error,
        )
        self._register_builtins()
        if load_file_plugins:
            self._load_file_plugins(self.plugin_dir)
        if load_entry_points:
            self._load_entry_point_plugins()

    def diagnostics(self) -> list[VerifierDiagnostic]:
        return list(self._diagnostics)

    def register(
        self,
        service: str,
        verifier: VerifierCallable,
        *,
        source: str = "manual",
        override: bool = False,
    ) -> None:
        normalized_service = normalize(service)
        existing = self._registry.get(normalized_service)
        if existing is not None and not override:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="warning",
                    service=normalized_service,
                    source=source,
                    message=(
                        f"Verifier for {normalized_service!r} from {source} was ignored; "
                        f"{existing.source} is already registered."
                    ),
                )
            )
            return
        if existing is not None and override:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="info",
                    service=normalized_service,
                    source=source,
                    message=(
                        f"Verifier for {normalized_service!r} from {source} replaced "
                        f"{existing.source}."
                    ),
                )
            )
        self._registry[normalized_service] = RegisteredVerifier(
            service=normalized_service,
            source=source,
            verifier=verifier,
            allow_override=override,
        )

    def verify(self, service: str, secret: str) -> VerificationResult:
        service = normalize(service)
        registered = self._registry.get(service)
        if registered is not None:
            try:
                return registered.verifier(secret)
            except Exception as exc:
                return VerificationResult(
                    service=service,
                    category=VerificationCategory.unknown,
                    success=False,
                    reason=f"Verifier plugin failed: {exc.__class__.__name__}",
                )

        adapter = getattr(self, f"_verify_{service}", None)
        if adapter is None:
            env_var = f"HERMES_VAULT_VERIFY_URL_{service.replace('-', '_').replace('.', '_').replace(' ', '_').upper()}"
            url = os.environ.get(env_var)
            if url:
                result = self._http_verify(ProviderVerifierConfig(
                    service=service,
                    url=url,
                    headers={"Authorization": f"Bearer {secret}"},
                ))
                if result.status_code is not None and result.reason.startswith(f"Provider returned status {result.status_code}:"):
                    result.reason = f"Provider returned status {result.status_code}."
                return result

            return VerificationResult(
                service=service,
                category=VerificationCategory.unknown,
                success=False,
                reason="No provider-specific verifier is configured for this service.",
            )
        return adapter(secret)

    def _register_builtins(self) -> None:
        self.register("openai", self._verify_openai, source="builtin")
        self.register("anthropic", self._verify_anthropic, source="builtin")
        self.register("evolink", self._verify_evolink, source="builtin")
        self.register("minimax", self._verify_minimax, source="builtin")
        self.register("github", self._verify_github, source="builtin")
        self.register("supabase", self._verify_supabase, source="builtin")

    def _load_file_plugins(self, plugin_dir: Path) -> None:
        if not plugin_dir.exists():
            return
        if not plugin_dir.is_dir():
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="warning",
                    service=None,
                    source=f"file:{plugin_dir}",
                    message="Verifier plugin path exists but is not a directory.",
                )
            )
            return
        try:
            candidates = [
                path
                for path in plugin_dir.iterdir()
                if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
            ]
        except OSError as exc:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="warning",
                    service=None,
                    source=f"file:{plugin_dir}",
                    message=f"Verifier plugin directory could not be read: {exc.__class__.__name__}",
                )
            )
            return

        for path in sorted(candidates, key=lambda candidate: str(candidate.resolve())):
            self._load_file_plugin(path)

    def _load_file_plugin(self, path: Path) -> None:
        source = f"file:{path}"
        try:
            raw_data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="error",
                    service=None,
                    source=source,
                    message=f"Invalid verifier plugin YAML: {exc.__class__.__name__}",
                )
            )
            return
        except OSError as exc:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="warning",
                    service=None,
                    source=source,
                    message=f"Verifier plugin file could not be read: {exc.__class__.__name__}",
                )
            )
            return

        if not isinstance(raw_data, dict) or not isinstance(raw_data.get("verifiers"), dict):
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="error",
                    service=None,
                    source=source,
                    message="Verifier plugin file must contain a 'verifiers' mapping.",
                )
            )
            return

        for raw_service in sorted(raw_data["verifiers"].keys(), key=str):
            service_source = f"{source}#{raw_service}"
            normalized_service = normalize(str(raw_service))
            raw_config = raw_data["verifiers"][raw_service]
            try:
                config = _FileHttpVerifierModel.model_validate(raw_config)
            except ValidationError as exc:
                self._diagnostics.append(
                    VerifierDiagnostic(
                        level="error",
                        service=normalized_service,
                        source=service_source,
                        message=f"Invalid verifier plugin schema: {exc.errors()[0]['msg']}",
                    )
                )
                continue

            self._register_plugin(
                _HttpVerifierPlugin(normalized_service, config),
                source=service_source,
                plugin_allows_override=config.allow_override,
            )

    def _load_entry_point_plugins(self) -> None:
        try:
            entry_points = metadata.entry_points(group="hermes_vault.verifiers")
        except Exception as exc:
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="error",
                    service=None,
                    source="entry-point:hermes_vault.verifiers",
                    message=f"Verifier entry points could not be discovered: {exc.__class__.__name__}",
                )
            )
            return

        for entry_point in sorted(entry_points, key=lambda ep: ep.name):
            source = f"entry-point:{entry_point.name}"
            try:
                plugin = self._entry_point_to_plugin(entry_point.load())
            except Exception as exc:
                self._diagnostics.append(
                    VerifierDiagnostic(
                        level="error",
                        service=None,
                        source=source,
                        message=f"Verifier entry point could not be loaded: {exc.__class__.__name__}",
                    )
                )
                continue
            self._register_plugin(
                plugin,
                source=source,
                plugin_allows_override=bool(getattr(plugin, "allow_override", False)),
            )

    def _entry_point_to_plugin(self, loaded: object) -> CredentialVerifierPlugin:
        plugin = loaded
        if isinstance(plugin, type):
            plugin = plugin()
        elif not self._is_plugin(plugin) and callable(plugin):
            plugin = plugin()
        if not self._is_plugin(plugin):
            raise TypeError("entry point does not provide a credential verifier plugin")
        return cast(CredentialVerifierPlugin, plugin)

    def _is_plugin(self, plugin: object) -> bool:
        service_ids = getattr(plugin, "service_ids", None)
        return (
            not isinstance(service_ids, str)
            and isinstance(service_ids, (tuple, list))
            and bool(service_ids)
            and callable(getattr(plugin, "verify", None))
        )

    def _register_plugin(
        self,
        plugin: CredentialVerifierPlugin,
        *,
        source: str,
        plugin_allows_override: bool,
    ) -> None:
        if not self._is_plugin(plugin):
            self._diagnostics.append(
                VerifierDiagnostic(
                    level="error",
                    service=None,
                    source=source,
                    message="Verifier plugin is missing service_ids or verify().",
                )
            )
            return

        for raw_service in getattr(plugin, "service_ids"):
            if not isinstance(raw_service, str) or not raw_service.strip():
                self._diagnostics.append(
                    VerifierDiagnostic(
                        level="error",
                        service=None,
                        source=source,
                        message="Verifier plugin service_ids must be non-empty strings.",
                    )
                )
                continue
            normalized_service = normalize(raw_service)

            def _adapted(secret: str, *, service: str = normalized_service) -> VerificationResult:
                return plugin.verify(service, secret, self._context)

            self.register(
                normalized_service,
                _adapted,
                source=source,
                override=self.allow_plugin_overrides and plugin_allows_override,
            )

    def _verify_openai(self, secret: str) -> VerificationResult:
        return self._http_verify(ProviderVerifierConfig(
            service="openai",
            url="https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {secret}"},
        ))

    def _verify_anthropic(self, secret: str) -> VerificationResult:
        return self._http_verify(ProviderVerifierConfig(
            service="anthropic",
            url="https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": secret,
                "anthropic-version": "2023-06-01",
            },
        ))

    def _verify_evolink(self, secret: str) -> VerificationResult:
        return self._http_verify(ProviderVerifierConfig(
            service="evolink",
            url="https://direct.evolink.ai/v1/models",
            headers={"Authorization": f"Bearer {secret}"},
        ))

    def _verify_minimax(self, secret: str) -> VerificationResult:
        url = os.environ.get("HERMES_VAULT_MINIMAX_VERIFY_URL")
        if not url:
            return VerificationResult(
                service="minimax",
                category=VerificationCategory.unknown,
                success=False,
                reason="MiniMax verification endpoint is not configured. Set HERMES_VAULT_MINIMAX_VERIFY_URL to a provider health or lightweight authenticated endpoint.",
            )
        return self._http_verify(ProviderVerifierConfig(
            service="minimax",
            url=url,
            headers={"Authorization": f"Bearer {secret}"},
        ))

    def _verify_github(self, secret: str) -> VerificationResult:
        return self._http_verify(ProviderVerifierConfig(
            service="github",
            url="https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {secret}",
                "Accept": "application/vnd.github+json",
            },
        ))

    def _verify_supabase(self, secret: str) -> VerificationResult:
        # Supabase personal access tokens can be verified against the management API
        return self._http_verify(ProviderVerifierConfig(
            service="supabase",
            url="https://api.supabase.com/v1/projects",
            headers={
                "Authorization": f"Bearer {secret}",
                "Accept": "application/json",
            },
        ))

    def _http_verify(self, config: ProviderVerifierConfig) -> VerificationResult:
        parsed = urlparse(config.url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            return VerificationResult(
                service=config.service,
                category=VerificationCategory.endpoint_misconfiguration,
                success=False,
                reason=f"Verification endpoint is misconfigured: {config.url}",
            )
        request = urllib.request.Request(
            url=config.url,
            headers=config.headers,
            method=config.method,
        )
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds or self.timeout_seconds) as response:
                status_code = response.getcode()
                if self._is_success_status(config, status_code):
                    return VerificationResult(
                        service=config.service,
                        category=VerificationCategory.valid,
                        success=True,
                        reason="Credential verified successfully.",
                        status_code=status_code,
                    )
                return self._classify_http_error(
                    config.service,
                    status_code,
                    "",
                    dict(response.headers.items()) if getattr(response, "headers", None) else {},
                    invalid_statuses=config.invalid_statuses,
                    rate_limit_statuses=config.rate_limit_statuses,
                    permission_statuses=config.permission_statuses,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            return self._classify_http_error(
                config.service,
                exc.code,
                body,
                dict(exc.headers.items()) if exc.headers else {},
                invalid_statuses=config.invalid_statuses,
                rate_limit_statuses=config.rate_limit_statuses,
                permission_statuses=config.permission_statuses,
            )
        except (urllib.error.URLError, socket.timeout) as exc:
            return self._classify_transport_error(config.service, exc)
        except Exception as exc:
            return VerificationResult(
                service=config.service,
                category=VerificationCategory.unknown,
                success=False,
                reason=f"Unexpected verification error ({type(exc).__name__})",
            )

    def _is_success_status(self, config: ProviderVerifierConfig, status_code: int) -> bool:
        if config.success_statuses is None:
            return 200 <= status_code < 300
        return status_code in config.success_statuses

    def _classify_transport_error(
        self, service: str, exc: BaseException
    ) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.network_failure,
            success=False,
            reason=f"Network failure during verification ({type(exc).__name__})",
        )

    def _classify_http_error(
        self,
        service: str,
        status_code: int,
        body: str,
        headers: dict[str, str] | None = None,
        *,
        invalid_statuses: tuple[int, ...] = (400, 401),
        rate_limit_statuses: tuple[int, ...] = (429,),
        permission_statuses: tuple[int, ...] = (403,),
    ) -> VerificationResult:
        lowered = body.lower()
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        if status_code in invalid_statuses:
            return VerificationResult(
                service=service,
                category=VerificationCategory.invalid_or_expired,
                success=False,
                reason="Provider rejected the credential as invalid or expired.",
                status_code=status_code,
            )
        if status_code in rate_limit_statuses or headers.get("x-ratelimit-remaining") == "0":
            return VerificationResult(
                service=service,
                category=VerificationCategory.rate_limit,
                success=False,
                reason="Provider rate limit reached during verification.",
                status_code=status_code,
            )
        if status_code in permission_statuses:
            category = (
                VerificationCategory.rate_limit
                if "rate limit" in lowered or "ratelimit" in lowered or headers.get("x-ratelimit-remaining") == "0"
                else VerificationCategory.permission_scope_issue
            )
            reason = (
                "Provider reported a rate limit condition."
                if category is VerificationCategory.rate_limit
                else "Provider rejected the credential because of permissions or scope."
            )
            return VerificationResult(
                service=service,
                category=category,
                success=False,
                reason=reason,
                status_code=status_code,
            )
        if status_code == 404:
            return VerificationResult(
                service=service,
                category=VerificationCategory.endpoint_misconfiguration,
                success=False,
                reason="Verification endpoint appears misconfigured or unavailable.",
                status_code=status_code,
            )
        return VerificationResult(
            service=service,
            category=VerificationCategory.unknown,
            success=False,
            reason=f"Provider returned status {status_code}: {self._compact_body(body)}",
            status_code=status_code,
        )

    def _compact_body(self, body: str) -> str:
        try:
            parsed = json.loads(body)
            return json.dumps(parsed, sort_keys=True)[:200]
        except Exception:
            return body[:200]
