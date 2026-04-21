from __future__ import annotations

import os
import json
import socket
from dataclasses import dataclass
from urllib.parse import urlparse
import urllib.error
import urllib.request

from hermes_vault.models import VerificationCategory, VerificationResult
from hermes_vault.service_ids import normalize


@dataclass(frozen=True)
class ProviderVerifierConfig:
    service: str
    url: str
    headers: dict[str, str]


class Verifier:
    def __init__(self, timeout_seconds: int = 10) -> None:
        self.timeout_seconds = timeout_seconds

    def verify(self, service: str, secret: str) -> VerificationResult:
        service = normalize(service)
        adapter = getattr(self, f"_verify_{service}", None)
        if adapter is None:
            return VerificationResult(
                service=service,
                category=VerificationCategory.unknown,
                success=False,
                reason="No provider-specific verifier is configured for this service.",
            )
        return adapter(secret)

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
        request = urllib.request.Request(url=config.url, headers=config.headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return VerificationResult(
                    service=config.service,
                    category=VerificationCategory.valid,
                    success=True,
                    reason="Credential verified successfully.",
                    status_code=response.getcode(),
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            return self._classify_http_error(config.service, exc.code, body, dict(exc.headers.items()) if exc.headers else {})
        except (urllib.error.URLError, socket.timeout) as exc:
            return self._classify_transport_error(config.service, exc)
        except Exception as exc:
            return VerificationResult(
                service=config.service,
                category=VerificationCategory.unknown,
                success=False,
                reason=f"Unexpected verification error: {exc}",
            )

    def _classify_transport_error(
        self, service: str, exc: BaseException
    ) -> VerificationResult:
        return VerificationResult(
            service=service,
            category=VerificationCategory.network_failure,
            success=False,
            reason=f"Network failure during verification: {exc}",
        )

    def _classify_http_error(
        self, service: str, status_code: int, body: str, headers: dict[str, str] | None = None
    ) -> VerificationResult:
        lowered = body.lower()
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        if status_code in (401, 400):
            return VerificationResult(
                service=service,
                category=VerificationCategory.invalid_or_expired,
                success=False,
                reason="Provider rejected the credential as invalid or expired.",
                status_code=status_code,
            )
        if status_code == 429 or headers.get("x-ratelimit-remaining") == "0":
            return VerificationResult(
                service=service,
                category=VerificationCategory.rate_limit,
                success=False,
                reason="Provider rate limit reached during verification.",
                status_code=status_code,
            )
        if status_code == 403:
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
