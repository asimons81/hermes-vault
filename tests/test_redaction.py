from __future__ import annotations

from hermes_vault.logging_redaction import redact_exception, redact_mapping, redact_text


def test_redaction_scrubs_secret_text() -> None:
    rendered = redact_text("OPENAI_API_KEY=sk-secretvalue1234567890")
    assert "sk-secretvalue1234567890" not in rendered
    assert "[REDACTED]" in rendered


def test_redaction_scrubs_sensitive_mapping_keys() -> None:
    redacted = redact_mapping({"api_key": "value", "safe": "ok"})
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["safe"] == "ok"


def test_redaction_scrubs_exception_messages() -> None:
    exc = RuntimeError("failed with token sk-secretvalue1234567890")
    rendered = redact_exception(exc)
    assert "sk-secretvalue1234567890" not in rendered
    assert "[REDACTED]" in rendered

