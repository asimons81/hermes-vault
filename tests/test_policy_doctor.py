from __future__ import annotations

import json
from pathlib import Path

import yaml

from hermes_vault.policy_doctor import (
    PolicyDoctorFinding,
    PolicyDoctorReport,
    run_policy_doctor,
)


def _write_policy(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_policy_doctor_clean_policy_is_safe(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    generated_skills_dir = tmp_path / "generated-skills"
    policy = {
        "agents": {
            "hermes": {
                "services": {
                    "openai": {
                        "actions": [
                            "add_credential",
                            "rotate",
                            "get_env",
                            "verify",
                            "metadata",
                        ],
                    }
                },
                "capabilities": ["list_credentials"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            }
        }
    }
    _write_policy(policy_path, policy)
    original_text = policy_path.read_text(encoding="utf-8")

    report = run_policy_doctor(policy_path, generated_skills_dir=generated_skills_dir)

    assert isinstance(report, PolicyDoctorReport)
    assert report.findings == []
    assert report.policy_hash is not None
    assert report.strict_violation is False
    assert policy_path.read_text(encoding="utf-8") == original_text
    payload = report.as_dict()
    json.dumps(payload)
    assert payload["version"] == "policy-doctor-v1"
    assert payload["finding_count"] == 0


def test_policy_doctor_flags_unknown_action_and_capability(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = {
        "agents": {
            "dwight": {
                "services": {
                    "openai": {
                        "actions": ["get_env", "verify", "frobulate"],
                    }
                },
                "capabilities": ["list_credentials", "teleport"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 900,
            }
        }
    }
    _write_policy(policy_path, policy)

    report = run_policy_doctor(policy_path)

    kinds = {finding.kind for finding in report.findings}
    assert "unknown_action" in kinds
    assert "unknown_capability" in kinds
    assert report.strict_violation is False

    unknown_action = next(f for f in report.findings if f.kind == "unknown_action")
    assert unknown_action.service == "openai"
    assert "frobulate" in unknown_action.detail
    assert unknown_action.strict_violation is True
    json.dumps(unknown_action.as_dict())


def test_policy_doctor_flags_legacy_capability_grant_and_raw_secret_access(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = {
        "agents": {
            "hermes": {
                "services": ["openai"],
                "raw_secret_access": True,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            }
        }
    }
    _write_policy(policy_path, policy)

    report = run_policy_doctor(policy_path)

    kinds = {finding.kind for finding in report.findings}
    assert "legacy_implicit_capabilities" in kinds
    assert "raw_secret_access_enabled" in kinds

    legacy = next(f for f in report.findings if f.kind == "legacy_implicit_capabilities")
    raw_secret = next(f for f in report.findings if f.kind == "raw_secret_access_enabled")
    assert legacy.strict_violation is True
    assert raw_secret.strict_violation is True


def test_policy_doctor_flags_oauth_permission_gaps(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = {
        "agents": {
            "claude-desktop": {
                "services": {
                    "google": {
                        "actions": ["get_env", "verify", "metadata"],
                    }
                },
                "capabilities": ["list_credentials"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 3600,
            }
        }
    }
    _write_policy(policy_path, policy)

    report = run_policy_doctor(policy_path)

    kinds = {finding.kind for finding in report.findings}
    assert "oauth_login_permission_gap" in kinds
    assert "oauth_refresh_permission_gap" in kinds

    login_gap = next(f for f in report.findings if f.kind == "oauth_login_permission_gap")
    refresh_gap = next(f for f in report.findings if f.kind == "oauth_refresh_permission_gap")
    assert login_gap.service == "google"
    assert refresh_gap.service == "google"
    assert login_gap.strict_violation is True
    assert refresh_gap.strict_violation is True


def test_policy_doctor_does_not_flag_custom_service(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = {
        "agents": {
            "internal-bot": {
                "services": {
                    "acme-vault": {
                        "actions": ["get_env", "verify"],
                    }
                },
                "capabilities": ["list_credentials"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 900,
            }
        }
    }
    _write_policy(policy_path, policy)

    report = run_policy_doctor(policy_path)

    assert report.findings == []
    assert report.policy_hash is not None


def test_policy_doctor_detects_stale_generated_skill_hash(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    generated_skills_dir = tmp_path / "generated-skills"
    policy = {
        "agents": {
            "hermes": {
                "services": {
                    "openai": {
                        "actions": [
                            "add_credential",
                            "rotate",
                            "get_env",
                            "verify",
                            "metadata",
                        ],
                    }
                },
                "capabilities": ["list_credentials"],
                "raw_secret_access": False,
                "ephemeral_env_only": True,
                "max_ttl_seconds": 1800,
            }
        }
    }
    _write_policy(policy_path, policy)

    skill_path = generated_skills_dir / "hermes" / "SKILL.md"
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_path.write_text(
        "---\nname: hermes-vault-access\n---\n\n<!-- hv-policy-hash: "
        + "0" * 64
        + " -->\n",
        encoding="utf-8",
    )

    report = run_policy_doctor(policy_path, generated_skills_dir=generated_skills_dir)

    stale = [finding for finding in report.findings if finding.kind == "stale_generated_skill"]
    assert len(stale) == 1
    assert stale[0].agent_id == "hermes"
    assert stale[0].strict_violation is False


def test_policy_doctor_strict_sets_strict_violation(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy = {
        "agents": {
            "hermes": {
                "services": ["openai"],
                "raw_secret_access": True,
            }
        }
    }
    _write_policy(policy_path, policy)

    report = run_policy_doctor(policy_path, strict=True)

    assert report.strict_violation is True
    assert report.strict_violation_count >= 1
    assert any(finding.strict_violation for finding in report.findings)


def test_policy_doctor_finding_model_serializes() -> None:
    finding = PolicyDoctorFinding(
        kind="raw_secret_access_enabled",
        severity="high",
        detail="raw_secret_access is enabled",
        agent_id="hermes",
        strict_violation=True,
    )

    assert finding.model_dump(mode="json")["severity"] == "high"
    json.dumps(finding.as_dict())
