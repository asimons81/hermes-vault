"""CI release-integrity contract.

Pins the workflow invariants that protect releases (v0.26.0 P6):

- ``uv.lock`` freshness guard — the #81 stale-lock class (constraint widened in
  pyproject, lock left pinning mcp 1.27.0, every lock-based install of master
  crashed at import) must never ship silently again. CI installed without the
  lock, so nothing kept it honest.
- PyPI publish gated on a green test job — tags used to publish with ZERO
  tests (that is how 0.25.1 initially went out); the tag push must run the
  suite before anything reaches PyPI.
- Locked dependency advisory scan — the existing ``dependency-audit`` job
  audits a live-resolved install; this guard audits the exact reviewed,
  hash-pinned set recorded in ``uv.lock`` (security F-09).
- Repo hygiene invariants — the v0.23.1 release strays are committed for
  archive parity and the unreferenced ``site/assets/hermes-vault-logo.jpg``
  stays out of the tree.

These are structural YAML tests: they fail loudly if a workflow edit silently
removes a guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


@pytest.fixture(scope="module")
def ci_workflow() -> dict:
    return yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def publish_workflow() -> dict:
    return yaml.safe_load((WORKFLOWS / "publish-to-pypi.yml").read_text(encoding="utf-8"))


def _jobs(workflow: dict) -> dict:
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "workflow has no jobs"
    return jobs


def _job_steps(job: dict) -> list[str]:
    """All 'run:' step bodies of a job, concatenated."""
    parts: list[str] = []
    for step in job.get("steps", []):
        run = step.get("run")
        if run:
            parts.append(run)
    return parts


def _find_job_with_run(jobs: dict, needle: str) -> tuple[str, dict] | None:
    """First (name, job) whose run steps contain ``needle``."""
    for name, job in jobs.items():
        if any(needle in run for run in _job_steps(job)):
            return name, job
    return None


# ── Lock freshness (#81 stale-lock class) ────────────────────────────


def test_ci_verifies_lock_freshness(ci_workflow: dict) -> None:
    """ci.yml must run `uv lock --check` so lock rot fails the build."""
    match = _find_job_with_run(_jobs(ci_workflow), "uv lock --check")
    assert match is not None, (
        "ci.yml no longer runs `uv lock --check` — the #81 stale-lock class "
        "(pyproject widened, uv.lock left stale, lock-based installs crash) "
        "would ship silently again"
    )
    name, _job = match
    assert "lock" in name.lower(), f"lock-freshness job should be named for what it does, got {name!r}"


def test_ci_lock_freshness_job_installs_uv(ci_workflow: dict) -> None:
    """The lock guard must actually install uv (runners do not ship it)."""
    match = _find_job_with_run(_jobs(ci_workflow), "uv lock --check")
    assert match is not None
    _name, job = match
    install_lines = [line for line in "\n".join(_job_steps(job)).splitlines() if "pip install" in line]
    assert install_lines and any("uv" in line for line in install_lines), (
        "lock-freshness job does not install uv before invoking it"
    )


# ── Locked dependency advisory scan (F-09) ───────────────────────────


def test_ci_audits_locked_dependency_set(ci_workflow: dict) -> None:
    """ci.yml must pip-audit the exported, hash-pinned locked set — not only a
    live-resolved install (which can resolve versions the lock never reviewed)."""
    jobs = _jobs(ci_workflow)
    export_match = _find_job_with_run(jobs, "uv export --locked")
    assert export_match is not None, (
        "ci.yml no longer exports the locked dependency set (uv export --locked)"
    )
    _name, job = export_match
    all_runs = "\n".join(_job_steps(job))
    assert "pip-audit" in all_runs, "locked-set job must feed the export to pip-audit"
    assert "--require-hashes" in all_runs, "locked-set audit must enforce hash pinning"


# ── Publish gated on green tests ─────────────────────────────────────


def test_publish_workflow_runs_tests(publish_workflow: dict) -> None:
    """publish-to-pypi.yml must run the test suite — tags used to publish with
    zero test execution."""
    jobs = _jobs(publish_workflow)
    match = _find_job_with_run(jobs, "python -m pytest tests")
    assert match is not None, "publish-to-pypi.yml has no job running the core test suite"


def test_publish_gated_on_test_job(publish_workflow: dict) -> None:
    """The PyPI upload job must `needs` the test job."""
    jobs = _jobs(publish_workflow)
    publish_jobs = [
        (name, job)
        for name, job in jobs.items()
        if any("pypi-publish" in str(step.get("uses", "")) for step in job.get("steps", []))
    ]
    assert publish_jobs, "publish-to-pypi.yml no longer uses pypa/gh-action-pypi-publish"
    for name, job in publish_jobs:
        needs = job.get("needs")
        needed = [needs] if isinstance(needs, str) else list(needs or [])
        assert needed, f"publish job {name!r} has no `needs:` — a tag could publish without tests"
    test_job_names = {n for n, j in jobs.items() if any("pytest tests" in r for r in _job_steps(j))}
    assert test_job_names, "no test job found to gate publish on"
    # At least one needed job of each publish job must be a test job.
    for name, job in publish_jobs:
        needs = job.get("needs")
        needed = [needs] if isinstance(needs, str) else list(needs or [])
        assert test_job_names & set(needed), (
            f"publish job {name!r} does not need a test job (needs={needed})"
        )


def test_publish_tests_cover_plugin_suites(publish_workflow: dict) -> None:
    """The release test job must cover the plugin suites, matching ci.yml —
    a tag that skips plugin tests is not a green release gate."""
    all_runs = "\n".join(
        run for _n, job in _jobs(publish_workflow).items() for run in _job_steps(job)
    )
    assert "plugins/hermes-vault-secret-source/tests" in all_runs
    assert "plugins/hermes-vault-desktop/tests" in all_runs


# ── Repo hygiene (v0.23.1 strays + stray logo) ───────────────────────


def test_v0_23_1_release_strays_are_committed() -> None:
    """Every release since v0.10.0 has a tracked readiness record; v0.23.1's
    must stay committed for archive parity (they lived as untracked strays)."""
    notes = REPO_ROOT / "release-notes-0.23.1.md"
    verification = REPO_ROOT / "release-readiness" / "v0.23.1" / "post-release-verification.md"
    assert notes.is_file(), "release-notes-0.23.1.md is missing (was an untracked stray)"
    assert verification.is_file(), "release-readiness/v0.23.1/ is missing (was an untracked stray)"


def test_stray_logo_stays_out_of_the_tree() -> None:
    """site/assets/hermes-vault-logo.jpg is unreferenced (0 references in the
    repo and the deployed site) — it must not come back."""
    stray = REPO_ROOT / "site" / "assets" / "hermes-vault-logo.jpg"
    assert not stray.exists(), "unreferenced site/assets/hermes-vault-logo.jpg reappeared"
