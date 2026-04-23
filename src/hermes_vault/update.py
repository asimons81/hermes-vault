from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, url2pathname, urlopen

PACKAGE_NAME = "hermes-vault"
REPOSITORY = "asimons81/hermes-vault"
RELEASES_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_LATEST_URL = f"https://github.com/{REPOSITORY}/releases/latest"
REPOSITORY_GIT_URL = f"https://github.com/{REPOSITORY}.git"
RELEASE_ARCHIVE_URL = f"https://github.com/{REPOSITORY}/archive/refs/tags/{{tag}}.tar.gz"
_VERSION_RE = re.compile(r"^v?(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>.*)$")
_READ_VERSION_SNIPPET = (
    "import importlib.metadata as m\n"
    "from hermes_vault import __version__ as fallback\n"
    "try:\n"
    "    print(m.version('hermes-vault'))\n"
    "except m.PackageNotFoundError:\n"
    "    print(fallback)\n"
)


class UpdateError(RuntimeError):
    """Raised when Hermes Vault cannot complete an update check safely."""


class InstallMethod(StrEnum):
    PIPX = "pipx"
    UV_TOOL = "uv tool"
    EDITABLE_DEV = "editable/dev install"
    PIP = "standard pip/venv install"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReleaseInfo:
    tag: str
    version: str
    url: str
    archive_url: str


@dataclass(frozen=True)
class InstallationState:
    method: InstallMethod
    detail: str
    auto_update_supported: bool
    auto_update_command: tuple[str, ...] | None
    manual_command: str


@dataclass(frozen=True)
class UpdatePlan:
    current_version: str
    latest_release: ReleaseInfo
    installation: InstallationState

    @property
    def needs_update(self) -> bool:
        return _compare_versions(self.latest_release.version, self.current_version) > 0


def get_current_version() -> str:
    """Return the installed Hermes Vault version."""
    try:
        return importlib_metadata.version(PACKAGE_NAME)
    except importlib_metadata.PackageNotFoundError:
        from hermes_vault import __version__

        return __version__


def resolve_update_plan() -> UpdatePlan:
    """Build an update plan from the installed package metadata and release source."""
    latest_release = fetch_latest_release()
    installation = detect_installation_state(latest_release)
    return UpdatePlan(
        current_version=get_current_version(),
        latest_release=latest_release,
        installation=installation,
    )


def fetch_latest_release(opener=urlopen) -> ReleaseInfo:
    """Resolve the latest published Hermes Vault release from GitHub Releases."""
    request = Request(
        RELEASES_API_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "hermes-vault-update-check",
        },
    )
    try:
        with opener(request, timeout=10) as response:
            payload = json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            raise UpdateError(
                "GitHub Releases did not return a latest release for Hermes Vault."
            ) from exc
        raise UpdateError(
            f"Failed to query the Hermes Vault release source ({exc.code})."
        ) from exc
    except URLError as exc:
        raise UpdateError(
            f"Failed to reach the Hermes Vault release source: {exc.reason}"
        ) from exc
    except OSError as exc:
        raise UpdateError(f"Failed to read the Hermes Vault release response: {exc}") from exc

    tag = str(payload.get("tag_name", "")).strip()
    html_url = str(payload.get("html_url", RELEASES_LATEST_URL)).strip() or RELEASES_LATEST_URL
    if not tag:
        raise UpdateError("GitHub Releases returned a latest release without a tag name.")

    return ReleaseInfo(
        tag=tag,
        version=_normalize_version(tag),
        url=html_url,
        archive_url=RELEASE_ARCHIVE_URL.format(tag=tag),
    )


def detect_installation_state(
    latest_release: ReleaseInfo,
    *,
    distribution: importlib_metadata.Distribution | None = None,
    sys_prefix: str | None = None,
    sys_executable: str | None = None,
    platform_name: str | None = None,
) -> InstallationState:
    """Detect how Hermes Vault was installed and whether auto-update is safe."""
    distribution = distribution or _load_distribution()
    prefix = Path(sys_prefix or sys.prefix)
    executable = Path(sys_executable or sys.executable)
    platform_name = platform_name or os.name
    normalized_prefix = _normalize_path(prefix)
    normalized_executable = _normalize_path(executable)
    direct_url = _load_direct_url(distribution)
    installer = _load_installer(distribution)
    source_path = _source_path_from_direct_url(direct_url, platform_name=platform_name)

    if (prefix / "pipx_metadata.json").exists() or "/pipx/venvs/" in normalized_prefix:
        auto_command = ("pipx", "install", "--force", _git_spec(latest_release.tag))
        pipx_available = shutil.which("pipx") is not None
        return InstallationState(
            method=InstallMethod.PIPX,
            detail="Detected a pipx-managed virtual environment.",
            auto_update_supported=pipx_available,
            auto_update_command=auto_command if pipx_available else None,
            manual_command=_format_command(auto_command),
        )

    if (prefix / "uv-receipt.toml").exists() or "/uv/tools/" in normalized_prefix:
        auto_command = ("uv", "tool", "install", _git_spec(latest_release.tag))
        uv_available = shutil.which("uv") is not None
        return InstallationState(
            method=InstallMethod.UV_TOOL,
            detail="Detected a uv tool environment.",
            auto_update_supported=uv_available,
            auto_update_command=auto_command if uv_available else None,
            manual_command=_format_command(auto_command),
        )

    if direct_url and direct_url.get("dir_info", {}).get("editable"):
        return InstallationState(
            method=InstallMethod.EDITABLE_DEV,
            detail=_editable_detail(source_path, executable),
            auto_update_supported=False,
            auto_update_command=None,
            manual_command=_editable_manual_command(source_path, latest_release.tag),
        )

    if source_path is not None:
        return InstallationState(
            method=InstallMethod.EDITABLE_DEV,
            detail=_editable_detail(source_path, executable),
            auto_update_supported=False,
            auto_update_command=None,
            manual_command=_editable_manual_command(source_path, latest_release.tag),
        )

    in_virtualenv = sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(os.environ.get("VIRTUAL_ENV"))
    if installer == "pip" or in_virtualenv:
        detail = "Detected a pip-managed virtual environment." if in_virtualenv else "Detected a pip-managed environment."
        return InstallationState(
            method=InstallMethod.PIP,
            detail=detail,
            auto_update_supported=False,
            auto_update_command=None,
            manual_command=_format_command(
                (sys.executable, "-m", "pip", "install", "--upgrade", latest_release.archive_url)
            ),
        )

    recommended_command = _recommended_manual_command(latest_release.tag)
    extra_detail = " Could not map the current executable to pipx, uv tool, or a local editable install."
    if "/uv/tools/" in normalized_executable or "/pipx/venvs/" in normalized_executable:
        extra_detail = " The executable path looks tool-managed, but the environment metadata was incomplete."
    return InstallationState(
        method=InstallMethod.UNKNOWN,
        detail="Install method is unknown or ambiguous." + extra_detail,
        auto_update_supported=False,
        auto_update_command=None,
        manual_command=recommended_command,
    )


def perform_update(
    plan: UpdatePlan,
    *,
    runner=subprocess.run,
    version_reader=None,
) -> str:
    """Execute the planned update and verify the resulting installed version."""
    if not plan.installation.auto_update_supported or not plan.installation.auto_update_command:
        raise UpdateError("Auto-update is not supported for this installation.")

    if not plan.needs_update:
        return plan.current_version

    result = runner(
        list(plan.installation.auto_update_command),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise UpdateError(
            f"Update command failed with exit code {result.returncode}."
        )

    reader = version_reader or read_version_from_subprocess
    verified_version = reader(runner=runner)
    if _compare_versions(verified_version, plan.latest_release.version) != 0:
        raise UpdateError(
            "Update completed, but post-update verification reported "
            f"{verified_version} instead of {plan.latest_release.version}."
        )
    return verified_version


def read_version_from_subprocess(*, runner=subprocess.run) -> str:
    """Read the installed Hermes Vault version from a fresh Python subprocess."""
    result = runner(
        [sys.executable, "-c", _READ_VERSION_SNIPPET],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise UpdateError(f"Failed to verify the installed Hermes Vault version: {message}")
    value = result.stdout.strip()
    if not value:
        raise UpdateError("Failed to verify the installed Hermes Vault version: empty response.")
    return _normalize_version(value)


def _load_distribution() -> importlib_metadata.Distribution | None:
    try:
        return importlib_metadata.distribution(PACKAGE_NAME)
    except importlib_metadata.PackageNotFoundError:
        return None


def _load_direct_url(distribution: importlib_metadata.Distribution | None) -> dict | None:
    if distribution is None:
        return None
    raw = distribution.read_text("direct_url.json")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _load_installer(distribution: importlib_metadata.Distribution | None) -> str | None:
    if distribution is None:
        return None
    raw = distribution.read_text("INSTALLER")
    return raw.strip() if raw else None


def _source_path_from_direct_url(direct_url: dict | None, *, platform_name: str) -> Path | None:
    if not direct_url:
        return None
    url = str(direct_url.get("url", "")).strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme != "file":
        return None
    raw_path = url2pathname(unquote(parsed.path))
    if platform_name == "nt" and raw_path.startswith("/") and len(raw_path) > 2 and raw_path[2] == ":":
        raw_path = raw_path[1:]
    if parsed.netloc:
        raw_path = f"//{parsed.netloc}{raw_path}"
    return Path(raw_path)


def _editable_detail(source_path: Path | None, executable: Path) -> str:
    if source_path:
        return f"Detected a local source install at {source_path}."
    return f"Detected a local source install from executable {executable}."


def _editable_manual_command(source_path: Path | None, tag: str) -> str:
    if source_path and (source_path / ".git").exists():
        path_text = str(source_path)
        return _join_shell_steps(
            [
                _format_command(("git", "-C", path_text, "fetch", "--tags")),
                _format_command(("git", "-C", path_text, "checkout", tag)),
                _format_command((sys.executable, "-m", "pip", "install", "-e", path_text)),
            ]
        )
    if source_path:
        return _format_command((sys.executable, "-m", "pip", "install", "-e", str(source_path)))
    return _format_command((sys.executable, "-m", "pip", "install", "-e", "."))


def _recommended_manual_command(tag: str) -> str:
    git_spec = _git_spec(tag)
    if shutil.which("uv") is not None:
        return _format_command(("uv", "tool", "install", git_spec))
    if shutil.which("pipx") is not None:
        return _format_command(("pipx", "install", git_spec))
    return _format_command((sys.executable, "-m", "pip", "install", "--upgrade", RELEASE_ARCHIVE_URL.format(tag=tag)))


def _git_spec(tag: str) -> str:
    return f"git+{REPOSITORY_GIT_URL}@{tag}"


def _compare_versions(left: str, right: str) -> int:
    left_key = _parse_version_key(left)
    right_key = _parse_version_key(right)
    if left_key == right_key:
        return 0
    return 1 if left_key > right_key else -1


def _parse_version_key(value: str) -> tuple[tuple[int, ...], int, str]:
    normalized = _normalize_version(value)
    match = _VERSION_RE.match(normalized)
    if not match:
        raise UpdateError(f"Unsupported version format: {value}")
    numbers = tuple(int(part) for part in match.group("numbers").split("."))
    suffix = match.group("suffix")
    # Stable releases sort after pre-release suffixes like rc1 or dev0.
    suffix_rank = 1 if not suffix else 0
    return numbers, suffix_rank, suffix


def _normalize_version(value: str) -> str:
    normalized = str(value).strip()
    if normalized.startswith("v"):
        normalized = normalized[1:]
    return normalized


def _normalize_path(path: Path) -> str:
    return str(path).replace("\\", "/").lower()


def _format_command(parts: tuple[str, ...] | list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(list(parts))
    return shlex.join(list(parts))


def _join_shell_steps(steps: list[str]) -> str:
    return " && ".join(steps)
