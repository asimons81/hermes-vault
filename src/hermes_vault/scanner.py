from __future__ import annotations

import fnmatch
import importlib.util
from pathlib import Path

from hermes_vault.config import AppSettings
from hermes_vault.detectors import detect_matches, fingerprint_secret
from hermes_vault.models import FindingRecord, FindingSeverity
from hermes_vault.policy import PolicyEngine
from hermes_vault.permissions import permission_finding

_HAS_PATHSPEC = importlib.util.find_spec("pathspec") is not None


TEXT_SUFFIXES = {
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".txt",
    ".md",
    ".sh",
    ".bashrc",
    ".zshrc",
    ".profile",
}
SECRET_TEXT_FILENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
}
SECRET_TEXT_PATTERNS = (
    ".env.*",
    ".aws/credentials",
    ".docker/config.json",
)
MAX_FILE_BYTES = 512_000
COMMENT_PREFIXES = ("#", "//", ";", "--")


class Scanner:
    def __init__(self, settings: AppSettings, policy: PolicyEngine | None = None) -> None:
        self.settings = settings
        self.policy = policy or PolicyEngine()

    def scan(self, paths: list[Path] | None = None) -> list[FindingRecord]:
        roots = [path.expanduser() for path in (paths or self.settings.default_scan_roots)]
        findings: list[FindingRecord] = []
        fingerprint_paths: dict[str, list[str]] = {}
        ignore_patterns = self._load_ignore_patterns()

        for root in roots:
            if not root.exists():
                continue
            if root.is_file():
                findings.extend(self._scan_file(root, fingerprint_paths))
                insecure = permission_finding(root)
                if insecure:
                    findings.append(insecure)
                continue

            for path in root.rglob("*"):
                if self._is_ignored(path, ignore_patterns):
                    continue
                if not path.is_file():
                    continue
                findings.extend(self._scan_file(path, fingerprint_paths))
                insecure = permission_finding(path)
                if insecure:
                    findings.append(insecure)

        findings.extend(self._duplicate_findings(fingerprint_paths))
        return findings

    def _scan_file(
        self, path: Path, fingerprint_paths: dict[str, list[str]]
    ) -> list[FindingRecord]:
        if not self._looks_like_text(path):
            return []
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return [
                    FindingRecord(
                        severity=FindingSeverity.medium,
                        kind="skipped_large_file",
                        path=str(path),
                        recommendation=(
                            "Review this large secret-bearing text file manually or split it so Hermes Vault can scan it."
                        ),
                        detail=f"File exceeds scanner size limit of {MAX_FILE_BYTES} bytes.",
                    )
                ]
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        file_findings: list[FindingRecord] = []
        severity, recommendation_prefix = self._classify_plaintext_path(path)
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith(COMMENT_PREFIXES):
                continue
            for detector, secret in detect_matches(line):
                fingerprint = fingerprint_secret(secret)
                fingerprint_paths.setdefault(fingerprint, []).append(str(path))
                file_findings.append(
                    FindingRecord(
                        severity=severity,
                        kind="plaintext_secret",
                        path=str(path),
                        service=detector.service,
                        fingerprint=fingerprint,
                        recommendation=recommendation_prefix + f" {detector.recommendation}",
                        line_number=line_number,
                        detail=f"Detected {detector.credential_type} candidate",
                    )
                )
        return file_findings

    def _duplicate_findings(self, fingerprint_paths: dict[str, list[str]]) -> list[FindingRecord]:
        duplicates: list[FindingRecord] = []
        for fingerprint, paths in fingerprint_paths.items():
            if len(paths) < 2:
                continue
            for path in paths:
                duplicates.append(
                    FindingRecord(
                        severity=FindingSeverity.high,
                        kind="duplicate_secret",
                        path=path,
                        fingerprint=fingerprint,
                        recommendation="Consolidate this credential into Hermes Vault so there is a single source of truth.",
                        detail=f"Duplicate fingerprint found in {len(paths)} files.",
                    )
                )
        return duplicates

    def _looks_like_text(self, path: Path) -> bool:
        if path.suffix.lower() in TEXT_SUFFIXES:
            return True
        if path.name in SECRET_TEXT_FILENAMES:
            return True
        normalized = path.as_posix()
        if any(fnmatch.fnmatch(path.name, pattern) or normalized.endswith(pattern) for pattern in SECRET_TEXT_PATTERNS):
            return True
        return any(path.name.endswith(suffix) for suffix in TEXT_SUFFIXES)

    def _load_ignore_patterns(self) -> list[str]:
        if not self.settings.ignore_path.exists():
            return []
        return [
            line.strip().replace("\\", "/")
            for line in self.settings.ignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def _is_ignored(self, path: Path, patterns: list[str]) -> bool:
        if not patterns:
            return False
        text = path.as_posix()
        if any(text == pattern for pattern in patterns):
            return True
        if _HAS_PATHSPEC:
            import pathspec

            spec = pathspec.PathSpec.from_lines("gitignore", patterns)
            return spec.match_file(text)
        return any(fnmatch.fnmatch(text, pattern) for pattern in patterns)

    def _classify_plaintext_path(self, path: Path) -> tuple[FindingSeverity, str]:
        return self.policy.classify_plaintext_storage(path)
