"""Git history secrets scanner.

Searches git commit history for secret patterns using `git log -G<regex>`.
The -G flag finds commits where the diff contains lines matching the pattern —
additions OR deletions — so a secret committed and then deleted will appear
twice (once for add, once for remove). The finding count reflects commits that
touched the pattern, not live secrets.

Known limitation: shallow clones (`git clone --depth=N`) only have partial
history. A shallow clone that looks clean may contain secrets in hidden commits.
This scanner emits an INFO finding when a shallow clone is detected so the gap
is visible rather than silent.

Timeout is configurable via GIT_SCAN_TIMEOUT env var (default: 30s).
"""
import os
import subprocess
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_CRITICAL_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"xox[baprs]-[A-Za-z0-9]{10,}", "Slack token"),
]

_HIGH_PATTERNS: list[tuple[str, str]] = [
    (r"API_KEY=[A-Za-z0-9+/]{32,}", "API key assignment"),
    (r"SECRET_KEY=[A-Za-z0-9+/]{32,}", "secret key assignment"),
]

_DEFAULT_TIMEOUT = 30


class GitHistoryScanner(BaseScanner):
    name = "git_history"

    def scan(self, root: Path) -> list[Finding]:
        if not (root / ".git").is_dir():
            return []

        timeout = int(os.environ.get("GIT_SCAN_TIMEOUT", _DEFAULT_TIMEOUT))
        findings = []

        shallow_finding = self._check_shallow(root)
        if shallow_finding:
            findings.append(shallow_finding)

        all_patterns = (
            [(p, label, Severity.CRITICAL) for p, label in _CRITICAL_PATTERNS] +
            [(p, label, Severity.HIGH) for p, label in _HIGH_PATTERNS]
        )
        for pattern, label, severity in all_patterns:
            commits, error = self._grep_history(root, pattern, timeout)
            if error is not None:
                # HIGH, not MEDIUM: this check feeds gating CRITICAL/HIGH
                # findings, and git is local infrastructure — a history that
                # cannot be scanned must fail closed, not pass silently.
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    file="git history",
                    line=1,
                    match=error[:120],
                    detail=(
                        f"git history scan could not complete ({error}) — "
                        "secrets in history cannot be confirmed absent. "
                        "Fix the environment or accept explicitly via accepted-findings.toml."
                    ),
                    checklist_item="GIT-HIST-1: No secrets in git history (purge with git-filter-repo)",
                ))
                return findings  # same infrastructure failure would repeat for every pattern
            if commits:
                detail = (
                    f"{label} pattern found in {len(commits)} commit diff(s) — "
                    "recoverable even if later deleted. "
                    f"Purge with git-filter-repo. Commits: {', '.join(commits[:3])}"
                ) if severity == Severity.CRITICAL else (
                    f"{label} pattern found in {len(commits)} commit diff(s) — "
                    "may be a false positive on example values; verify manually. "
                    f"Commits: {', '.join(commits[:3])}"
                )
                findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    file="git history",
                    line=1,
                    match=commits[0][:80],
                    detail=detail,
                    checklist_item="GIT-HIST-1: No secrets in git history (purge with git-filter-repo)",
                ))

        return findings

    def _check_shallow(self, root: Path) -> Finding | None:
        shallow_file = root / ".git" / "shallow"
        if not shallow_file.exists():
            return None
        return Finding(
            scanner=self.name,
            severity=Severity.INFO,
            file="git history",
            line=1,
            match=".git/shallow exists",
            detail=(
                "Shallow clone detected — git history scan is incomplete. "
                "Run 'git fetch --unshallow' before trusting a clean result."
            ),
            checklist_item="GIT-HIST-1: No secrets in git history (purge with git-filter-repo)",
        )

    def _grep_history(self, root: Path, pattern: str, timeout: int) -> tuple[list[str], str | None]:
        """Returns (commit hashes, error). error is set when the scan could not
        run at all; an empty commit list with no error is a genuine no-matches
        result. The two must stay distinguishable — collapsing an error into []
        reports an unscannable history as clean.

        Exit codes verified against real repos: git log exits 0 for both match
        and no-match (empty stdout signals no matches); 128 for real failures
        (bad regex, not a repo). The (0, 1) allowance is inherited slack."""
        try:
            result = subprocess.run(
                [
                    "git", "-C", str(root),
                    "log", "--all", "--format=%H",
                    f"-G{pattern}", "--no-merges",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return [], (
                f"timed out after {timeout}s — increase GIT_SCAN_TIMEOUT or run "
                "'git fetch --unshallow' on shallow clones"
            )
        except FileNotFoundError:
            return [], "git executable not found on PATH"
        if result.returncode not in (0, 1):
            stderr_first = (result.stderr.strip().splitlines() or [""])[0]
            return [], f"git log exited {result.returncode}: {stderr_first[:120]}"
        return [c.strip() for c in result.stdout.splitlines() if c.strip()], None
