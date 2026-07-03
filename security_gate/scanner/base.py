import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_SUPPRESS = re.compile(r"(?:#|//)\s*gate:\s*ignore", re.IGNORECASE)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Severity → numeric for sorting
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    scanner: str
    severity: Severity
    file: str
    line: int
    match: str
    detail: str
    checklist_item: str

    def sort_key(self) -> tuple:
        return (_SEVERITY_ORDER.get(self.severity, 99), self.file, self.line)

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "match": self.match,
            "detail": self.detail,
            "checklist_item": self.checklist_item,
        }


_DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", "__pycache__", "node_modules",
    ".venv", "venv", "dist", "build", ".eggs",
})


class BaseScanner:
    name: str = "base"
    # Severity the CLI assigns to this scanner's integrity_errors. HIGH because
    # an unread file removes coverage from gating checks; a scanner whose OWN
    # findings never gate (e.g. the semgrep layer) must override this rather
    # than inherit a gating severity for a non-gating coverage loss.
    integrity_severity: Severity = Severity.HIGH

    def __init__(self, excludes: frozenset[str] = frozenset()) -> None:
        self._excludes = _DEFAULT_EXCLUDE_DIRS | excludes
        # (path, error) for every file this scanner discovered but could not
        # read or parse. A skipped file is unverified code — the CLI turns
        # these into gating scan_integrity findings; skipping silently would
        # let the gate pass on files it never inspected. Tool failures (git
        # missing, semgrep crash, DAST probe errors) do NOT belong here — they
        # emit their own Findings with scanner-specific severity and wording.
        self.integrity_errors: list[tuple[Path, str]] = []

    def scan(self, root: Path) -> list[Finding]:
        raise NotImplementedError

    def _read_text(self, path: Path) -> str | None:
        # Strict decode: errors="replace" would silently scan garbage in place
        # of undecodable bytes. UnicodeDecodeError is a ValueError, not OSError.
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            self.integrity_errors.append((path, str(exc)))
            return None

    def _read_lines(self, path: Path) -> list[str] | None:
        text = self._read_text(path)
        return None if text is None else text.splitlines()

    def _py_files(self, root: Path) -> list[Path]:
        return [
            p for p in root.rglob("*.py")
            if not any(part in self._excludes for part in p.parts)
            and not any(part.endswith(".egg-info") for part in p.parts)
        ]

    def _ts_files(self, root: Path) -> list[Path]:
        return [
            p for p in root.rglob("*.ts")
            if not any(part in self._excludes for part in p.parts)
            and not p.name.endswith(".d.ts")
        ]

    def _suppressed(self, line: str) -> bool:
        return bool(_SUPPRESS.search(line))

    def _rel(self, root: Path, path: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return str(path)
