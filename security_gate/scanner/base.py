import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_SUPPRESS = re.compile(r"#\s*gate:\s*ignore", re.IGNORECASE)


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

    def __init__(self, excludes: frozenset[str] = frozenset()) -> None:
        self._excludes = _DEFAULT_EXCLUDE_DIRS | excludes

    def scan(self, root: Path) -> list[Finding]:
        raise NotImplementedError

    def _py_files(self, root: Path) -> list[Path]:
        return [
            p for p in root.rglob("*.py")
            if not any(part in self._excludes for part in p.parts)
            and not any(part.endswith(".egg-info") for part in p.parts)
        ]

    def _suppressed(self, line: str) -> bool:
        return bool(_SUPPRESS.search(line))

    def _rel(self, root: Path, path: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return str(path)
