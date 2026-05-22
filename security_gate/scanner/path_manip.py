import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_PATTERNS = [
    (re.compile(r"sys\.path\.(insert|append|extend)\s*\("),
     "sys.path manipulation — implicit trust between repos, brittle path coupling"),
    (re.compile(r"importlib\.import_module\s*\(.*\.\./"),
     "importlib with relative path — potential path traversal on module load"),
]


class PathManipScanner(BaseScanner):
    name = "path_manipulation"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for pattern, detail in _PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            file=self._rel(root, py_file),
                            line=lineno,
                            match=stripped[:120],
                            detail=detail,
                            checklist_item="PHASE-1-7: No relative-path repo coupling",
                        ))
                        break
        return findings
