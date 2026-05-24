import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# External data entry points that need schema validation
_ENTRY_POINTS = [
    (re.compile(r"request\.get_json\s*\("),
     "Flask request.get_json() — validate with Pydantic before use"),
    (re.compile(r"request\.(form|args|data|json)\b"),
     "Flask request input — validate with Pydantic before use"),
    (re.compile(r"response\.json\s*\(\s*\)"),
     "External API response.json() used directly — validate schema before processing"),
    (re.compile(r"json\.loads\s*\("),
     "json.loads on external data — validate structure before use"),
    (re.compile(r"yaml\.safe_load\s*\("),
     "yaml.safe_load — validate schema before use"),
    (re.compile(r"yaml\.load\s*\("),
     "yaml.load (unsafe) — use yaml.safe_load and validate schema"),
]

# Validation signals — if any of these appear in the same file, skip
_VALIDATION_SIGNALS = re.compile(
    r"(BaseModel|pydantic|Schema|Validator|validate\s*\(|TypedDict|marshmallow|cerberus|voluptuous)",
    re.IGNORECASE,
)


class ValidationScanner(BaseScanner):
    name = "missing_validation"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                text = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # If the file imports a validation library, treat it as handled
            if _VALIDATION_SIGNALS.search(text):
                continue

            lines = text.splitlines()
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
                    continue
                for pattern, detail in _ENTRY_POINTS:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            file=self._rel(root, py_file),
                            line=lineno,
                            match=stripped[:120],
                            detail=detail,
                            checklist_item="PHASE-1-1: Schema validation on all inputs",
                        ))
                        break
        return findings
