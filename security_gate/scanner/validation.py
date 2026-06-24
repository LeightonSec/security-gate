import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# _ENTRY_POINTS: (pattern, detail, severity)
# yaml.load is CRITICAL (arbitrary code execution if input is attacker-controlled).
# All other entry points are HIGH (missing validation boundary).
_ENTRY_POINTS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"request\.get_json\s*\("),
     "Flask request.get_json() — validate with Pydantic before use",  # gate: ignore - scanner detail string, not a runtime call
     Severity.HIGH),
    (re.compile(r"request\.(form|args|data|json)\b"),
     "Flask request input — validate with Pydantic before use",
     Severity.HIGH),
    (re.compile(r"response\.json\s*\(\s*\)"),
     "External API response.json() used directly — validate schema before processing",  # gate: ignore - scanner detail string, not a runtime call
     Severity.HIGH),
    (re.compile(r"json\.loads\s*\("),
     "json.loads on external data — validate structure before use",
     Severity.HIGH),
    (re.compile(r"yaml\.safe_load\s*\("),
     "yaml.safe_load — validate schema before use",
     Severity.HIGH),
    (re.compile(r"yaml\.load\s*\("),
     "yaml.load (unsafe) — arbitrary code execution if input is attacker-controlled; "  # gate: ignore - scanner detail string, not a runtime call
     "use yaml.safe_load and validate schema",
     Severity.CRITICAL),
]

# Matches actual validation usage — instantiation, method calls, library access.
# Import lines are excluded from the window before this is applied, so a top-of-file
# 'from pydantic import BaseModel' cannot suppress a finding 100 lines away.
_VALIDATION_USAGE = re.compile(
    r"(?:BaseModel|Schema|Validator|TypedDict)\s*\(|"
    r"\.(?:parse_obj|parse_raw|model_validate|from_orm)\s*\(|"
    r"\bvalidate\s*\(|"
    r"marshmallow\.\w+|cerberus\.\w+|voluptuous\.\w+",
    re.IGNORECASE,
)

_VALIDATION_WINDOW = 5  # lines forward from entry point to check for validation usage


class ValidationScanner(BaseScanner):
    name = "missing_validation"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            findings.extend(self._scan_file(root, py_file, lines))
        return findings

    def _scan_file(self, root: Path, py_file: Path, lines: list[str]) -> list[Finding]:
        findings = []
        rel = self._rel(root, py_file)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or self._suppressed(line):
                continue

            for pattern, detail, severity in _ENTRY_POINTS:
                if not pattern.search(line):
                    continue

                # Check _VALIDATION_WINDOW lines forward (including current line) for
                # actual validation usage. Import lines are stripped from the window to
                # prevent a top-of-file library import from masking unvalidated entry points.
                idx = lineno - 1
                window = [
                    wl for wl in lines[idx : idx + _VALIDATION_WINDOW + 1]
                    if not wl.strip().startswith(("import ", "from "))
                ]
                if _VALIDATION_USAGE.search("\n".join(window)):
                    break  # validation in proximity — not a finding

                findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    file=rel,
                    line=lineno,
                    match=stripped[:120],
                    detail=detail,
                    checklist_item="PHASE-1-1: Schema validation on all inputs",
                ))
                break  # one finding per line

        return findings
