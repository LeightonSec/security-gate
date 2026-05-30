"""Bare suppression scanner — enforces rationale on all gate: ignore comments.

A bare '# gate: ignore' or '// gate: ignore' with no explanation text is a bypass,
not a suppression. This scanner flags those so they don't silently erode the gate.

Valid:   # gate: ignore — reads tool state file, not external input
Invalid: # gate: ignore    (no rationale text — flagged HIGH by this scanner)

The pattern anchors to end-of-line (\\s*$) to avoid false positives on lines where
'# gate: ignore' appears inside a string literal or in a documentation comment that
explains the syntax (e.g. "Add # gate: ignore — <reason> to suppress this finding").
Those lines will always have text after 'ignore' and therefore not match.
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# Matches trailing gate: ignore with nothing after it (bare suppression)
_BARE_SUPPRESS = re.compile(r"(?:#|//)\s*gate:\s*ignore\s*$", re.IGNORECASE)


class BareSuppressScanner(BaseScanner):
    name = "bare_suppress"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for f in self._py_files(root) + self._ts_files(root):
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if _BARE_SUPPRESS.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, f),
                        line=i + 1,
                        match=line.strip()[:120],
                        detail=(
                            "Bare 'gate: ignore' with no rationale — "
                            "add explanation after the dash: # gate: ignore — <reason>"
                        ),
                        checklist_item="GATE-0: All suppressions require rationale text",
                    ))
        return findings
