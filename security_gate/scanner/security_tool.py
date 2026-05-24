import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_PATH_TRAVERSAL = [
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"\.\.[\\/]\.\.[\\/]"),  # ../../ or ..\..\ path traversal
    re.compile(r"C:\\Windows\\System32", re.IGNORECASE),
]

_INJECTION_PAYLOADS = [
    re.compile(r"';\s*DROP\s+TABLE", re.IGNORECASE),
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),
    re.compile(r"<script[^>]*>\s*alert", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+src\s*=\s*x", re.IGNORECASE),
]

_TEST_PATH_PARTS = {"tests", "test", "fixtures", "fixture"}


class SecurityToolScanner(BaseScanner):
    name = "security_tool"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            if not any(part in _TEST_PATH_PARTS for part in py_file.parts):
                continue
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
                    continue

                for pattern in _PATH_TRAVERSAL:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, py_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail="Path traversal or system file target in test fixture — confirm string is synthetic, not a real payload",
                            checklist_item="SEC-TOOL-1: Test fixtures contain no real path traversal payloads",
                        ))
                        break

                for pattern in _INJECTION_PAYLOADS:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, py_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail="Injection payload string in test fixture — confirm string is synthetic and not derived from a real attack",
                            checklist_item="SEC-TOOL-2: Test fixtures contain no real exploit payloads",
                        ))
                        break

        return findings
