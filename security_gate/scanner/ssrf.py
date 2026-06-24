"""Server-side request forgery (SSRF) scanner.

Detects HTTP client calls where the URL argument is not a string literal —
variables, f-strings, and function call results are all potentially user-controlled
and enable SSRF attacks when they reach network requests.

Covers requests, httpx, and urllib.request. aiohttp is not covered because the
URL is passed at the method call level (session.get(url)) where the type of
session cannot be statically determined by a regex scanner.

Known limitation: the literal guard checks the first token of the URL argument.
String concatenation starting with a literal (e.g. requests.get with BASE_URL + path)
is not detected. Config constants (e.g. requests.get with settings.API_URL) will fire
as false positives — suppress with: # gate: ignore — URL from application config

  Safe:    requests.get("https://api.example.com/data")  # gate: ignore - docstring example, not executed
  Unsafe:  requests.get(user_url)          # gate: ignore — docstring example, not executed
  Unsafe:  requests.get(f"http://{host}")  # gate: ignore — docstring example, not executed
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_LITERAL_GUARD = r"(?!['\"]|[bBrRuU]+['\"])"

_REQUESTS = re.compile(
    r"\brequests\.(get|post|put|patch|delete|request|head)\s*\(\s*" + _LITERAL_GUARD
)
_HTTPX = re.compile(
    r"\bhttpx\.(get|post|put|patch|delete|request)\s*\(\s*" + _LITERAL_GUARD
)
_URLLIB = re.compile(
    r"\burllib\.request\.(urlopen|urlretrieve)\s*\(\s*" + _LITERAL_GUARD
)

_CHECKS = [
    (_REQUESTS, "requests"),
    (_HTTPX, "httpx"),
    (_URLLIB, "urllib.request"),
]


class SsrfScanner(BaseScanner):
    name = "ssrf"

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

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or self._suppressed(line):
                continue

            for pattern, lib in _CHECKS:
                if pattern.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i + 1,
                        match=stripped[:120],
                        detail=(
                            f"{lib} HTTP call with non-literal URL — SSRF risk if URL "
                            "contains user-controlled data. Use an allowlist to restrict "
                            "permitted destinations."
                        ),
                        checklist_item="SSRF-1: All outbound URLs validated against an allowlist before use",
                    ))
                    break

        return findings
