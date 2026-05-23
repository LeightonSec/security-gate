import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_DEBUG_ENABLED = re.compile(
    r"(DEBUG\s*=\s*True|app\.debug\s*=\s*True)",
)

_SQL_FSTRING = re.compile(
    r"\.(execute|executemany)\s*\(\s*f[\"']",
)
_SQL_CONCAT = re.compile(
    r"\.(execute|executemany)\s*\(\s*[\"'].*[\"']\s*\+",
)

_CORS_WILDCARD = re.compile(
    r"(CORS\s*\(\s*app\s*\)|Access-Control-Allow-Origin[\"']?\s*:\s*[\"']?\*)",
)

_ROUTE_STATE_CHANGING = re.compile(
    r"@\w+\.route\s*\([^)]*methods\s*=\s*\[[^\]]*(?:POST|PUT|DELETE|PATCH)",
)
_AUTH_DECORATOR = re.compile(
    r"@.*(?:login_required|jwt_required|require_auth|token_required|authenticated|permission_required)",
)

_AUTH_WINDOW = 6  # lines forward to look for auth decorator after route decorator


class WebAppScanner(BaseScanner):
    name = "web_app"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                if _DEBUG_ENABLED.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, py_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="Debug mode enabled — exposes stack traces, interactive debugger, and internal state",
                        checklist_item="WEB-1: Debug mode disabled in production",
                    ))

                if _SQL_FSTRING.search(line) or _SQL_CONCAT.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=self._rel(root, py_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="SQL query built with string interpolation or concatenation — SQL injection risk",
                        checklist_item="WEB-2: All SQL queries use parameterised statements",
                    ))

                if _CORS_WILDCARD.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, py_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="CORS wildcard allows any origin to make credentialed cross-origin requests",
                        checklist_item="WEB-3: CORS origin restricted to known domains",
                    ))

                if _ROUTE_STATE_CHANGING.search(line):
                    window = lines[i : i + _AUTH_WINDOW + 1]
                    if not any(_AUTH_DECORATOR.search(wl) for wl in window):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, py_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail="State-changing route (POST/PUT/DELETE/PATCH) has no recognised auth decorator in scope",
                            checklist_item="WEB-4: All state-changing endpoints require authentication",
                        ))

        return findings
