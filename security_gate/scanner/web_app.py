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
_SQL_DDL = re.compile(
    r"\b(ALTER|CREATE|DROP)\s+TABLE\b|\bPRAGMA\b",
    re.IGNORECASE,
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

# Rate limiting on LLM routes — file-level heuristic, same-file scope only.
# Known gap: Limiter configured in app factory or a separate file is not detected.
# Infrastructure-level rate limiting (nginx, Cloudflare) is always invisible here.
# Use # gate: ignore with a note confirming the layer (e.g. "rate limited at nginx")
# to suppress when controls are applied outside this file.
_FLASK_ROUTE = re.compile(r"@\w+\.route\s*\(")
_LLM_SINK_RATE = re.compile(
    r"(?:client\.messages\.create|"
    r"openai\.chat\.completions\.create|"
    r"ChatCompletion\.create|"
    r"anthropic\.messages\.create|"
    r"llm\.predict\s*\(|llm\.invoke\s*\()"
)
_RATE_LIMIT_IMPORT = re.compile(
    r"(?:from\s+flask_limiter|import\s+flask_limiter|"
    r"from\s+slowapi|import\s+slowapi|"
    r"Limiter\s*\(|RateLimiter\s*\()",
    re.IGNORECASE,
)
_RATE_LIMIT_DECORATOR = re.compile(
    r"@.*(?:limiter\.limit|rate_limit|ratelimit|throttle)",
    re.IGNORECASE,
)
_RATE_LIMIT_WINDOW = 20


class WebAppScanner(BaseScanner):
    name = "web_app"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                text = py_file.read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()
            except OSError:
                continue

            has_flask_route = bool(_FLASK_ROUTE.search(text))
            has_llm_sink = bool(_LLM_SINK_RATE.search(text))
            has_rate_limiting = bool(_RATE_LIMIT_IMPORT.search(text))

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
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

                if (_SQL_FSTRING.search(line) or _SQL_CONCAT.search(line)) and not _SQL_DDL.search(line):
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

                if (has_flask_route and has_llm_sink and not has_rate_limiting
                        and _LLM_SINK_RATE.search(line)
                        and not self._suppressed(line)):
                    window = lines[max(0, i - _RATE_LIMIT_WINDOW) : i + 1]
                    if not any(_RATE_LIMIT_DECORATOR.search(wl) for wl in window):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, py_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail=(
                                "LLM API call in Flask route with no rate limiting detected — "
                                "cost attack and data exfiltration risk"
                            ),
                            checklist_item=(
                                "WEB-5: Rate limiting confirmed at route, app, or infrastructure layer "
                                "(document which). Add # gate: ignore if applied outside this file."
                            ),
                        ))

        return findings
