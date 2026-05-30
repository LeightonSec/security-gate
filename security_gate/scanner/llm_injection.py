"""LLM prompt injection taint scanner.

Known limitation: intra-function scope only. If the tainted variable is passed
into a helper function that calls the LLM, this scanner will not follow it.
No cross-function or cross-file taint tracking. Use # gate: ignore with a
rationale comment to suppress false positives (e.g. input validated upstream).
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_REQUEST_SRC = re.compile(
    r"\brequest\s*\.\s*(?:get_json|get_data|json|form|args|data|values)",
)

# Variable directly assigned from a request accessor — not through a class constructor
_SOURCE_ASSIGN = re.compile(
    r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*=.*\brequest\s*\.\s*(?:get_json|get_data|json|form|args|data|values)"
)

_LLM_SINK = re.compile(
    r"(?:client\.messages\.create|"
    r"anthropic\.messages\.create|"
    r"\.chat\.completions\.create|"
    r"ChatCompletion\.create|"
    r"llm\.predict\s*\(|"
    r"llm\.invoke\s*\(|"
    r"chain\.run\s*\()"
)

# Require actual function call syntax to avoid matching bare words in comments
_SANITIZE = re.compile(
    r"(?:re\.sub\s*\(|re\.escape\s*\(|html\.escape\s*\(|bleach\.clean\s*\(|"
    r"sanitize\w*\s*\(|validate_\w+\s*\(|clean_\w+\s*\(|filter_\w+\s*\(|"
    r"truncate_\w+\s*\(|BaseModel\s*\(|pydantic\s*\.|marshmallow\s*\.|"
    r"cerberus\s*\.|voluptuous\s*\.|Schema\s*\()",
    re.IGNORECASE,
)

_SINK_WINDOW = 15


class LlmInjectionScanner(BaseScanner):
    name = "llm_injection"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                text = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not _REQUEST_SRC.search(text) or not _LLM_SINK.search(text):
                continue
            findings.extend(self._scan_file(root, py_file, text.splitlines()))
        return findings

    def _scan_file(self, root: Path, py_file: Path, lines: list[str]) -> list[Finding]:
        findings = []

        # Pass 1: collect variables directly assigned from request data
        tainted: list[tuple[int, str]] = []  # (line_idx, var_name)
        for i, line in enumerate(lines):
            if self._suppressed(line):
                continue
            m = _SOURCE_ASSIGN.match(line)
            if m:
                tainted.append((i, m.group(1)))

        if not tainted:
            return []

        # Pass 2: find LLM sink calls, check if tainted var appears in call block
        for i, line in enumerate(lines):
            if self._suppressed(line) or not _LLM_SINK.search(line):
                continue

            sink_block = "\n".join(lines[i : i + _SINK_WINDOW])

            for src_idx, var_name in tainted:
                if src_idx >= i:
                    continue  # source must precede sink
                if not re.search(r"\b" + re.escape(var_name) + r"\b", sink_block):
                    continue

                between = "\n".join(lines[src_idx : i + 1])
                if _SANITIZE.search(between):
                    continue

                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    file=self._rel(root, py_file),
                    line=i + 1,
                    match=line.strip()[:120],
                    detail=(
                        f"'{var_name}' (request input, line {src_idx + 1}) flows into LLM API "
                        "call without sanitization — prompt injection risk. "
                        "Add # gate: ignore if input is validated upstream."
                    ),
                    checklist_item="LLM-INJ-1: User-controlled input sanitised before LLM call",
                ))
                break  # one finding per sink line

        return findings
