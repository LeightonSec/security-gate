import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# (pattern, detail, checklist_item)
_PATTERNS: list[tuple[str, str, str]] = [
    # HTTP clients
    (r"requests\.(get|post|put|patch|delete|request|head)\s*\(",
     "requests HTTP call — data may leave trust boundary",
     "PRE-BUILD-5: Audit outbound API calls"),
    (r"httpx\.(get|post|put|patch|delete|request)\s*\(",
     "httpx HTTP call — data may leave trust boundary",
     "PRE-BUILD-5: Audit outbound API calls"),
    (r"aiohttp\.ClientSession\s*\(",
     "aiohttp async HTTP client — data may leave trust boundary",
     "PRE-BUILD-5: Audit outbound API calls"),
    (r"urllib\.request\.(urlopen|urlretrieve)\s*\(",
     "urllib outbound request — data may leave trust boundary",
     "PRE-BUILD-5: Audit outbound API calls"),
    # AI / cloud SDKs
    (r"Anthropic\s*\(",
     "Anthropic SDK instantiated — prompts/data sent to external API",
     "PRE-BUILD-4: Confirm offline inference"),
    (r"anthropic\.Anthropic\s*\(",
     "Anthropic SDK instantiated — prompts/data sent to external API",
     "PRE-BUILD-4: Confirm offline inference"),
    (r"client\.messages\.create\s*\(",
     "Anthropic messages.create call — content sent to external API",
     "PRE-BUILD-4: Confirm offline inference"),
    (r"OpenAI\s*\(",
     "OpenAI SDK instantiated — data sent to external API",
     "PRE-BUILD-4: Confirm offline inference"),
    (r"openai\.OpenAI\s*\(",
     "OpenAI SDK instantiated — data sent to external API",
     "PRE-BUILD-4: Confirm offline inference"),
    (r"boto3\.(client|resource|Session)\s*\(",
     "AWS boto3 call — data may leave trust boundary",
     "PRE-BUILD-5: Audit outbound API calls"),
]

_COMPILED = [(re.compile(p), detail, item) for p, detail, item in _PATTERNS]


class OutboundScanner(BaseScanner):
    name = "outbound_calls"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            lines = self._read_lines(py_file)
            if lines is None:
                continue
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
                    continue
                for pattern, detail, checklist_item in _COMPILED:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            file=self._rel(root, py_file),
                            line=lineno,
                            match=stripped[:120],
                            detail=detail,
                            checklist_item=checklist_item,
                        ))
                        break  # one finding per line per scanner
        return findings
