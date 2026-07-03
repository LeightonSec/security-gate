import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# DB/file write patterns that accumulate data indefinitely
_WRITE_PATTERNS = [
    re.compile(r"conn\.execute\s*\(\s*['\"]?\s*INSERT", re.IGNORECASE),
    re.compile(r"cursor\.execute\s*\(\s*['\"]?\s*INSERT", re.IGNORECASE),
    re.compile(r"db\.execute\s*\(\s*['\"]?\s*INSERT", re.IGNORECASE),
    re.compile(r"session\.add\s*\("),
    re.compile(r"json\.dump\s*\(.*open\s*\("),   # json.dump to file
    re.compile(r"with open\s*\(.*['\"]a['\"]"),  # append mode file writes
]

# Retention/purge signals that indicate the writer thought about lifecycle
_RETENTION_SIGNALS = re.compile(
    r"(TTL|ttl|purge|expire|retention|max_age|delete.*older|cleanup|evict|rotate|prune)",
    re.IGNORECASE,
)

_WINDOW = 15  # lines above/below write to look for retention signal


class RetentionScanner(BaseScanner):
    name = "retention_policy"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            lines = self._read_lines(py_file)
            if lines is None:
                continue

            # Strip comment lines before checking for retention signals — prevents
            # "# TODO: add retention policy" from suppressing real findings
            non_comment_text = "\n".join(
                line for line in lines if not line.strip().startswith("#")
            )
            if _RETENTION_SIGNALS.search(non_comment_text):
                continue

            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
                    continue
                for pattern in _WRITE_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            file=self._rel(root, py_file),
                            line=lineno,
                            match=stripped[:120],
                            detail="Data write with no retention/purge logic detected in file — indefinite accumulation risk",
                            checklist_item="PRE-BUILD-6: Data retention policy defined per source",
                        ))
                        break  # one finding per line
        return findings
