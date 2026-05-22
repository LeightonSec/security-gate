import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# Obvious hardcoded defaults that should never ship
_HARDCODED_DEFAULTS = re.compile(
    r"""(?:SECRET_KEY|API_KEY|TOKEN|PASSWORD|PASSWD|AUTH_KEY|PRIVATE_KEY)\s*=\s*['"](changeme|password|secret|admin|test|letmein|12345|default|placeholder|todo|fixme|replace_me|your[_-]?key|your[_-]?secret|your[_-]?token)['"]\s*$""",
    re.IGNORECASE,
)

# getenv with an obvious insecure fallback: os.getenv('X', 'changeme')
_GETENV_DEFAULT = re.compile(
    r"""os\.getenv\s*\(\s*['"][^'"]+['"]\s*,\s*['"](changeme|password|secret|admin|default|placeholder)['"]\s*\)""",
    re.IGNORECASE,
)

# Inline literal API key assignment (catches obvious cases — not a replacement for gitleaks)
_INLINE_SECRET = re.compile(
    r"""(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*['"][A-Za-z0-9+/\-_]{20,}['"]""",
)


class SecretsScanner(BaseScanner):
    name = "hardcoded_secrets"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if _HARDCODED_DEFAULTS.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=self._rel(root, py_file),
                        line=lineno,
                        match=stripped[:120],
                        detail="Hardcoded insecure default — will ship as-is if env var is unset",
                        checklist_item="PHASE-3-1: No hardcoded secrets or default credentials",
                    ))
                elif _GETENV_DEFAULT.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.HIGH,
                        file=self._rel(root, py_file),
                        line=lineno,
                        match=stripped[:120],
                        detail="os.getenv with insecure fallback — fails open if env var missing",
                        checklist_item="PHASE-3-1: No hardcoded secrets or default credentials",
                    ))
                elif _INLINE_SECRET.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=self._rel(root, py_file),
                        line=lineno,
                        match=stripped[:120],
                        detail="Possible inline secret assignment — verify this is not a real key",
                        checklist_item="PHASE-4-1: Secrets scan clean (supplement with gitleaks)",
                    ))
        return findings
