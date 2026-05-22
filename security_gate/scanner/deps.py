import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_COMMENT = re.compile(r"^\s*#")
_BLANK = re.compile(r"^\s*$")
_OPTION = re.compile(r"^\s*-[a-zA-Z]")
_PINNED = re.compile(r"==")
_HASHED = re.compile(r"--hash=")


class DepsScanner(BaseScanner):
    name = "unpinned_deps"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        req_files = list(root.rglob("requirements*.txt"))

        for req_file in req_files:
            rel = self._rel(root, req_file)
            any_hashes = False
            try:
                text = req_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = text.splitlines()
            if any(_HASHED.search(l) for l in lines):
                any_hashes = True

            if not any_hashes:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    file=rel,
                    line=1,
                    match=req_file.name,
                    detail="No hash-pinned dependencies — run pip-compile --generate-hashes. Supply chain attack surface.",
                    checklist_item="PHASE-2-5: PyPI dependencies pinned with hashes",
                ))

            for lineno, line in enumerate(lines, start=1):
                if _COMMENT.match(line) or _BLANK.match(line) or _OPTION.match(line):
                    continue
                pkg = line.split(";")[0].strip()
                if pkg and not _PINNED.search(pkg):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=lineno,
                        match=pkg[:80],
                        detail=f"Unpinned dependency '{pkg.split()[0]}' — no exact version locked",
                        checklist_item="PHASE-2-5: PyPI dependencies pinned with hashes",
                    ))

        return findings
