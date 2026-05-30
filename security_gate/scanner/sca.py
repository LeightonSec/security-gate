import json
import re
import subprocess
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_PINNED = re.compile(r"==")

# pip-audit's JSON format does not include CVSS scores — VulnerabilityResult only
# carries id, description, fix_versions, and aliases. All CVEs are rated HIGH by
# default; check the CVE directly (nvd.nist.gov) for precise severity.
_DEFAULT_CVE_SEVERITY = Severity.HIGH


class ScaScanner(BaseScanner):
    name = "sca"

    def scan(self, root: Path) -> list[Finding]:
        req_files = list(root.rglob("requirements*.txt"))
        if not req_files:
            return []

        # Check for any pinned dep across all req files
        has_pinned = any(
            _PINNED.search(line)
            for rf in req_files
            for line in self._read_lines(rf)
        )
        if not has_pinned:
            return [Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file="requirements.txt",
                line=1,
                match="no pinned versions",
                detail="SCA skipped — no pinned versions to query. Run unpinned_deps scanner first.",
                checklist_item="PHASE-2-6: No known CVEs in direct dependencies",
            )]

        findings = []
        for req_file in req_files:
            findings.extend(self._audit_file(root, req_file))
        return findings

    def _audit_file(self, root: Path, req_file: Path) -> list[Finding]:
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json", "--desc", "-r", str(req_file)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return [Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file=self._rel(root, req_file),
                line=1,
                match="pip-audit not found",
                detail="pip-audit not installed — SCA skipped. Install with: pip install pip-audit",
                checklist_item="PHASE-2-6: No known CVEs in direct dependencies",
            )]
        except subprocess.TimeoutExpired:
            return [Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                file=self._rel(root, req_file),
                line=1,
                match="pip-audit timed out after 120s",
                detail=(
                    "pip-audit timed out after 120s — CVE scan incomplete, "
                    "vulnerable dependencies cannot be confirmed absent. "
                    "Run pip-audit manually: pip-audit -r requirements.txt"
                ),
                checklist_item="PHASE-2-6: No known CVEs in direct dependencies",
            )]

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)  # gate: ignore — parses pip-audit subprocess output, controlled input
        except json.JSONDecodeError:
            return []

        findings = []
        for dep in data.get("dependencies", []):
            pkg_name = dep.get("name", "unknown")
            pkg_version = dep.get("version", "unknown")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                alias_str = f" ({', '.join(aliases)})" if aliases else ""
                description = vuln.get("description", "")[:120]
                detail = f"{vuln_id}{alias_str}: {description}" if description else f"{vuln_id}{alias_str}"
                findings.append(Finding(
                    scanner=self.name,
                    severity=_DEFAULT_CVE_SEVERITY,
                    file=self._rel(root, req_file),
                    line=1,
                    match=f"{pkg_name}=={pkg_version}",
                    detail=detail,
                    checklist_item="PHASE-2-6: No known CVEs in direct dependencies",
                ))
        return findings

    def _read_lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
