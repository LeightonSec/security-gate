import json
import re
import subprocess
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_PINNED = re.compile(r"==")


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


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
                ["pip-audit", "--format=json", "-r", str(req_file)],
                capture_output=True,
                text=True,
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

        if not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for dep in data.get("dependencies", []):
            pkg_name = dep.get("name", "unknown")
            pkg_version = dep.get("version", "unknown")
            for vuln in dep.get("vulns", []):
                cvss = self._extract_cvss(vuln)
                severity = _cvss_to_severity(cvss)
                cve_id = vuln.get("id", "UNKNOWN")
                description = vuln.get("description", "")[:120]
                findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    file=self._rel(root, req_file),
                    line=1,
                    match=f"{pkg_name}=={pkg_version}",
                    detail=f"{cve_id}: {description}",
                    checklist_item="PHASE-2-6: No known CVEs in direct dependencies",
                ))
        return findings

    def _extract_cvss(self, vuln: dict) -> float:
        for alias in vuln.get("aliases", []):
            pass
        for fix in vuln.get("fix_versions", []):
            pass
        # pip-audit embeds CVSS in the vulnerability object under various keys
        score = vuln.get("cvss", vuln.get("severity_score", 0.0))
        if isinstance(score, (int, float)):
            return float(score)
        # Some formats nest it under scores list
        for s in vuln.get("scores", []):
            if isinstance(s, dict):
                return float(s.get("score", 0.0))
            if isinstance(s, (int, float)):
                return float(s)
        return 0.0

    def _read_lines(self, path: Path) -> list[str]:
        try:
            return path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
