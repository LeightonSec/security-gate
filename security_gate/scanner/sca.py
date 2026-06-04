import re
import sys
from pathlib import Path

import httpx

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]

from .base import BaseScanner, Finding, Severity

_OSV_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 30.0
_CHECKLIST = "PHASE-2-6: No known CVEs in direct dependencies"
_REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;#\\]+)")

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _parse_req_file(text: str) -> list[tuple[str, str]]:
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            result.append((m.group(1), m.group(2)))
    return result


def _parse_pyproject(text: str) -> list[tuple[str, str]]:
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    project = data.get("project", {})
    raw_deps: list[str] = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        raw_deps.extend(group)
    result = []
    for dep in raw_deps:
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;,\]]+)", dep.strip())
        if m:
            result.append((m.group(1), m.group(2)))
    return result


def _canonical_id(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    for alias in vuln.get("aliases", []):
        if alias.startswith("GHSA-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _fix_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _map_severity(vuln: dict) -> Severity:
    sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if sev in _SEV_MAP:
        return _SEV_MAP[sev]
    return Severity.HIGH


class ScaScanner(BaseScanner):
    name = "sca"

    def scan(self, root: Path) -> list[Finding]:
        pinned = self._collect_pinned(root)
        has_dep_files = bool(
            list(root.rglob("requirements*.txt")) + list(root.rglob("pyproject.toml"))
        )
        if not has_dep_files:
            return []
        if not pinned:
            return [Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file="requirements.txt",
                line=1,
                match="no pinned versions",
                detail="SCA skipped — no pinned versions to query. Run unpinned_deps scanner first.",
                checklist_item=_CHECKLIST,
            )]
        return self._query_osv(root, pinned)

    def _collect_pinned(self, root: Path) -> list[tuple[str, str, str]]:
        deps: list[tuple[str, str, str]] = []
        for req_file in root.rglob("requirements*.txt"):
            try:
                text = req_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for name, version in _parse_req_file(text):
                deps.append((name, version, self._rel(root, req_file)))
        for pyproject in root.rglob("pyproject.toml"):
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for name, version in _parse_pyproject(text):
                deps.append((name, version, self._rel(root, pyproject)))
        return deps

    def _query_osv(
        self, root: Path, pinned: list[tuple[str, str, str]]
    ) -> list[Finding]:
        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for name, version, _ in pinned
        ]
        try:
            resp = httpx.post(_OSV_URL, json={"queries": queries}, timeout=_TIMEOUT)  # gate: ignore — intentional outbound call to osv.dev CVE API; URL is a hardcoded constant, trust boundary documented in scanner design
            resp.raise_for_status()
            data = resp.json()
        except httpx.TimeoutException:
            return [Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                file="requirements.txt",
                line=1,
                match="osv.dev timeout",
                detail=f"OSV API timed out after {_TIMEOUT}s — CVE scan incomplete.",
                checklist_item=_CHECKLIST,
            )]
        except Exception as exc:
            return [Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                file="requirements.txt",
                line=1,
                match="osv.dev error",
                detail=f"OSV API error — CVE scan incomplete: {exc}",
                checklist_item=_CHECKLIST,
            )]

        findings = []
        for idx, result in enumerate(data.get("results", [])):
            if idx >= len(pinned):
                break
            name, version, src_file = pinned[idx]
            seen: set[str] = set()
            for vuln in result.get("vulns", []):
                cid = _canonical_id(vuln)
                if cid in seen:
                    continue
                seen.add(cid)
                fix = _fix_version(vuln)
                summary = vuln.get("summary", "")[:120]
                detail = f"{cid}: {summary}"
                if fix:
                    detail += f" (fix: {fix})"
                findings.append(Finding(
                    scanner=self.name,
                    severity=_map_severity(vuln),
                    file=src_file,
                    line=1,
                    match=f"{name}=={version}",
                    detail=detail,
                    checklist_item=_CHECKLIST,
                ))
        return findings
