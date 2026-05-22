import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from .base import BaseScanner, Finding, Severity

_COMMENT = re.compile(r"^\s*#")
_BLANK = re.compile(r"^\s*$")
_OPTION = re.compile(r"^\s*-[a-zA-Z]")
_PINNED = re.compile(r"==")
_HASHED = re.compile(r"--hash=")
_PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")

_LOCKFILES = ("uv.lock", "pdm.lock", "poetry.lock")


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

        findings.extend(self._scan_pyproject(root, has_req_files=bool(req_files)))
        return findings

    def _scan_pyproject(self, root: Path, has_req_files: bool) -> list[Finding]:
        if tomllib is None:
            return []

        pyproject = root / "pyproject.toml"
        if not pyproject.exists():
            return []

        try:
            text = pyproject.read_text(encoding="utf-8")
            data = tomllib.loads(text)
        except Exception:
            return []

        project = data.get("project", {})
        if not project:
            return []

        # Collect (dep_spec, section_label) from [project.dependencies]
        # and [project.optional-dependencies]
        all_deps: list[tuple[str, str]] = []
        for dep in project.get("dependencies", []):
            all_deps.append((dep, "[project.dependencies]"))
        for group, deps in project.get("optional-dependencies", {}).items():
            for dep in deps:
                all_deps.append((dep, f"[project.optional-dependencies.{group}]"))

        if not all_deps:
            return []

        findings = []
        raw_lines = text.splitlines()

        # Fire HIGH only when pyproject.toml is the primary spec — if requirements*.txt
        # files exist the requirements scan already covers the HIGH finding, and firing
        # again here would double-report the same root cause.
        if not has_req_files and not self._has_lock(root):
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.HIGH,
                file="pyproject.toml",
                line=1,
                match="pyproject.toml",
                detail=(
                    "pyproject.toml dependencies not hash-locked — add a hash-pinned "
                    "requirements.txt (pip-compile --generate-hashes) or a lockfile."
                ),
                checklist_item="PHASE-2-5: PyPI dependencies pinned with hashes",
            ))

        for dep_spec, section in all_deps:
            pkg = dep_spec.split(";")[0].strip()
            if _PINNED.search(pkg):
                continue

            lineno = next(
                (i + 1 for i, line in enumerate(raw_lines) if dep_spec in line),
                1,
            )
            m = _PKG_NAME.match(pkg)
            pkg_name = m.group(0) if m else pkg.split()[0]
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                file="pyproject.toml",
                line=lineno,
                match=pkg[:80],
                detail=f"Unpinned dependency '{pkg_name}' in pyproject.toml {section} — no exact version locked",
                checklist_item="PHASE-2-5: PyPI dependencies pinned with hashes",
            ))

        return findings

    def _has_lock(self, root: Path) -> bool:
        for rf in root.rglob("requirements*.txt"):
            try:
                if any(_HASHED.search(l) for l in rf.read_text(encoding="utf-8", errors="replace").splitlines()):
                    return True
            except OSError:
                pass
        return any((root / lf).exists() for lf in _LOCKFILES)
