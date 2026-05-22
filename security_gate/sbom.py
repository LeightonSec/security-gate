"""
Minimal CycloneDX 1.5 SBOM generator.
Reads requirements*.txt files, outputs a spec-compliant JSON SBOM.
No runtime dependencies beyond the stdlib.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

_PINNED = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)")
_COMMENT = re.compile(r"^\s*#")
_BLANK = re.compile(r"^\s*$")
_OPTION = re.compile(r"^\s*-")


def _parse_requirements(root: Path) -> list[dict]:
    components = []
    seen = set()
    for req_file in sorted(root.rglob("requirements*.txt")):
        try:
            lines = req_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if _COMMENT.match(line) or _BLANK.match(line) or _OPTION.match(line):
                continue
            m = _PINNED.match(line.strip())
            if m:
                name, version = m.group(1), m.group(2)
                key = name.lower()
                if key not in seen:
                    seen.add(key)
                    components.append({
                        "type": "library",
                        "bom-ref": f"pkg:pypi/{name.lower()}@{version}",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:pypi/{name.lower()}@{version}",
                    })
    return components


def generate_sbom(root: Path, repo_name: str) -> dict:
    components = _parse_requirements(root)
    now = datetime.now(timezone.utc).isoformat()
    serial = str(uuid.uuid4())

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "security-gate", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "name": repo_name,
                "bom-ref": f"pkg:generic/{repo_name}",
            },
        },
        "components": components,
    }


def generate_sbom_json(root: Path) -> str:
    repo_name = root.resolve().name
    sbom = generate_sbom(root, repo_name)
    return json.dumps(sbom, indent=2)
