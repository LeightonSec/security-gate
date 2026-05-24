import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_PRETRAINED = re.compile(r"\.from_pretrained\s*\(")
_TRUST_REMOTE = re.compile(r"trust_remote_code\s*=\s*True")
_TELEMETRY_PERMISSIVE = re.compile(
    r"(DISABLE_TELEMETRY|HF_HUB_DISABLE_TELEMETRY).*=\s*[\"']?(0|false)[\"']?",
    re.IGNORECASE,
)

_REVISION_WINDOW = 5  # lines forward to look for revision= after from_pretrained(


class AiMlScanner(BaseScanner):
    name = "ai_ml"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("#") or self._suppressed(line):
                    continue

                if _PRETRAINED.search(line):
                    window = lines[i : i + _REVISION_WINDOW + 1]
                    if not any("revision=" in wl for wl in window):
                        findings.append(Finding(
                            scanner=self.name,
                            severity=Severity.HIGH,
                            file=self._rel(root, py_file),
                            line=i + 1,
                            match=stripped[:120],
                            detail="from_pretrained() called without revision= — unpinned model download is a supply chain risk",
                            checklist_item="AI-ML-1: Model downloads pinned to a specific revision hash",
                        ))

                if _TRUST_REMOTE.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=self._rel(root, py_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="trust_remote_code=True enables arbitrary code execution from the model repository",
                        checklist_item="AI-ML-2: trust_remote_code never set to True",
                    ))

                if _TELEMETRY_PERMISSIVE.search(line):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        file=self._rel(root, py_file),
                        line=i + 1,
                        match=stripped[:120],
                        detail="HuggingFace telemetry explicitly enabled — data will be sent to HuggingFace servers",
                        checklist_item="AI-ML-3: HuggingFace telemetry disabled in production",
                    ))

        return findings
