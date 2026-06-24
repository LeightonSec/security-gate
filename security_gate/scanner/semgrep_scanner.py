"""Semgrep integration scanner.

Runs bundled custom taint rules via the semgrep CLI. Provides AST-based
intra-procedural taint tracking — follows data through variable reassignment
chains within a function. This catches multi-hop cases that regex scanners miss:

  data = request.get_json()      # gate: ignore - docstring example, not executed
  prompt = data.get("message")
  user_msg = prompt              # regex scanner loses track here
  client.messages.create(...)    # gate: ignore - docstring example, not executed (semgrep still follows the taint)

Scope: intra-function only. Cross-function taint (data passing through a helper
function call) requires semgrep Pro. This scanner complements the regex scanners
rather than replacing them — it fires at MEDIUM, not gating on its own.

If semgrep is not installed, emits a single INFO finding so the gap is visible
rather than silent. Install with: pip install semgrep
"""
import json
import subprocess
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_RULES_FILE = Path(__file__).parent.parent / "rules" / "semgrep_rules.yml"

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_CHECKLIST_MAP = {
    "sgw-llm-injection-taint": (
        "LLM-INJ-2: Intra-function taint — request input reaches LLM API via reassignment chain"
    ),
    "sgw-cmd-injection-taint": (
        "CMD-INJ-4: Intra-function taint — request input reaches command execution via reassignment chain"
    ),
    "sgw-ssrf-taint": (
        "SSRF-2: Intra-function taint — request input reaches HTTP client URL via reassignment chain"
    ),
}


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def scan(self, root: Path) -> list[Finding]:
        try:
            result = subprocess.run(
                [
                    "semgrep", "--json", "--quiet",
                    "--config", str(_RULES_FILE),
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return [Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file="semgrep",
                line=1,
                match="semgrep not found",
                detail=(
                    "semgrep not installed — AST-based intra-procedural taint analysis skipped. "
                    "Install with: pip install semgrep"
                ),
                checklist_item="SEMGREP-0: semgrep installed for AST-based taint analysis",
            )]
        except subprocess.TimeoutExpired:
            return [Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file="semgrep",
                line=1,
                match="timed out after 120s",
                detail=(
                    "semgrep scan timed out after 120s — AST-based intra-procedural taint "
                    "analysis incomplete. Run semgrep manually or increase timeout."
                ),
                checklist_item="SEMGREP-0: semgrep installed for AST-based taint analysis",
            )]

        # Exit 0 = success no findings, exit 1 = success with findings, exit 2+ = error
        if result.returncode > 1 or not result.stdout.strip():
            return []

        try:
            data = json.loads(result.stdout)  # gate: ignore — parses semgrep subprocess output, controlled invocation
        except json.JSONDecodeError:
            return []

        findings = []
        for r in data.get("results", []):
            # check_id may be prefixed with rule path: strip to rule id only
            rule_id = r.get("check_id", "").split(".")[-1]
            sev_str = r.get("extra", {}).get("severity", "WARNING").upper()
            severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            path = r.get("path", "")
            line = r.get("start", {}).get("line", 1)
            message = r.get("extra", {}).get("message", "").strip().splitlines()[0]
            code_line = r.get("extra", {}).get("lines", "").strip()

            try:
                rel = str(Path(path).relative_to(root))
            except ValueError:
                rel = path

            checklist = _CHECKLIST_MAP.get(
                rule_id,
                "SEMGREP: Review finding — AST-based intra-procedural detection",
            )

            findings.append(Finding(
                scanner=self.name,
                severity=severity,
                file=rel,
                line=line,
                match=code_line[:120],
                detail=f"[semgrep/{rule_id}] {message}",
                checklist_item=checklist,
            ))

        return findings
