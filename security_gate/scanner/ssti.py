"""Server-side template injection (SSTI) scanner.

Detects two patterns that enable arbitrary code execution via template injection:

  render_template_string with non-literal argument — Flask/Jinja2. Passing
    user-controlled input to render_template_string enables full Python execution
    via Jinja2 template syntax (e.g. {{7*7}}, {{config}}, {{''.__class__...}}).
    Safe:    render_template_string("<h1>Hello</h1>")
    Unsafe:  render_template_string(user_input)         # gate: ignore — docstring example, not executed
    Unsafe:  render_template_string(f"<h1>{name}</h1>")  # gate: ignore — docstring example, not executed

  jinja2.Template with non-literal argument — direct Jinja2 template instantiation.
    Same attack surface as render_template_string. Safe only when the template
    string is a fully controlled literal.

Known limitation: templates loaded from files via render_template are safe (Jinja2
auto-escaping applies). This scanner only flags render_template_string and direct
Template instantiation. String concatenation where the first token is a literal
(e.g. render_template_string("<h1>" + user_input)) is not detected.
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# render_template_string with non-literal argument
_RENDER_TEMPLATE_STRING = re.compile(
    r"\brender_template_string\s*\(\s*(?!['\"]|[bBrRuU]+['\"])"
)

# jinja2.Template with non-literal argument
_JINJA2_TEMPLATE = re.compile(
    r"\bjinja2\.Template\s*\(\s*(?!['\"]|[bBrRuU]+['\"])"
)


class SstiScanner(BaseScanner):
    name = "ssti"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            findings.extend(self._scan_file(root, py_file, lines))
        return findings

    def _scan_file(self, root: Path, py_file: Path, lines: list[str]) -> list[Finding]:
        findings = []
        rel = self._rel(root, py_file)

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or self._suppressed(line):
                continue

            if _RENDER_TEMPLATE_STRING.search(line):
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        "render_template_string called with non-literal argument — "
                        "Jinja2 template injection enables arbitrary code execution if "
                        "argument contains user-controlled data"
                    ),
                    checklist_item="SSTI-1: render_template_string never called with user-controlled input",
                ))
                continue

            if _JINJA2_TEMPLATE.search(line):
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        "jinja2.Template instantiated with non-literal argument — "
                        "template injection enables arbitrary code execution if "
                        "argument contains user-controlled data"
                    ),
                    checklist_item="SSTI-2: jinja2.Template never instantiated with user-controlled input",
                ))

        return findings
