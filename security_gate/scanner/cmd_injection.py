"""Command injection scanner.

Detects four patterns that enable arbitrary code or shell execution:

  eval/exec with non-literal argument — fires on variables, f-strings, function calls.
    Safe:    eval("2+2")         — string literal, not user-controlled
    Unsafe:  eval(user_input)    — variable, CRITICAL  # gate: ignore — docstring example, not executed
    Unsafe:  eval(f"code {x}")   — f-string, CRITICAL  # gate: ignore — docstring example, not executed

  os.system with non-literal argument — same literal guard as eval/exec.

  subprocess.run/Popen/call/check_output/check_call with shell=True in the call
    block (15-line window). shell=True passes the command to the shell for
    interpretation — any user-controlled portion of the string enables injection.
    shell=False with a list argument is safe and is not flagged.

Known limitation: string concatenation where the first token IS a literal is not
detected (e.g. eval("prefix" + user_input)). The f-string case IS detected because
f-strings are excluded from the literal guard.
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# eval/exec with non-literal argument.
# (?<!\.) excludes method calls like model.eval() or obj.exec() — the built-in
# eval/exec are never called as methods, so a preceding dot is always a false positive.
# Negative lookahead excludes plain string literals and prefixed literals (b, r, u
# and combinations). f/F are NOT excluded — f-strings with interpolation are unsafe.
_EVAL_EXEC = re.compile(
    r"(?<!\.)\b(eval|exec)\s*\(\s*(?!['\"]|[bBrRuU]+['\"])"
)

# os.system with non-literal argument — same literal guard.
_OS_SYSTEM = re.compile(
    r"\bos\.system\s*\(\s*(?!['\"]|[bBrRuU]+['\"])"
)

# subprocess family — fires when shell=True appears in the call block.
_SUBPROCESS = re.compile(
    r"\bsubprocess\s*\.\s*(?:run|Popen|call|check_output|check_call)\s*\("
)
_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")

_SHELL_WINDOW = 15


class CmdInjectionScanner(BaseScanner):
    name = "cmd_injection"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            lines = self._read_lines(py_file)
            if lines is None:
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

            m = _EVAL_EXEC.search(line)
            if m:
                func = m.group(1)
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        f"{func}() called with non-literal argument — "
                        "arbitrary Python execution if argument is user-controlled"
                    ),
                    checklist_item="CMD-INJ-1: eval/exec never called with user-controlled input",
                ))
                continue  # one finding per line

            if _OS_SYSTEM.search(line):
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        "os.system with non-literal argument — "
                        "shell injection risk if argument contains user-controlled data"
                    ),
                    checklist_item="CMD-INJ-2: os.system never called with user-controlled input",
                ))
                continue

            if _SUBPROCESS.search(line):
                window = lines[i : i + _SHELL_WINDOW + 1]
                if any(_SHELL_TRUE.search(wl) for wl in window):
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=i + 1,
                        match=stripped[:120],
                        detail=(
                            "subprocess called with shell=True — the shell interprets "
                            "the command string, enabling injection if any part is user-controlled. "
                            "Use shell=False with a list argument instead."
                        ),
                        checklist_item="CMD-INJ-3: subprocess calls use shell=False with argument lists",
                    ))

        return findings
