"""Insecure deserialization scanner.

pickle (and its variants cPickle / _pickle) executes arbitrary code during
deserialization: an attacker who controls the byte stream controls the process.
There is no safe way to unpickle untrusted data.

Detects three patterns, all CRITICAL:

  pickle.loads / pickle.load with a non-literal argument — fires on variables,
    function calls, attribute access. A bytes/str literal argument is excluded
    (constant, not attacker-controlled), same literal guard as the eval/exec scanner.
      Safe:    pickle.loads(b"...")     — constant literal  # gate: ignore — docstring example
      Unsafe:  pickle.loads(payload)    — variable, CRITICAL  # gate: ignore — docstring example
      Unsafe:  pickle.load(open(path))  — call result, CRITICAL  # gate: ignore — docstring example

  the Unpickler class (pickle.Unpickler) — the streaming/OO unpickling API; the
    class is only instantiated to deserialize, so it is flagged regardless of argument.

Known limitation: `from pickle import loads` followed by a bare `loads(...)` call is
not detected, because a bare `loads(` is indistinguishable from json/marshmallow at
the regex level and would false-positive. Import the module (`import pickle`) form is
the common idiom and is covered.
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# pickle.load / pickle.loads with a non-literal argument.
# Negative lookahead excludes plain and prefixed string/bytes literals (b, r, u and
# combinations) — a constant payload is not attacker-controlled.
_PICKLE_LOAD = re.compile(
    r"\b(?:pickle|cPickle|_pickle)\.(loads?)\s*\(\s*(?!['\"]|[bBrRuU]+['\"])"
)

# pickle.Unpickler(...) — instantiated only to deserialize.
_UNPICKLER = re.compile(r"\b(?:pickle|cPickle|_pickle)\.Unpickler\s*\(")


class PickleUsageScanner(BaseScanner):
    name = "pickle_usage"

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

            m = _PICKLE_LOAD.search(line)
            if m:
                func = m.group(1)
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        f"pickle.{func} with non-literal argument — arbitrary code "
                        "execution during deserialization if the byte stream is "
                        "attacker-controlled. Use a safe format (JSON) or a signed/"
                        "authenticated envelope; never unpickle untrusted data."
                    ),
                    checklist_item="DESERIAL-1: No pickle/Unpickler on untrusted data",
                ))
                continue  # one finding per line

            if _UNPICKLER.search(line):
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        "pickle.Unpickler instantiated — the unpickling API executes "
                        "arbitrary code on the byte stream. Never unpickle untrusted "
                        "data; use a safe format instead."
                    ),
                    checklist_item="DESERIAL-1: No pickle/Unpickler on untrusted data",
                ))

        return findings
