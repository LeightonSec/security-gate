"""Missing-timeout scanner.

An outbound HTTP call with no timeout blocks the calling thread indefinitely if the
remote end stalls — a resource-exhaustion / availability risk (a slow-loris upstream
can pin every worker). Detected at MEDIUM: it is a robustness/DoS concern, not a
direct compromise, so it surfaces without gating CI.

Scope is deliberate:

  requests.<verb>(...)        — the `requests` library defaults to NO timeout
                                (waits forever). Flagged when no timeout= is present.
  urlopen (urllib.request)    — likewise has no default timeout.

httpx is intentionally NOT flagged: it ships a 5-second default timeout, so omitting
the argument is not a hang risk. aiohttp's default (5-minute total) is bounded too.

The argument list is read by tracking parentheses from the call's opening paren to its
match, so a timeout= on a neighbouring call cannot mask a bare one.
"""
import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

_HTTP_CALL = re.compile(r"\brequests\.(get|post|put|patch|delete|head|request)\s*\(")
_URLOPEN = re.compile(r"\burllib\.request\.urlopen\s*\(")
_TIMEOUT_KW = re.compile(r"\btimeout\s*=")

_MAX_CALL_LINES = 15  # safety bound on multi-line call argument scanning


class HardcodedTimeoutScanner(BaseScanner):
    name = "missing_timeout"

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

            for pattern, label in ((_HTTP_CALL, "requests"), (_URLOPEN, "urllib")):
                m = pattern.search(line)
                if not m:
                    continue
                args = self._call_args(lines, i, m.end() - 1)
                if _TIMEOUT_KW.search(args):
                    break  # timeout present — fine
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=i + 1,
                    match=stripped[:120],
                    detail=(
                        f"{label} call without a timeout — the request can block "
                        "indefinitely if the remote end stalls (availability/DoS risk). "
                        "Pass timeout=<seconds>."
                    ),
                    checklist_item="NET-1: Outbound calls set an explicit timeout",
                ))
                break  # one finding per line

        return findings

    @staticmethod
    def _call_args(lines: list[str], i: int, open_pos: int) -> str:
        """Return the text between a call's opening '(' and its matching ')'.

        Stops at _MAX_CALL_LINES to bound runaway scans on unbalanced source.
        """
        depth = 0
        buf: list[str] = []
        for j in range(i, min(len(lines), i + _MAX_CALL_LINES)):
            line = lines[j]
            start = open_pos if j == i else 0
            for ch in line[start:]:
                if ch == "(":
                    depth += 1
                    if depth == 1:
                        continue  # skip the opening paren itself
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        return "".join(buf)
                if depth >= 1:
                    buf.append(ch)
            buf.append("\n")
        return "".join(buf)
