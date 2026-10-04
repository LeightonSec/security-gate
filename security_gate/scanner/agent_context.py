"""Agent-context integrity scanner (scanner #21).

Verifies that files an AI agent reads and acts on — CLAUDE.md, SKILL.md, prompt
and agent-config files — still match a pinned SHA-256 recorded in an in-repo
manifest (`.agent-context-manifest.json`), and flags content that reads like an
instruction aimed at the agent rather than the human.

WHAT THIS CATCHES, AND WHAT IT DOES NOT
    The hash check detects drift and a bad restore verified against an
    already-good manifest. It is NOT a defence against an attacker (or a
    poisoned agent) with write access to the repo: such an attacker can edit a
    tracked file and re-run the manifest tool to re-pin the tamper. The real
    control is PR review gating any change to the manifest file itself — a
    reviewer reading the manifest diff, not this hash comparison. Wherever this
    scanner is deployed, that review gate must exist (path-scoped required
    review on `.agent-context-manifest.json` where the host supports it); this
    scanner's presence does not by itself close the gap.

TRANSCLUSION (flatten-at-hash)
    Claude Code `@<path>` imports pull other files into a context file's
    effective content, so hashing only the top-level bytes leaves a hole the
    width of the include mechanism (e.g. CLAUDE.md `@RTK.md`). The gating hash
    for each entrypoint is therefore the SHA-256 of its *transitively resolved*
    content — every `@import` expanded inline before hashing — so a change to an
    included file moves the entrypoint's hash. The manifest also stores each
    contributing file's individual raw hash under `includes`, purely so a
    mismatch can name which included file drifted; that per-file map is
    diagnostic, never a second gating concern.

    In scope: `@<path>` import syntax only. Out of scope, by design: skill-prose
    `references/...` mentions and memory `[[wiki links]]` — those are
    associative, not deterministic includes, and cannot be resolved reliably.
    Files an agent loads from outside any repo (e.g. ~/.claude memory) are also
    out of a repo-scoped scanner's reach; treat that as an accepted gap.

PATTERN CHECK
    A second, HEURISTIC layer flags URLs paired with fetch/install language,
    shell/PowerShell fragments, long base64 blobs, zero-width/format Unicode,
    and imperative phrasing directed at the loader. It is easily evaded and
    false-positives on legitimate documentation, so every pattern finding is
    INFO and NON-GATING — it never fails the gate and is not routed through the
    accepted-findings waiver file. The hash check is the real control.
"""
import hashlib
import json
import re
import unicodedata
from pathlib import Path

from .base import BaseScanner, Finding, Severity

MANIFEST_NAME = ".agent-context-manifest.json"
MANIFEST_VERSION = 1

# Maximum @import nesting depth resolved before giving up. Exceeding it is an
# integrity error (fail closed), never a silent truncation. Kept here, named and
# visible, because it is the one number a maintainer will need to tune later
# without reading the resolver.
MAX_INCLUDE_DEPTH = 10

# Files treated as agent-loaded context. Extend to match what your agents read.
TRACKED_GLOBS = (
    "**/CLAUDE.md",
    "**/SKILL.md",
    "**/*.skill.md",
    "**/agent-config/*.md",
    "**/agent-config/*.yaml",
    "**/agent-config/*.yml",
    "**/prompts/*.md",
    "**/prompts/*.txt",
)

# A bare "@token" is treated as an import only when the token looks like a path:
# it contains a separator or ends in one of these extensions. This keeps stray
# "@handle" text (emails, mentions) from being read as a missing import.
_CONTEXT_EXTS = frozenset({".md", ".txt", ".yaml", ".yml", ".json"})

# @import at line start or after whitespace; token runs to the next space/backtick.
_IMPORT_RE = re.compile(r"(?:^|(?<=\s))@([^\s`]+)")
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
_INLINE_CODE_RE = re.compile(r"`[^`]*`")
# Trailing sentence punctuation stripped off an import token before resolving.
_TRAILING_PUNCT = ".,;:!?)]}'\""

# ---- pattern-check heuristics (all INFO / non-gating) -----------------------
_URL_RE = re.compile(r"https?://[^\s)\]\"'>]+", re.IGNORECASE)
_FETCH_LANGUAGE_RE = re.compile(
    r"\b(download|fetch|curl|wget|invoke-webrequest|iwr|re-?download|"
    r"install(?:\s+this)?|run\s+the\s+following|execute\s+the\s+following)\b",
    re.IGNORECASE,
)
_SHELL_FRAGMENT_RE = re.compile(
    r"(\$\(.*?\)|`[^`]+`|powershell\s+-|cmd\.exe|/bin/(?:ba)?sh\s+-c|"
    r"Invoke-Expression|IEX\s*\(|base64\s+-d|certutil\s+-decode)",
    re.IGNORECASE,
)
_BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){20,}={0,2}")
_AGENT_IMPERATIVE_RE = re.compile(
    r"\b(always|every time|whenever)\b.{0,40}\b(load|read|open|process)"
    r"\b.{0,60}\b(this file|this document|this guide)\b",
    re.IGNORECASE,
)


class _ResolveError(Exception):
    """A transclusion failure. `kind` steers how the scanner reports it:
    'missing' | 'cycle' | 'depth' -> integrity error (fail closed, HIGH);
    'outside_root' -> gating Finding (import escapes the repo boundary).
    """

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def _looks_like_import(token: str) -> bool:
    return "/" in token or Path(token).suffix.lower() in _CONTEXT_EXTS


def _iter_imports(text: str):
    """Yield import tokens outside fenced blocks and inline code spans."""
    in_fence = False
    for line in text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        scan_line = _INLINE_CODE_RE.sub(" ", line)
        for m in _IMPORT_RE.finditer(scan_line):
            token = m.group(1).rstrip(_TRAILING_PUNCT)
            if token and _looks_like_import(token):
                yield token


def resolve_context(root: Path, entry: Path) -> tuple[str, dict[str, str]]:
    """Resolve `entry`'s transitive @import closure.

    Returns (resolved_text, contributing) where contributing maps each
    contributing file's repo-relative path to its raw-bytes SHA-256 (the
    entrypoint itself included). Raises _ResolveError on any failure. Shared
    verbatim by the scanner's check and by the manifest init/update tool so the
    two can never compute the hash differently.
    """
    contributing: dict[str, str] = {}
    text = _resolve_recursive(root, entry, frozenset(), 0, contributing)
    return text, contributing


def _rel_str(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def _resolve_recursive(
    root: Path,
    path: Path,
    stack: frozenset[Path],
    depth: int,
    contributing: dict[str, str],
) -> str:
    real = path.resolve()
    if depth > MAX_INCLUDE_DEPTH:
        raise _ResolveError(
            "depth",
            f"@import nesting exceeded MAX_INCLUDE_DEPTH={MAX_INCLUDE_DEPTH} "
            f"at {_rel_str(root, real)}",
        )
    if real in stack:
        raise _ResolveError("cycle", f"@import cycle detected at {_rel_str(root, real)}")
    try:
        raw = real.read_bytes()
    except OSError as exc:
        raise _ResolveError("missing", f"cannot read @import target {_rel_str(root, real)}: {exc}")
    contributing[_rel_str(root, real)] = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _ResolveError("missing", f"cannot decode {_rel_str(root, real)}: {exc}")

    child_stack = stack | {real}
    parts: list[str] = []
    in_fence = False
    for line in text.splitlines(keepends=True):
        parts.append(line)
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        scan_line = _INLINE_CODE_RE.sub(" ", line)
        for m in _IMPORT_RE.finditer(scan_line):
            token = m.group(1).rstrip(_TRAILING_PUNCT)
            if not token or not _looks_like_import(token):
                continue
            target = (real.parent / token)
            try:
                target.resolve().relative_to(root)
            except ValueError:
                raise _ResolveError(
                    "outside_root",
                    f"@import '{token}' in {_rel_str(root, real)} resolves outside "
                    "the repo root",
                )
            parts.append(_resolve_recursive(root, target, child_stack, depth + 1, contributing))
    return "".join(parts)


def _describe_drift(pinned_includes: dict[str, str], live_includes: dict[str, str]) -> str:
    """Name which contributing files moved between the pin and the live tree."""
    changed = [f for f, h in live_includes.items() if f in pinned_includes and pinned_includes[f] != h]
    added = [f for f in live_includes if f not in pinned_includes]
    removed = [f for f in pinned_includes if f not in live_includes]
    bits = []
    if changed:
        bits.append("changed: " + ", ".join(sorted(changed)))
    if added:
        bits.append("added: " + ", ".join(sorted(added)))
    if removed:
        bits.append("removed: " + ", ".join(sorted(removed)))
    return "; ".join(bits) if bits else "content changed"


def validate_files_map(manifest: object) -> dict[str, dict]:
    """Validate the parsed manifest's shape and return its `files` mapping.

    Raises ValueError when the manifest is not a JSON object, or has no dict
    `files` member, so the caller's single `except` fails closed on both a parse
    error and a structural one. (Guards the latent `list/int.get` crash a
    valid-JSON non-object manifest would otherwise raise uncaught.)
    """
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not a JSON object")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("manifest has no 'files' object")
    return files


class AgentContextScanner(BaseScanner):
    name = "agent_context_integrity"

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        root = root.resolve()

        tracked = self._gather_tracked(root)
        manifest_files = self._load_manifest(root)

        # Resolve every tracked entrypoint once; record its resolved hash and the
        # contributing-file breakdown, or route failures to the right channel.
        live: dict[str, tuple[str, dict[str, str]]] = {}
        for path in tracked:
            rel = self._rel(root, path)
            try:
                resolved_text, contributing = resolve_context(root, path)
            except _ResolveError as err:
                if err.kind == "outside_root":
                    # CRITICAL, not a coverage tier: a root-escaping import is an
                    # attempt to pull unreviewed external content into a trusted
                    # closure and have it count as pinned — a different, worse
                    # failure class than an as-yet-unpinned file.
                    findings.append(Finding(
                        scanner=self.name,
                        severity=Severity.CRITICAL,
                        file=rel,
                        line=1,
                        match="@import",
                        detail=err.detail,
                        checklist_item="AGENT-CTX-3: @import targets stay within repo boundary",
                    ))
                else:
                    # missing / cycle / depth: unverifiable content -> integrity
                    # error, which the CLI turns into a gating finding.
                    self.integrity_errors.append((path, err.detail))
                continue
            live[rel] = (hashlib.sha256(resolved_text.encode("utf-8")).hexdigest(), contributing)

        # Hash + unpinned checks against the manifest.
        for rel, (resolved_hash, contributing) in live.items():
            entry = manifest_files.get(rel)
            if entry is None:
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.HIGH,
                    file=rel,
                    line=1,
                    match=rel,
                    detail=(
                        "Tracked agent-context file is not pinned in "
                        f"{MANIFEST_NAME} (no manifest entry). An unpinned context "
                        "file is unverified — pin it via a reviewed manifest change."
                    ),
                    checklist_item="AGENT-CTX-2: All agent-context files pinned in manifest",
                ))
                continue
            if entry.get("resolved_sha256") != resolved_hash:
                drift = _describe_drift(entry.get("includes", {}) or {}, contributing)
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=1,
                    match=rel,
                    detail=(
                        "Agent-context file (resolved with @imports) does not match "
                        f"its pinned hash in {MANIFEST_NAME} — {drift}. If this change "
                        "is intended, re-pin through a reviewed manifest diff."
                    ),
                    checklist_item="AGENT-CTX-1: Agent-context file matches pinned hash",
                ))

        # Pinned files that have gone missing from the tree entirely.
        # Classified CRITICAL: a pinned context file vanishing is a content change
        # from the pin, same failure class as a hash mismatch. (Severity beyond the
        # locked mismatch/unpinned/pattern set — flagged for confirmation.)
        for rel in manifest_files:
            if not (root / rel).exists():
                findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=1,
                    match=rel,
                    detail=(
                        f"Pinned agent-context file is missing from the tree but "
                        f"present in {MANIFEST_NAME}. Removal of a pinned context "
                        "file must go through a reviewed manifest change."
                    ),
                    checklist_item="AGENT-CTX-1: Agent-context file matches pinned hash",
                ))

        # Heuristic pattern layer: INFO only, never gating, never waived.
        for path in tracked:
            findings.extend(self._pattern_findings(root, path))

        return findings

    def _gather_tracked(self, root: Path) -> list[Path]:
        seen: set[Path] = set()
        out: list[Path] = []
        for pattern in TRACKED_GLOBS:
            for path in root.glob(pattern):
                if not path.is_file():
                    continue
                # Exclude by path component RELATIVE to root, so a repo living
                # under a dir named e.g. "build" is not wrongly skipped.
                rel_parts = path.relative_to(root).parts
                if any(part in self._excludes for part in rel_parts):
                    continue
                if path.is_symlink():
                    # A symlinked entrypoint could hash content outside the tree;
                    # do not follow it silently. Fail closed as an integrity error.
                    self.integrity_errors.append((path, "tracked agent-context file is a symlink; not followed"))
                    continue
                if path in seen:
                    continue
                seen.add(path)
                out.append(path)
        return sorted(out)

    def _load_manifest(self, root: Path) -> dict[str, dict]:
        """Return the manifest's `files` map, or {} when absent/unreadable.

        A missing manifest yields {} (tracked files then surface as unpinned).
        A present-but-broken manifest additionally records an integrity error so
        the gate fails closed rather than silently treating everything unpinned.
        """
        mpath = root / MANIFEST_NAME
        if not mpath.exists():
            return {}
        try:
            files = validate_files_map(json.loads(mpath.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            self.integrity_errors.append((mpath, f"invalid manifest: {exc}"))
            return {}
        return files

    def _pattern_findings(self, root: Path, path: Path) -> list[Finding]:
        text = self._read_text(path)  # strict UTF-8; undecodable -> integrity error
        if text is None:
            return []
        rel = self._rel(root, path)
        lines = text.splitlines()
        findings: list[Finding] = []

        def add(line_no: int, detail: str) -> None:
            findings.append(Finding(
                scanner=self.name,
                severity=Severity.INFO,
                file=rel,
                line=line_no,
                match=(lines[line_no - 1].strip()[:120] if 1 <= line_no <= len(lines) else ""),
                detail=detail + " (heuristic, non-gating)",
                checklist_item="AGENT-CTX-4: Agent-context file free of loader-directed instruction patterns",
            ))

        if _URL_RE.search(text) and _FETCH_LANGUAGE_RE.search(text):
            add(self._first_line(lines, _URL_RE), "URL present alongside download/execute phrasing")
        if _SHELL_FRAGMENT_RE.search(text):
            add(self._first_line(lines, _SHELL_FRAGMENT_RE), "shell/PowerShell execution fragment")
        if _BASE64_BLOB_RE.search(text):
            add(self._first_line(lines, _BASE64_BLOB_RE), "long base64-like blob")
        if _AGENT_IMPERATIVE_RE.search(text):
            add(self._first_line(lines, _AGENT_IMPERATIVE_RE),
                "imperative phrasing directed at the loader ('always/every time ... load/read ... this file')")
        uni = self._suspicious_unicode(text)
        if uni:
            add(1, f"suspicious/zero-width Unicode: {', '.join(uni)}")

        return findings

    @staticmethod
    def _first_line(lines: list[str], pattern: re.Pattern) -> int:
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                return i
        return 1

    @staticmethod
    def _suspicious_unicode(text: str) -> list[str]:
        hits: list[str] = []
        for ch in sorted(set(text)):
            if unicodedata.category(ch) == "Cf":
                hits.append(f"U+{ord(ch):04X} ({unicodedata.name(ch, 'UNKNOWN')})")
        return hits
