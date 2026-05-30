"""Accepted findings — structured suppression for findings that cannot be suppressed inline.

Format: accepted-findings.toml at the root of the repo being scanned.

    [[accepted]]
    scanner  = "git_history"
    file     = "git history"
    match    = "4562cfee"          # substring match against the finding's match field
    rationale = "Example placeholder in .env.example — not a real credential"
    reviewer  = "leighton"
    date      = "2026-05-30"

Matching uses substring containment on both `file` and `match` fields so short commit
hash prefixes work without requiring the full 40-char SHA.
"""
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


@dataclass
class AcceptedEntry:
    scanner: str
    file: str
    match: str
    rationale: str
    reviewer: str
    date: str


def load_accepted(repo_root: Path) -> list[AcceptedEntry]:
    path = repo_root / "accepted-findings.toml"
    if not path.exists() or tomllib is None:
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    entries = []
    for item in data.get("accepted", []):
        scanner = item.get("scanner", "").strip()
        file_ = item.get("file", "").strip()
        match = item.get("match", "").strip()
        if not (scanner and file_ and match):
            continue  # skip incomplete entries — empty strings would match everything
        entries.append(AcceptedEntry(
            scanner=scanner,
            file=file_,
            match=match,
            rationale=item.get("rationale", ""),
            reviewer=item.get("reviewer", ""),
            date=str(item.get("date", "")),
        ))
    return entries


def _matches(finding, entry: AcceptedEntry) -> bool:
    file_val = getattr(finding, "file", getattr(finding, "endpoint", ""))
    match_val = getattr(finding, "match", getattr(finding, "payload_variant", ""))
    return (
        finding.scanner == entry.scanner
        and entry.file in file_val
        and entry.match in match_val
    )


def partition_findings(
    findings: list,
    accepted: list[AcceptedEntry],
) -> tuple[list, list[tuple]]:
    """Split findings into (active, [(suppressed_finding, AcceptedEntry)]).

    Active findings are passed to gate_passed() and appear in the main report.
    Suppressed findings are shown in a separate accepted section with rationale.
    """
    if not accepted:
        return list(findings), []
    active = []
    suppressed = []
    for f in findings:
        matched = next((e for e in accepted if _matches(f, e)), None)
        if matched:
            suppressed.append((f, matched))
        else:
            active.append(f)
    return active, suppressed
