
from security_gate.accepted import load_accepted, partition_findings
from security_gate.report.generator import gate_passed
from security_gate.scanner.base import Finding, Severity

_TOML = """\
[[accepted]]
scanner  = "git_history"
file     = "git history"
match    = "4562cfee"
rationale = "Example placeholder in .env.example — not a real credential"
reviewer  = "leighton"
date      = "2026-05-30"
"""


def _git_finding(match: str = "4562cfee04021f2a8210860bd2d2e49c159ff8de") -> Finding:
    return Finding(
        scanner="git_history",
        severity=Severity.HIGH,
        file="git history",
        line=1,
        match=match,
        detail="API key pattern in history",
        checklist_item="GIT-HIST-1",
    )


def _other_finding() -> Finding:
    return Finding(
        scanner="hardcoded_secrets",
        severity=Severity.CRITICAL,
        file="app.py",
        line=42,
        match="SECRET_KEY = 'changeme'",
        detail="Hardcoded secret",
        checklist_item="PHASE-3-1",
    )


# --- load_accepted ---

def test_load_accepted_returns_empty_without_file(tmp_path):
    entries = load_accepted(tmp_path)
    assert entries == []


def test_load_accepted_parses_entry(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    assert len(entries) == 1
    assert entries[0].scanner == "git_history"
    assert entries[0].file == "git history"
    assert entries[0].match == "4562cfee"
    assert entries[0].reviewer == "leighton"
    assert entries[0].rationale.startswith("Example")


def test_load_accepted_skips_entry_with_empty_scanner(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(
        '[[accepted]]\nscanner = ""\nfile = "git history"\nmatch = "abc123"\n'
        'rationale = "test"\nreviewer = "x"\ndate = "2026-05-30"\n'
    )
    entries = load_accepted(tmp_path)
    assert entries == []


def test_load_accepted_skips_entry_with_empty_match(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(
        '[[accepted]]\nscanner = "git_history"\nfile = "git history"\nmatch = ""\n'
        'rationale = "test"\nreviewer = "x"\ndate = "2026-05-30"\n'
    )
    entries = load_accepted(tmp_path)
    assert entries == []


def test_load_accepted_skips_entry_with_empty_file(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(
        '[[accepted]]\nscanner = "git_history"\nfile = ""\nmatch = "abc123"\n'
        'rationale = "test"\nreviewer = "x"\ndate = "2026-05-30"\n'
    )
    entries = load_accepted(tmp_path)
    assert entries == []


def test_load_accepted_returns_empty_on_malformed_toml(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text("not valid toml [[[\n")
    entries = load_accepted(tmp_path)
    assert entries == []


def test_load_accepted_multiple_entries(tmp_path):
    toml = _TOML + (
        '\n[[accepted]]\nscanner = "hardcoded_secrets"\nfile = "app.py"\n'
        'match = "changeme"\nrationale = "test"\nreviewer = "x"\ndate = "2026-05-30"\n'
    )
    (tmp_path / "accepted-findings.toml").write_text(toml)
    entries = load_accepted(tmp_path)
    assert len(entries) == 2


# --- partition_findings ---

def test_partition_empty_accepted_returns_all_active():
    findings = [_git_finding(), _other_finding()]
    active, suppressed = partition_findings(findings, [])
    assert len(active) == 2
    assert suppressed == []


def test_partition_matching_finding_is_suppressed(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    findings = [_git_finding()]
    active, suppressed = partition_findings(findings, entries)
    assert active == []
    assert len(suppressed) == 1
    assert suppressed[0][0].scanner == "git_history"
    assert suppressed[0][1].rationale.startswith("Example")


def test_partition_non_matching_finding_stays_active(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    findings = [_other_finding()]
    active, suppressed = partition_findings(findings, entries)
    assert len(active) == 1
    assert suppressed == []


def test_partition_mixed_findings_split_correctly(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    findings = [_git_finding(), _other_finding()]
    active, suppressed = partition_findings(findings, entries)
    assert len(active) == 1
    assert active[0].scanner == "hardcoded_secrets"
    assert len(suppressed) == 1


def test_partition_substring_match_on_short_hash(tmp_path):
    # Accepted entry uses 8-char prefix; finding has full 40-char hash
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    full_hash = "4562cfee04021f2a8210860bd2d2e49c159ff8de"
    findings = [_git_finding(match=full_hash)]
    active, suppressed = partition_findings(findings, entries)
    assert active == []
    assert len(suppressed) == 1


def test_partition_non_matching_hash_not_suppressed(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    findings = [_git_finding(match="deadbeef99999999deadbeefdeadbeefdeadbeef")]
    active, suppressed = partition_findings(findings, entries)
    assert len(active) == 1
    assert suppressed == []


# --- Gate integration ---

def test_gate_passes_when_only_accepted_findings_remain(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    all_findings = [_git_finding()]
    active, _ = partition_findings(all_findings, entries)
    assert gate_passed(active) is True


def test_gate_blocked_when_non_accepted_high_remains(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(_TOML)
    entries = load_accepted(tmp_path)
    all_findings = [_git_finding(), _other_finding()]
    active, _ = partition_findings(all_findings, entries)
    assert gate_passed(active) is False


def test_gate_blocked_without_accepted_file(tmp_path):
    all_findings = [_git_finding()]
    active, _ = partition_findings(all_findings, [])
    assert gate_passed(active) is False
