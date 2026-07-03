"""Failure-visibility tests — fail-open audit 2026-07-03.

Every test here pins one invariant: a scan failure must be VISIBLE (a gating
finding, a degradation finding, or a loud warning), never a silent skip.
Unscannable ≠ clean.
"""
import json
import os
from unittest.mock import MagicMock, patch

import httpx
import pytest

from security_gate.accepted import load_accepted
from security_gate.dast.scanner import DastScanner
from security_gate.scanner.base import _SEVERITY_ORDER, Severity
from security_gate.scanner.deps import DepsScanner
from security_gate.scanner.git_history import GitHistoryScanner
from security_gate.scanner.sca import ScaScanner
from security_gate.scanner.secrets import SecretsScanner
from security_gate.scanner.semgrep_scanner import SemgrepScanner

needs_nonroot = pytest.mark.skipif(
    os.geteuid() == 0, reason="chmod 000 does not block reads for root"
)


# ── severity ordering invariant ──────────────────────────────────────────────

def test_every_severity_has_explicit_rank():
    # cli.py's integrity dedupe and Finding.sort_key both rely on this dict —
    # a new Severity member without an explicit rank must fail here, not KeyError
    # at scan time.
    assert set(_SEVERITY_ORDER) == set(Severity)


# ── file-read failures are recorded, not skipped (Class A) ───────────────────

@needs_nonroot
def test_unreadable_file_recorded_not_skipped(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    f.chmod(0)
    scanner = SecretsScanner()
    scanner.scan(tmp_path)
    f.chmod(0o644)
    assert scanner.integrity_errors, "unreadable file must be recorded"
    path, err = scanner.integrity_errors[0]
    assert path == f
    assert "denied" in err.lower() or "errno" in err.lower()


def test_undecodable_file_recorded(tmp_path):
    # errors="replace" used to scan garbage in place of undecodable bytes —
    # strict decode must record the file instead.
    f = tmp_path / "bad.py"
    f.write_bytes(b"x = '\xff\xfe garbage'\n")
    scanner = SecretsScanner()
    scanner.scan(tmp_path)
    assert any(p == f for p, _ in scanner.integrity_errors)


def test_broken_symlink_recorded(tmp_path):
    link = tmp_path / "ghost.py"
    link.symlink_to(tmp_path / "nonexistent.py")
    scanner = SecretsScanner()
    scanner.scan(tmp_path)
    assert any(p == link for p, _ in scanner.integrity_errors)


# ── CLI: one deduped gating finding per file, waivable ───────────────────────

@needs_nonroot
def test_cli_emits_single_gating_scan_integrity_finding(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from security_gate.cli import app

    f = tmp_path / "app.py"
    f.write_text("import os\n")
    f.chmod(0)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "-o", "json", "--save"])
    f.chmod(0o644)
    assert result.exit_code == 1
    report = json.loads((tmp_path / "security-gate-report.json").read_text())
    integ = [x for x in report["findings"] if x["scanner"] == "scan_integrity"]
    assert len(integ) == 1, "must be deduped across all scanners that hit the file"
    assert integ[0]["severity"] == "HIGH"
    assert integ[0]["file"] == "app.py"
    assert report["gate"] == "BLOCKED"


@needs_nonroot
def test_cli_scan_integrity_waivable(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from security_gate.cli import app

    f = tmp_path / "app.py"
    f.write_text("import os\n")
    f.chmod(0)
    (tmp_path / "accepted-findings.toml").write_text(
        '[[accepted]]\n'
        'scanner = "scan_integrity"\n'
        'file = "app.py"\n'
        'match = "denied"\n'
        'rationale = "deliberately unreadable fixture"\n'
        'reviewer = "leighton"\n'
        'date = "2026-07-03"\n'
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "-o", "json", "--save"])
    f.chmod(0o644)
    assert result.exit_code == 0
    report = json.loads((tmp_path / "security-gate-report.json").read_text())
    assert report["gate"] == "PASSED"
    assert any(x["scanner"] == "scan_integrity" for x in report.get("accepted", []))


# ── pyproject parse failures are recorded (Class C) ──────────────────────────

def test_deps_malformed_pyproject_recorded(tmp_path):
    (tmp_path / "pyproject.toml").write_text("not [valid toml\n")
    scanner = DepsScanner()
    scanner.scan(tmp_path)
    assert any("parse error" in err for _, err in scanner.integrity_errors)


def test_sca_malformed_pyproject_recorded(tmp_path):
    (tmp_path / "pyproject.toml").write_text("not [valid toml\n")
    scanner = ScaScanner()
    findings = scanner.scan(tmp_path)
    assert any("parse error" in err for _, err in scanner.integrity_errors)
    # dep files exist but nothing was parseable — the INFO marker still fires,
    # the scan must not silently look clean
    assert findings and findings[0].severity == Severity.INFO


# ── git history: infrastructure failure fails HIGH (Class B) ─────────────────

def test_git_missing_emits_high(tmp_path):
    (tmp_path / ".git").mkdir()
    with patch(
        "security_gate.scanner.git_history.subprocess.run",
        side_effect=FileNotFoundError(),
    ):
        findings = GitHistoryScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) == 1
    assert "not found" in high[0].match


def test_git_error_exit_emits_high(tmp_path):
    (tmp_path / ".git").mkdir()
    mock = MagicMock(returncode=128, stdout="", stderr="fatal: bad object\n")
    with patch("security_gate.scanner.git_history.subprocess.run", return_value=mock):
        findings = GitHistoryScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) == 1
    assert "exited 128" in high[0].match
    assert "bad object" in high[0].match


def test_git_clean_repo_no_error_finding(tmp_path):
    # ([], None) is a genuine no-matches result — must NOT trip the error path
    (tmp_path / ".git").mkdir()
    mock = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_gate.scanner.git_history.subprocess.run", return_value=mock):
        findings = GitHistoryScanner().scan(tmp_path)
    assert findings == []


# ── semgrep: degraded output is a finding, not a clean scan (Class B) ────────

def test_semgrep_empty_output_emits_medium(tmp_path):
    mock = MagicMock(returncode=0, stdout="", stderr="")
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "no output" in findings[0].match


def test_semgrep_invalid_json_emits_medium(tmp_path):
    mock = MagicMock(returncode=0, stdout="{not json", stderr="")
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "not valid JSON" in findings[0].match


def test_semgrep_blank_message_does_not_crash(tmp_path):
    data = {"results": [{
        "check_id": "rules.sgw-llm-injection-taint",
        "path": "a.py",
        "start": {"line": 3},
        "extra": {"severity": "WARNING", "message": "", "lines": "x = 1"},
    }]}
    mock = MagicMock(returncode=1, stdout=json.dumps(data), stderr="")
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 3


# ── waiver loader: fail-closed but loud (Class E) ────────────────────────────

def test_accepted_malformed_toml_warns(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text("not [valid")
    entries, warnings = load_accepted(tmp_path)
    assert entries == []
    assert len(warnings) == 1
    assert "ALL waivers ignored" in warnings[0]


def test_accepted_incomplete_entry_warns(tmp_path):
    (tmp_path / "accepted-findings.toml").write_text(
        '[[accepted]]\nscanner = "secrets"\nfile = "a.py"\nmatch = ""\n'
    )
    entries, warnings = load_accepted(tmp_path)
    assert entries == []
    assert len(warnings) == 1
    assert "entry 1 incomplete" in warnings[0]


def test_accepted_missing_tomli_warns(tmp_path, monkeypatch):
    import security_gate.accepted as accepted_mod

    (tmp_path / "accepted-findings.toml").write_text("[[accepted]]\n")
    monkeypatch.setattr(accepted_mod, "tomllib", None)
    entries, warnings = load_accepted(tmp_path)
    assert entries == []
    assert "tomli is not installed" in warnings[0]


# ── DAST: dropped probes are unmeasured coverage, HIGH (Class F) ─────────────

def _resp(json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = json.dumps(json_data)
    resp.json.return_value = json_data
    return resp


def test_dast_all_probes_failing_emits_high():
    scanner = DastScanner(base_url="http://localhost:9")
    client = MagicMock()
    client.post.side_effect = httpx.ConnectError("connection refused")
    payloads = [{"label": "threat", "text": "t", "variant": "dan"}]
    findings = scanner._check_chat_endpoint(client, payloads)
    pf = [f for f in findings if f.payload_variant == "probe_failures"]
    assert len(pf) == 1
    assert pf[0].severity == Severity.HIGH
    assert "1 of 1" in pf[0].detail


def test_dast_partial_probe_failure_still_emits_high():
    # the detection rate over the remaining probes must not silently absorb
    # the dropped one
    scanner = DastScanner(base_url="http://localhost:9")
    client = MagicMock()
    ok = _resp({"classification": "malicious", "risk_level": "HIGH"})
    client.post.side_effect = [httpx.ConnectError("reset"), ok]
    payloads = [
        {"label": "threat", "text": "a", "variant": "dan"},
        {"label": "threat", "text": "b", "variant": "inject"},
    ]
    findings = scanner._check_chat_endpoint(client, payloads)
    pf = [f for f in findings if f.payload_variant == "probe_failures"]
    assert len(pf) == 1
    assert pf[0].severity == Severity.HIGH
    assert "1 of 2" in pf[0].detail
