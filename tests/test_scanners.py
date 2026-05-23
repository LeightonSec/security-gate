from pathlib import Path

import pytest

from security_gate.scanner.ai_ml import AiMlScanner
from security_gate.scanner.outbound import OutboundScanner
from security_gate.scanner.path_manip import PathManipScanner
from security_gate.scanner.secrets import SecretsScanner
from security_gate.scanner.retention import RetentionScanner
from security_gate.scanner.validation import ValidationScanner
from security_gate.scanner.deps import DepsScanner
from security_gate.report.generator import gate_passed
from security_gate.scanner.base import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_outbound_detects_requests_and_sdk():
    findings = OutboundScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_outbound" in f for f in files)


def test_outbound_clean_fixture_no_findings():
    findings = OutboundScanner().scan(FIXTURES / "clean.py".replace("/", ""))
    # clean.py has no outbound calls
    clean_findings = [f for f in OutboundScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_path_manip_detects_sys_path():
    findings = PathManipScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_path_manip" in f for f in files)


def test_path_manip_severity_is_high():
    findings = PathManipScanner().scan(FIXTURES)
    path_findings = [f for f in findings if "has_path_manip" in f.file]
    assert all(f.severity == Severity.HIGH for f in path_findings)


def test_secrets_detects_changeme_default():
    findings = SecretsScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_secrets" in f for f in files)


def test_secrets_detects_inline_key():
    findings = SecretsScanner().scan(FIXTURES)
    inline = [f for f in findings if "has_secrets" in f.file and f.severity == Severity.CRITICAL]
    assert len(inline) >= 1


def test_secrets_clean_fixture_no_findings():
    clean_findings = [f for f in SecretsScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_retention_detects_db_write_without_ttl():
    findings = RetentionScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_retention" in f for f in files)


def test_validation_detects_unvalidated_flask_input():
    findings = ValidationScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_validation" in f for f in files)


def test_validation_clean_fixture_suppressed_by_pydantic():
    clean_findings = [f for f in ValidationScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_gate_passed_no_findings():
    assert gate_passed([]) is True


def test_gate_blocked_on_critical(tmp_path):
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.CRITICAL,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings) is False


def test_gate_blocked_on_high(tmp_path):
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.HIGH,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings) is False


def test_gate_passed_on_medium_only(tmp_path):
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.MEDIUM,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings) is True


# --- DepsScanner: pyproject.toml support ---

def test_deps_pyproject_unpinned_flagged(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests>=2.28.0\", \"click\"]\n"
    )
    findings = DepsScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    names = [f.match for f in medium]
    assert any("requests" in n for n in names)
    assert any("click" in n for n in names)


def test_deps_pyproject_pinned_no_medium(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests==2.31.0\"]\n"
    )
    findings = DepsScanner().scan(tmp_path)
    assert not any(f.severity == Severity.MEDIUM for f in findings)


def test_deps_pyproject_no_req_file_fires_high(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests>=2.28.0\"]\n"
    )
    findings = DepsScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) == 1
    assert "pyproject.toml" in high[0].file


def test_deps_pyproject_with_req_file_no_double_high(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests>=2.28.0\"]\n"
    )
    (tmp_path / "requirements.txt").write_text("requests>=2.28.0\n")
    findings = DepsScanner().scan(tmp_path)
    # requirements.txt scan fires HIGH for missing hashes; pyproject scan must not add a second
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) == 1


def test_deps_pyproject_optional_deps_scanned(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = []\n"
        "[project.optional-dependencies]\ndev = [\"pytest>=7.0\", \"ruff\"]\n"
    )
    findings = DepsScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    names = [f.match for f in medium]
    assert any("pytest" in n for n in names)
    assert any("ruff" in n for n in names)


def test_deps_pyproject_lockfile_suppresses_high(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = [\"requests>=2.28.0\"]\n"
    )
    (tmp_path / "uv.lock").write_text("# uv lockfile\n")
    findings = DepsScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high == []


# --- AiMlScanner ---

def test_ai_ml_detects_unpinned_pretrained():
    findings = AiMlScanner().scan(FIXTURES)
    high = [f for f in findings if "has_ai_ml" in f.file and f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_ai_ml_detects_trust_remote_code():
    findings = AiMlScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ai_ml" in f.file and f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_ai_ml_detects_permissive_telemetry():
    findings = AiMlScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_ai_ml" in f.file and f.severity == Severity.MEDIUM]
    assert len(medium) >= 1


def test_ai_ml_clean_fixture_no_findings():
    clean_findings = [f for f in AiMlScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_ai_ml_pinned_pretrained_no_finding(tmp_path):
    f = tmp_path / "model_loader.py"
    f.write_text(
        'model = AutoModel.from_pretrained(\n'
        '    "bert-base-uncased",\n'
        '    revision="abc123def456",\n'
        ')\n'
    )
    findings = AiMlScanner().scan(tmp_path)
    assert findings == []
