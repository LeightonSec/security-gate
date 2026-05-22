from pathlib import Path

import pytest

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
