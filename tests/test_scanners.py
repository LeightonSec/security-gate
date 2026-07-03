import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from security_gate.report.generator import gate_passed
from security_gate.scanner.ai_ml import AiMlScanner
from security_gate.scanner.bare_suppress import BareSuppressScanner
from security_gate.scanner.base import Severity
from security_gate.scanner.cmd_injection import CmdInjectionScanner
from security_gate.scanner.crypto import CryptoScanner
from security_gate.scanner.deps import DepsScanner
from security_gate.scanner.git_history import GitHistoryScanner
from security_gate.scanner.hardcoded_timeout import HardcodedTimeoutScanner
from security_gate.scanner.llm_injection import LlmInjectionScanner
from security_gate.scanner.outbound import OutboundScanner
from security_gate.scanner.path_manip import PathManipScanner
from security_gate.scanner.pickle_usage import PickleUsageScanner
from security_gate.scanner.retention import RetentionScanner
from security_gate.scanner.sca import ScaScanner
from security_gate.scanner.secrets import SecretsScanner
from security_gate.scanner.security_tool import SecurityToolScanner
from security_gate.scanner.semgrep_scanner import SemgrepScanner
from security_gate.scanner.ssrf import SsrfScanner
from security_gate.scanner.ssti import SstiScanner
from security_gate.scanner.validation import ValidationScanner
from security_gate.scanner.web_app import WebAppScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_outbound_detects_requests_and_sdk():
    findings = OutboundScanner().scan(FIXTURES)
    files = [f.file for f in findings]
    assert any("has_outbound" in f for f in files)


def test_outbound_clean_fixture_no_findings():
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


def test_validation_clean_fixture_no_entry_points():
    # clean.py has no request/json/yaml entry points — clean for the right reason
    clean_findings = [f for f in ValidationScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_validation_pydantic_import_without_nearby_usage_still_fires(tmp_path):
    # Pydantic imported at file level but entry point has no validation in proximity
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "from pydantic import BaseModel\n"
        "\n"
        "class Body(BaseModel):\n"
        "    name: str\n"
        "\n"
        "def endpoint():\n"
        "    data = request.get_json()\n"
        "    name = data.get('name')\n"
        "    age = data.get('age')\n"
        "    result = name + str(age)\n"
        "    return result\n"
    )
    findings = ValidationScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"


def test_validation_pydantic_in_proximity_suppresses_finding(tmp_path):
    # Entry point immediately followed by model_validate — within window, no finding
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "from pydantic import BaseModel\n"
        "\n"
        "class Body(BaseModel):\n"
        "    name: str\n"
        "\n"
        "def endpoint():\n"
        "    data = request.get_json()\n"
        "    body = Body.model_validate(data)\n"
        "    return body.name\n"
    )
    findings = ValidationScanner().scan(tmp_path)
    assert findings == []


def test_validation_yaml_load_is_critical(tmp_path):
    f = tmp_path / "loader.py"
    f.write_text("import yaml\ndata = yaml.load(stream)\n")
    findings = ValidationScanner().scan(tmp_path)
    assert any(f.severity.value == "CRITICAL" for f in findings)


def test_validation_yaml_safe_load_is_high(tmp_path):
    f = tmp_path / "loader.py"
    f.write_text("import yaml\ndata = yaml.safe_load(stream)\n")
    findings = ValidationScanner().scan(tmp_path)
    assert any(f.severity.value == "HIGH" for f in findings)


def test_validation_gate_ignore_suppresses_finding(tmp_path):
    f = tmp_path / "state.py"
    f.write_text('data = json.loads(p.read_text())  # gate: ignore — reads tool state file, not external input\n')
    findings = ValidationScanner().scan(tmp_path)
    assert findings == []


def test_validation_without_suppression_still_fires(tmp_path):
    f = tmp_path / "state.py"
    f.write_text('data = json.loads(p.read_text())\n')
    findings = ValidationScanner().scan(tmp_path)
    assert len(findings) == 1


def test_validation_multiline_model_constructor_suppresses(tmp_path):
    # Entry points are kwargs inside an open user-model constructor spanning lines.
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "from schemas import TicketFilter\n"
        "def get_tickets():\n"
        "    filters = TicketFilter(\n"
        "        status=request.args.get('status'),\n"
        "        priority=request.args.get('priority'),\n"
        "        source=request.args.get('source'),\n"
        "        department=request.args.get('department'),\n"
        "    )\n"
        "    return filters\n"
    )
    assert ValidationScanner().scan(tmp_path) == []


def test_validation_var_flows_into_model_constructor_suppresses(tmp_path):
    # raw = request.get_json() then TicketCreate(**raw) within the window.
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "from schemas import TicketCreate\n"
        "def create():\n"
        "    raw = request.get_json()\n"
        "    try:\n"
        "        body = TicketCreate(**raw)\n"
        "    except ValidationError:\n"
        "        return 400\n"
        "    return body\n"
    )
    assert ValidationScanner().scan(tmp_path) == []


def test_validation_validator_opening_above_entry_point_suppresses(tmp_path):
    # model_validate( opens on the line above the response.json() argument.
    f = tmp_path / "intel.py"
    f.write_text(
        "def fetch():\n"
        "    data = _AbuseIPDBData.model_validate(\n"
        "        response.json().get('data', {})\n"
        "    )\n"
        "    return data\n"
    )
    assert ValidationScanner().scan(tmp_path) == []


def test_validation_unrelated_validation_in_window_still_fires(tmp_path):
    # Validation of an UNRELATED value in the window must not suppress the finding
    # for the bound variable that is never validated (false-negative guard).
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "def handler():\n"
        "    raw = request.get_json()\n"
        "    log(raw)\n"
        "    other = Model.model_validate(something_else)\n"
        "    db.execute(raw['q'])\n"
    )
    findings = ValidationScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 3


def test_validation_non_model_capwords_does_not_suppress(tmp_path):
    # A non-validating CapWords constructor (Dict/Request/Response/Exception) must
    # NOT suppress a real finding — only model-named constructors count as validation.
    srcs = {
        "resp.py": "from flask import request\ndef h():\n    raw = request.get_json()\n    return Response(raw)\n",
        "dct.py": "from flask import request\ndef h():\n    data = request.get_json()\n    return Dict(**data)\n",
        "exc.py": "from flask import request\ndef h():\n    raw = request.get_json()\n    raise Exception(raw)\n",
        "req.py": "from flask import request\ndef h():\n    r = Request(\n        request.get_json()\n    )\n    return r\n",
    }
    for name, src in srcs.items():
        f = tmp_path / name
        f.write_text(src)
    findings = ValidationScanner().scan(tmp_path)
    by_file = {f.file: f for f in findings}
    for name in srcs:
        assert name in by_file, f"{name}: non-model CapWords wrongly suppressed the finding"


def test_validation_model_named_capwords_suppresses(tmp_path):
    # Model-named CapWords constructors (Create/Filter/Schema suffixes) DO count.
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "def h():\n"
        "    raw = request.get_json()\n"
        "    body = OrderCreate(**raw)\n"
        "    return body\n"
    )
    assert ValidationScanner().scan(tmp_path) == []


def test_validation_manual_guard_clause_still_fires(tmp_path):
    # Manual guard-clause validation (isinstance + early return) is NOT recognised
    # as a validation boundary — stays a finding for human review (decision A).
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import request\n"
        "def analyse():\n"
        "    data = request.get_json(silent=True)\n"
        "    if not data or 'prompt' not in data:\n"
        "        return _error(400)\n"
        "    prompt = data['prompt']\n"
        "    if not isinstance(prompt, str):\n"
        "        return _error(400)\n"
        "    return prompt\n"
    )
    findings = ValidationScanner().scan(tmp_path)
    assert len(findings) == 1


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


def test_deps_hash_pinned_requirements_no_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.1.3 \\\n"
        "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\\n"
        "    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
    )
    findings = DepsScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert medium == []


def test_deps_unpinned_requirement_still_fires(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask>=3.0.0\n")
    findings = DepsScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(medium) == 1


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


# --- WebAppScanner ---

def test_web_app_detects_debug_mode():
    findings = WebAppScanner().scan(FIXTURES)
    high = [f for f in findings if "has_web_app" in f.file and f.severity == Severity.HIGH]
    assert any("debug" in f.match.lower() or "DEBUG" in f.match for f in high)


def test_web_app_detects_sql_injection():
    findings = WebAppScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_web_app" in f.file and f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_web_app_detects_cors_wildcard():
    findings = WebAppScanner().scan(FIXTURES)
    high = [f for f in findings if "has_web_app" in f.file and f.severity == Severity.HIGH]
    assert any("CORS" in f.match or "cors" in f.match.lower() for f in high)


def test_web_app_detects_unauthenticated_state_route():
    findings = WebAppScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_web_app" in f.file and f.severity == Severity.MEDIUM]
    assert len(medium) >= 1


def test_web_app_clean_fixture_no_findings():
    clean_findings = [f for f in WebAppScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_web_app_authenticated_route_no_finding(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import Flask\n'
        'app = Flask(__name__)\n'
        '@app.route("/secure", methods=["POST"])\n'
        '@login_required\n'
        'def secure_view():\n'
        '    pass\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert medium == []


def test_web_app_get_only_route_no_finding(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        '@app.route("/public")\n'
        'def public_view():\n'
        '    return "hello"\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    assert findings == []


def test_web_app_parameterised_sql_no_finding(tmp_path):
    f = tmp_path / "db.py"
    f.write_text(
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical == []


def test_web_app_ddl_fstring_no_finding(tmp_path):
    f = tmp_path / "db.py"
    f.write_text(
        'conn.execute(f"ALTER TABLE attacks ADD COLUMN {col} {definition}")\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical == []


def test_web_app_dml_fstring_still_fires(tmp_path):
    f = tmp_path / "db.py"
    f.write_text(
        'conn.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 1


# --- SecurityToolScanner ---

def test_security_tool_detects_path_traversal():
    findings = SecurityToolScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_security_tool" in f.file and f.severity == Severity.MEDIUM]
    assert any("passwd" in f.match or "shadow" in f.match or ".." in f.match for f in medium)


def test_security_tool_detects_injection_payload():
    findings = SecurityToolScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_security_tool" in f.file and f.severity == Severity.MEDIUM]
    assert any("DROP TABLE" in f.match or "alert" in f.match or "onerror" in f.match for f in medium)


def test_security_tool_clean_fixture_no_findings():
    clean_findings = [f for f in SecurityToolScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_security_tool_skips_non_test_files(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("payload = '/etc/passwd'\n")
    findings = SecurityToolScanner().scan(tmp_path)
    assert findings == []


# --- Profile-aware gate ---

def test_gate_security_tool_profile_blocks_medium():
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.MEDIUM,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings, profile="security_tool") is False


def test_gate_security_tool_profile_passes_low():
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.LOW,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings, profile="security_tool") is True


def test_gate_default_profile_still_passes_medium():
    from security_gate.scanner.base import Finding, Severity
    findings = [Finding(
        scanner="test", severity=Severity.MEDIUM,
        file="x.py", line=1, match="x", detail="test", checklist_item="test",
    )]
    assert gate_passed(findings) is True


# --- ScaScanner ---

def _osv_mock(results: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.json.return_value = {"results": results}
    mock.raise_for_status.return_value = None
    return mock


def test_sca_clean_on_no_dep_files(tmp_path):
    findings = ScaScanner().scan(tmp_path)
    assert findings == []


def test_sca_skips_with_info_when_no_pinned_deps(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.28.0\nclick\n")
    findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "no pinned versions" in findings[0].detail.lower()


def test_sca_vuln_with_no_severity_defaults_to_high(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    osv_vuln = {
        "id": "GHSA-xxxx-xxxx-xxxx",
        "aliases": ["CVE-2023-9999"],
        "summary": "Critical RCE vulnerability",
        "database_specific": {},
        "affected": [],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [osv_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].match == "requests==2.28.0"
    assert "CVE-2023-9999" in findings[0].detail


def test_sca_maps_critical_severity(tmp_path):
    (tmp_path / "requirements.txt").write_text("pillow==9.0.0\n")
    osv_vuln = {
        "id": "GHSA-abcd-1234-abcd",
        "aliases": ["CVE-2024-1234"],
        "summary": "Remote code execution",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [osv_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_sca_maps_moderate_to_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text("cryptography==38.0.0\n")
    osv_vuln = {
        "id": "GHSA-mod-erat-efoo",
        "aliases": ["CVE-2024-9876"],
        "summary": "Moderate info disclosure",
        "database_specific": {"severity": "MODERATE"},
        "affected": [],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [osv_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_sca_reports_fix_version_in_detail(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
    osv_vuln = {
        "id": "GHSA-j8r2-6x86-q33q",
        "aliases": ["CVE-2023-32681"],
        "summary": ".netrc credentials leak",
        "database_specific": {"severity": "MODERATE"},
        "affected": [{
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
            }]
        }],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [osv_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert "fix: 2.31.0" in findings[0].detail


def test_sca_deduplicates_ghsa_and_pysec_same_cve(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
    ghsa_vuln = {
        "id": "GHSA-j8r2-6x86-q33q",
        "aliases": ["CVE-2023-32681"],
        "summary": ".netrc credentials leak",
        "database_specific": {"severity": "MODERATE"},
        "affected": [],
    }
    pysec_vuln = {
        "id": "PYSEC-2023-74",
        "aliases": ["CVE-2023-32681"],
        "summary": ".netrc credentials leak",
        "database_specific": {},
        "affected": [],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [ghsa_vuln, pysec_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert "CVE-2023-32681" in findings[0].detail


def test_sca_pyproject_pinned_deps_scanned(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests==2.25.0"]\n'
    )
    osv_vuln = {
        "id": "GHSA-j8r2-6x86-q33q",
        "aliases": ["CVE-2023-32681"],
        "summary": ".netrc credentials leak",
        "database_specific": {"severity": "MODERATE"},
        "affected": [],
    }
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": [osv_vuln]}])):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert "pyproject.toml" in findings[0].file
    assert findings[0].match == "requests==2.25.0"


def test_sca_osv_timeout_emits_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with patch("security_gate.scanner.sca.httpx.post",
               side_effect=httpx.TimeoutException("timeout")):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "timed out" in findings[0].detail
    assert "incomplete" in findings[0].detail


def test_sca_osv_network_error_emits_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with patch("security_gate.scanner.sca.httpx.post",
               side_effect=httpx.ConnectError("no route")):
        findings = ScaScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "OSV API error" in findings[0].detail


def test_sca_clean_package_no_findings(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.1.3\n")
    with patch("security_gate.scanner.sca.httpx.post",
               return_value=_osv_mock([{"vulns": []}])):
        findings = ScaScanner().scan(tmp_path)
    assert findings == []


# --- CryptoScanner ---

def test_crypto_detects_math_random():
    findings = CryptoScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_crypto" in f.file and f.severity == Severity.MEDIUM]
    assert any("CRYPTO-01" in f.checklist_item for f in medium)


def test_crypto_detects_cipheriv_without_aad():
    findings = CryptoScanner().scan(FIXTURES)
    high = [f for f in findings if "has_crypto" in f.file and f.severity == Severity.HIGH]
    assert any("CRYPTO-02" in f.checklist_item for f in high)


def test_crypto_detects_silent_catch():
    findings = CryptoScanner().scan(FIXTURES)
    medium = [f for f in findings if "has_crypto" in f.file and f.severity == Severity.MEDIUM]
    assert any("CRYPTO-04" in f.checklist_item for f in medium)


def test_crypto_detects_timing_unsafe_comparison():
    findings = CryptoScanner().scan(FIXTURES)
    high = [f for f in findings if "has_crypto" in f.file and f.severity == Severity.HIGH]
    assert any("CRYPTO-05" in f.checklist_item for f in high)


def test_crypto_detects_sensitive_material_in_log():
    findings = CryptoScanner().scan(FIXTURES)
    high = [f for f in findings if "has_crypto" in f.file and f.severity == Severity.HIGH]
    assert any("CRYPTO-06" in f.checklist_item for f in high)


def test_crypto_clean_fixture_no_findings():
    clean_findings = [f for f in CryptoScanner().scan(FIXTURES) if "clean" in f.file]
    assert clean_findings == []


def test_crypto_cipheriv_with_aad_no_finding(tmp_path):
    f = tmp_path / "enc.ts"
    f.write_text(
        'const cipher = createCipheriv("aes-256-gcm", key, iv)\n'
        'cipher.setAAD(aad)\n'
        'const out = cipher.update(data)\n'
    )
    findings = CryptoScanner().scan(tmp_path)
    assert not any("CRYPTO-02" in f.checklist_item for f in findings)


def test_crypto_cipheriv_without_aad_fires(tmp_path):
    f = tmp_path / "enc.ts"
    f.write_text(
        'const cipher = createCipheriv("aes-256-gcm", key, iv)\n'
        'const out = cipher.update(data)\n'
    )
    findings = CryptoScanner().scan(tmp_path)
    assert len([f for f in findings if "CRYPTO-02" in f.checklist_item]) == 1


def test_crypto_catch_with_logging_no_finding(tmp_path):
    f = tmp_path / "dec.ts"
    f.write_text(
        '} catch (err) {\n'
        '  console.error("failed:", err)\n'
        '  return null\n'
        '}\n'
    )
    findings = CryptoScanner().scan(tmp_path)
    assert not any("CRYPTO-04" in f.checklist_item for f in findings)


def test_crypto_null_comparison_excluded(tmp_path):
    f = tmp_path / "check.ts"
    f.write_text('if (this._keypair === null) throw new Error("not loaded")\n')
    findings = CryptoScanner().scan(tmp_path)
    assert not any("CRYPTO-05" in f.checklist_item for f in findings)


def test_crypto_suppressed_line_skipped(tmp_path):
    f = tmp_path / "enc.ts"
    f.write_text('const id = Math.random().toString(36)  # gate: ignore — non-cryptographic session ID, not used in security context\n')
    findings = CryptoScanner().scan(tmp_path)
    assert findings == []


# --- LlmInjectionScanner ---

def test_llm_injection_detects_direct_passthrough():
    findings = LlmInjectionScanner().scan(FIXTURES)
    high = [f for f in findings if "has_llm_injection" in f.file and f.severity == Severity.HIGH]
    assert len(high) >= 1
    assert "user_prompt" in high[0].detail


def test_llm_injection_detail_includes_source_line():
    findings = LlmInjectionScanner().scan(FIXTURES)
    high = [f for f in findings if "has_llm_injection" in f.file]
    assert any("line" in f.detail for f in high)


def test_llm_injection_clean_when_sanitized(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import request\n'
        'import anthropic\n'
        'client = anthropic.Anthropic()\n'
        'def chat():\n'
        '    raw = request.get_json().get("prompt")\n'
        '    clean = sanitize_input(raw)\n'
        '    response = client.messages.create(\n'
        '        messages=[{"role": "user", "content": clean}]\n'
        '    )\n'
    )
    findings = LlmInjectionScanner().scan(tmp_path)
    # 'raw' does not appear in the sink block; 'clean' is not tainted → no finding
    assert findings == []


def test_llm_injection_clean_when_tainted_var_absent_from_sink(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import request\n'
        'import anthropic\n'
        'client = anthropic.Anthropic()\n'
        'def chat():\n'
        '    user_prompt = request.get_json().get("prompt")\n'
        '    safe = sanitize_input(user_prompt)\n'
        '    response = client.messages.create(\n'
        '        messages=[{"role": "user", "content": safe}]\n'
        '    )\n'
    )
    findings = LlmInjectionScanner().scan(tmp_path)
    # sanitize_input( appears between source and sink → suppressed
    assert findings == []


def test_llm_injection_gate_ignore_suppresses(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import request\n'
        'import anthropic\n'
        'client = anthropic.Anthropic()\n'
        'def chat():\n'
        '    user_prompt = request.get_json().get("prompt")\n'
        '    response = client.messages.create(  # gate: ignore — validated upstream\n'
        '        messages=[{"role": "user", "content": user_prompt}]\n'
        '    )\n'
    )
    findings = LlmInjectionScanner().scan(tmp_path)
    assert findings == []


def test_llm_injection_no_findings_without_both_patterns(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import request\n'
        'def chat():\n'
        '    user_prompt = request.get_json().get("prompt")\n'
        '    return user_prompt\n'  # no LLM sink
    )
    findings = LlmInjectionScanner().scan(tmp_path)
    assert findings == []


# --- GitHistoryScanner ---

def test_git_history_skips_non_git_dir(tmp_path):
    findings = GitHistoryScanner().scan(tmp_path)
    assert findings == []


def test_git_history_shallow_clone_emits_info(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "shallow").write_text("abc123\n")
    findings = GitHistoryScanner().scan(tmp_path)
    info = [f for f in findings if f.severity == Severity.INFO]
    assert len(info) == 1
    assert "shallow" in info[0].detail.lower()


def test_git_history_shallow_clone_detail_includes_unshallow_hint(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "shallow").write_text("abc123\n")
    findings = GitHistoryScanner().scan(tmp_path)
    info = [f for f in findings if f.severity == Severity.INFO]
    assert "unshallow" in info[0].detail


def test_git_history_critical_on_aws_key(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    mock_result = MagicMock(returncode=0, stdout="abc123def456\n789abc012def\n")
    with patch("security_gate.scanner.git_history.subprocess.run", return_value=mock_result):
        findings = GitHistoryScanner().scan(tmp_path)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert any("AWS" in f.detail for f in critical)


def test_git_history_high_on_api_key_pattern(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    def side_effect(cmd, **kwargs):
        pattern = next((a for a in cmd if a.startswith("-G")), "")
        if "API_KEY" in pattern or "SECRET_KEY" in pattern:
            return MagicMock(returncode=0, stdout="deadbeef1234\n")
        return MagicMock(returncode=0, stdout="")

    with patch("security_gate.scanner.git_history.subprocess.run", side_effect=side_effect):
        findings = GitHistoryScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) >= 1


def test_git_history_clean_on_empty_output(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    mock_result = MagicMock(returncode=0, stdout="")
    with patch("security_gate.scanner.git_history.subprocess.run", return_value=mock_result):
        findings = GitHistoryScanner().scan(tmp_path)
    secret_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert secret_findings == []


def test_git_history_timeout_emits_high_finding(tmp_path):
    # HIGH, not MEDIUM: an unscannable history removes coverage from a gating
    # check and must fail closed (fail-open audit, 2026-07-03).
    import subprocess
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    with patch("security_gate.scanner.git_history.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30)):
        findings = GitHistoryScanner().scan(tmp_path)
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high) == 1
    assert "timed out" in high[0].match
    assert "could not complete" in high[0].detail


# --- WebAppScanner rate limiting (WEB-5) ---

def test_web_app_rate_limit_fires_on_unguarded_llm_route(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import Flask, request\n'
        'import anthropic\n'
        'app = Flask(__name__)\n'
        'client = anthropic.Anthropic()\n'
        '@app.route("/chat", methods=["POST"])\n'
        'def chat():\n'
        '    response = client.messages.create(\n'
        '        model="claude-3-5-sonnet-20241022",\n'
        '        messages=[{"role": "user", "content": "hello"}],\n'
        '    )\n'
        '    return {}\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    medium = [f for f in findings if f.severity == Severity.MEDIUM and "WEB-5" in f.checklist_item]
    assert len(medium) == 1


def test_web_app_rate_limit_suppressed_by_flask_limiter_import(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import Flask, request\n'
        'from flask_limiter import Limiter\n'
        'from flask_limiter.util import get_remote_address\n'
        'import anthropic\n'
        'app = Flask(__name__)\n'
        'limiter = Limiter(app, key_func=get_remote_address, default_limits=["200/day"])\n'
        'client = anthropic.Anthropic()\n'
        '@app.route("/chat", methods=["POST"])\n'
        'def chat():\n'
        '    response = client.messages.create(\n'
        '        model="claude-3-5-sonnet-20241022",\n'
        '        messages=[{"role": "user", "content": "hello"}],\n'
        '    )\n'
        '    return {}\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    web5 = [f for f in findings if "WEB-5" in f.checklist_item]
    assert web5 == []


def test_web_app_rate_limit_suppressed_by_decorator(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import Flask\n'
        'import anthropic\n'
        'app = Flask(__name__)\n'
        'client = anthropic.Anthropic()\n'
        '@app.route("/chat", methods=["POST"])\n'
        '@limiter.limit("10 per minute")\n'
        'def chat():\n'
        '    response = client.messages.create(\n'
        '        model="claude-3-5-sonnet-20241022",\n'
        '        messages=[{"role": "user", "content": "hello"}],\n'
        '    )\n'
        '    return {}\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    web5 = [f for f in findings if "WEB-5" in f.checklist_item]
    assert web5 == []


def test_web_app_rate_limit_gate_ignore_suppresses_infrastructure_case(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'from flask import Flask\n'
        'import anthropic\n'
        'app = Flask(__name__)\n'
        'client = anthropic.Anthropic()\n'
        '@app.route("/chat", methods=["POST"])\n'
        'def chat():\n'
        '    response = client.messages.create(  # gate: ignore — rate limited at nginx\n'
        '        model="claude-3-5-sonnet-20241022",\n'
        '        messages=[{"role": "user", "content": "hello"}],\n'
        '    )\n'
        '    return {}\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    web5 = [f for f in findings if "WEB-5" in f.checklist_item]
    assert web5 == []


def test_web_app_rate_limit_no_finding_without_flask_route(tmp_path):
    f = tmp_path / "worker.py"
    f.write_text(
        'import anthropic\n'
        'client = anthropic.Anthropic()\n'
        'def run_batch():\n'
        '    response = client.messages.create(\n'
        '        model="claude-3-5-sonnet-20241022",\n'
        '        messages=[{"role": "user", "content": "hello"}],\n'
        '    )\n'
    )
    findings = WebAppScanner().scan(tmp_path)
    web5 = [f for f in findings if "WEB-5" in f.checklist_item]
    assert web5 == []


# --- BareSuppressScanner ---

def test_bare_suppress_flags_python_bare_gate_ignore(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('data = json.loads(x)  # gate: ignore\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_bare_suppress_flags_typescript_bare_gate_ignore(tmp_path):
    f = tmp_path / "app.ts"
    f.write_text('const id = Math.random()  // gate: ignore\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_bare_suppress_accepts_python_with_rationale(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('data = json.loads(x)  # gate: ignore — reads tool state file\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert findings == []


def test_bare_suppress_accepts_typescript_with_rationale(tmp_path):
    f = tmp_path / "app.ts"
    f.write_text('const id = Math.random()  // gate: ignore — non-cryptographic ID\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert findings == []


def test_bare_suppress_ignores_documentation_mention_inline(tmp_path):
    # 'gate: ignore' inside a string explanation — has text after 'ignore', not at EOL
    f = tmp_path / "scanner.py"
    f.write_text('detail = "Add # gate: ignore — <reason> to suppress this finding"\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert findings == []


def test_bare_suppress_ignores_documentation_mention_in_comment(tmp_path):
    # Comment explaining the syntax — text follows 'ignore', not at EOL
    f = tmp_path / "scanner.py"
    f.write_text('# Use # gate: ignore — reason to suppress a finding\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert findings == []


def test_bare_suppress_detail_contains_format_hint(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('secret = "x"  # gate: ignore\n')
    findings = BareSuppressScanner().scan(tmp_path)
    assert "gate: ignore — <reason>" in findings[0].detail


def test_bare_suppress_self_scan_clean():
    # The security-gate codebase itself should have no bare suppressions
    import pathlib
    root = pathlib.Path(__file__).parent.parent
    findings = BareSuppressScanner().scan(root)
    assert findings == [], f"Bare suppressions in codebase: {[(f.file, f.line) for f in findings]}"


# --- CmdInjectionScanner ---

def test_cmd_injection_detects_eval_with_variable():
    findings = CmdInjectionScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_cmd_injection" in f.file and "eval" in f.detail]
    assert len(critical) >= 1
    assert all(f.severity == Severity.CRITICAL for f in critical)


def test_cmd_injection_detects_exec_with_fstring():
    findings = CmdInjectionScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_cmd_injection" in f.file and "exec" in f.detail]
    assert len(critical) >= 1


def test_cmd_injection_detects_os_system_with_variable():
    findings = CmdInjectionScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_cmd_injection" in f.file and "os.system" in f.detail]
    assert len(critical) >= 1


def test_cmd_injection_detects_subprocess_shell_true():
    findings = CmdInjectionScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_cmd_injection" in f.file and "shell=True" in f.detail]
    assert len(critical) >= 1


def test_cmd_injection_eval_literal_no_finding(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('result = eval("2+2")\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_exec_literal_no_finding(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('exec("import os")\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_os_system_literal_no_finding(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('import os\nos.system("ls -la")\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_subprocess_list_no_shell_no_finding(tmp_path):
    # This is the pattern git_history.py uses — must not fire
    f = tmp_path / "runner.py"
    f.write_text(
        'import subprocess\n'
        'result = subprocess.run(\n'
        '    ["git", "-C", str(root), "log", "--all", "--format=%H"],\n'
        '    capture_output=True,\n'
        '    text=True,\n'
        '    timeout=30,\n'
        ')\n'
    )
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_subprocess_shell_false_explicit_no_finding(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('import subprocess\nsubprocess.run(["ls", "-la"], shell=False)\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_subprocess_shell_true_fires(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('import subprocess\nsubprocess.run(cmd, shell=True)\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_cmd_injection_all_severity_critical(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(
        'import os, subprocess\n'
        'eval(user_input)\n'
        'exec(user_input)\n'
        'os.system(user_cmd)\n'
        'subprocess.run(cmd, shell=True)\n'
    )
    findings = CmdInjectionScanner().scan(tmp_path)
    assert len(findings) == 4
    assert all(f.severity == Severity.CRITICAL for f in findings)


def test_cmd_injection_gate_ignore_suppresses(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('eval(user_code)  # gate: ignore — sandboxed execution environment\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_method_call_eval_not_flagged(tmp_path):
    # model.eval() is PyTorch evaluation mode — not Python built-in eval()
    f = tmp_path / "train.py"
    f.write_text('import torch\nmodel.eval()\nmodel.eval()\n')
    findings = CmdInjectionScanner().scan(tmp_path)
    assert findings == []


def test_cmd_injection_self_scan_source_clean():
    # scanner source files must not contain eval/exec/shell=True calls
    import pathlib
    source = pathlib.Path(__file__).parent.parent / "security_gate"
    findings = CmdInjectionScanner().scan(source)
    assert findings == [], f"cmd_injection in source: {[(f.file, f.line, f.match) for f in findings]}"


# --- SstiScanner ---

def test_ssti_detects_render_template_string_with_variable():
    findings = SstiScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ssti" in f.file and "render_template_string" in f.detail]
    assert len(critical) >= 1
    assert all(f.severity == Severity.CRITICAL for f in critical)


def test_ssti_detects_jinja2_template_with_variable():
    findings = SstiScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ssti" in f.file and "jinja2.Template" in f.detail]
    assert len(critical) >= 1


def test_ssti_literal_render_template_string_no_finding(tmp_path):
    f = tmp_path / "views.py"
    f.write_text('return render_template_string("<h1>Hello</h1>")\n')
    findings = SstiScanner().scan(tmp_path)
    assert findings == []


def test_ssti_literal_jinja2_template_no_finding(tmp_path):
    f = tmp_path / "render.py"
    f.write_text('tmpl = jinja2.Template("Hello {{ name }}")\n')
    findings = SstiScanner().scan(tmp_path)
    assert findings == []


def test_ssti_render_template_safe_not_flagged(tmp_path):
    # render_template() (not render_template_string) is safe — auto-escaping
    f = tmp_path / "views.py"
    f.write_text('return render_template("index.html", name=user_name)\n')
    findings = SstiScanner().scan(tmp_path)
    assert findings == []


def test_ssti_fstring_argument_fires(tmp_path):
    f = tmp_path / "views.py"
    f.write_text('return render_template_string(f"<h1>{user_name}</h1>")\n')
    findings = SstiScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_ssti_gate_ignore_suppresses(tmp_path):
    f = tmp_path / "views.py"
    f.write_text(
        'return render_template_string(tmpl)  '
        '# gate: ignore — template sourced from admin-only config, not user input\n'
    )
    findings = SstiScanner().scan(tmp_path)
    assert findings == []


def test_ssti_self_scan_source_clean():
    import pathlib
    source = pathlib.Path(__file__).parent.parent / "security_gate"
    findings = SstiScanner().scan(source)
    assert findings == [], f"ssti in source: {[(f.file, f.line, f.match) for f in findings]}"


# --- SsrfScanner ---

def test_ssrf_detects_requests_with_variable_url():
    findings = SsrfScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ssrf" in f.file and "requests" in f.detail]
    assert len(critical) >= 1
    assert all(f.severity == Severity.CRITICAL for f in critical)


def test_ssrf_detects_httpx_with_fstring_url():
    findings = SsrfScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ssrf" in f.file and "httpx" in f.detail]
    assert len(critical) >= 1


def test_ssrf_detects_urllib_with_variable():
    findings = SsrfScanner().scan(FIXTURES)
    critical = [f for f in findings if "has_ssrf" in f.file and "urllib" in f.detail]
    assert len(critical) >= 1


def test_ssrf_literal_url_not_flagged(tmp_path):
    f = tmp_path / "client.py"
    f.write_text('import requests\nresponse = requests.get("https://api.example.com/data")\n')
    findings = SsrfScanner().scan(tmp_path)
    assert findings == []


def test_ssrf_httpx_literal_not_flagged(tmp_path):
    f = tmp_path / "client.py"
    f.write_text('import httpx\nresponse = httpx.get("https://api.example.com")\n')
    findings = SsrfScanner().scan(tmp_path)
    assert findings == []


def test_ssrf_requests_post_variable_fires(tmp_path):
    f = tmp_path / "client.py"
    f.write_text('import requests\nrequests.post(endpoint, json=data)\n')
    findings = SsrfScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_ssrf_gate_ignore_suppresses(tmp_path):
    f = tmp_path / "client.py"
    f.write_text(
        'import requests\n'
        'requests.get(settings.API_URL)  # gate: ignore — URL from application config, not user input\n'
    )
    findings = SsrfScanner().scan(tmp_path)
    assert findings == []


def test_ssrf_outbound_scanner_still_fires_on_literal(tmp_path):
    # outbound_calls and ssrf are complementary — outbound fires on ALL calls,
    # ssrf only fires when URL is non-literal. A literal URL should fire outbound but not ssrf.
    f = tmp_path / "client.py"
    f.write_text('import requests\nrequests.get("https://api.example.com")\n')
    ssrf_findings = SsrfScanner().scan(tmp_path)
    outbound_findings = OutboundScanner().scan(tmp_path)
    assert ssrf_findings == []
    assert len(outbound_findings) == 1


def test_ssrf_self_scan_source_clean():
    import pathlib
    source = pathlib.Path(__file__).parent.parent / "security_gate"
    findings = SsrfScanner().scan(source)
    assert findings == [], f"ssrf in source: {[(f.file, f.line, f.match) for f in findings]}"


# --- SemgrepScanner ---

_SEMGREP_FINDING = {
    "check_id": "security_gate.rules.semgrep_rules.sgw-llm-injection-taint",
    "path": "",  # filled in per-test
    "start": {"line": 20, "col": 5, "offset": 400},
    "end": {"line": 20, "col": 60, "offset": 455},
    "extra": {
        "message": (
            "Request input flows into LLM API call via reassignment chain — "
            "prompt injection risk."
        ),
        "severity": "WARNING",
        "lines": "    response = client.messages.create(",
        "metadata": {},
    },
}


def _semgrep_json(path: str, rule_id: str = "sgw-llm-injection-taint") -> str:
    finding = dict(_SEMGREP_FINDING)
    finding["path"] = path
    finding["check_id"] = f"security_gate.rules.semgrep_rules.{rule_id}"
    return json.dumps({"results": [finding], "errors": []})


def test_semgrep_not_installed_emits_info(tmp_path):
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run",
               side_effect=FileNotFoundError):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "semgrep not installed" in findings[0].detail


def test_semgrep_warning_maps_to_medium(tmp_path):
    fake_file = tmp_path / "views.py"
    fake_file.write_text("# placeholder\n")
    mock = MagicMock(returncode=1, stdout=_semgrep_json(str(fake_file)))
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_semgrep_rule_id_extracted_from_check_id(tmp_path):
    fake_file = tmp_path / "views.py"
    fake_file.write_text("# placeholder\n")
    mock = MagicMock(returncode=1, stdout=_semgrep_json(str(fake_file), "sgw-ssrf-taint"))
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert "sgw-ssrf-taint" in findings[0].detail
    assert "SSRF-2" in findings[0].checklist_item


def test_semgrep_clean_on_empty_results(tmp_path):
    mock = MagicMock(returncode=0, stdout=json.dumps({"results": [], "errors": []}))
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert findings == []


def test_semgrep_timeout_emits_medium_finding(tmp_path):
    # MEDIUM, not INFO: tool present but failed (INFO is reserved for the
    # expected not-installed case). Non-gating either way.
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=120)):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "timed out" in findings[0].detail


def test_semgrep_error_exit_emits_medium_finding(tmp_path):
    # rc=2 used to return [] — indistinguishable from a clean scan. It must
    # be a visible degradation finding (fail-open audit, 2026-07-03).
    mock = MagicMock(returncode=2, stdout="", stderr="fatal: bad rules file")
    with patch("security_gate.scanner.semgrep_scanner.subprocess.run", return_value=mock):
        findings = SemgrepScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "exited 2" in findings[0].match
    assert "bad rules file" in findings[0].detail


def test_semgrep_rules_file_exists():
    from security_gate.scanner.semgrep_scanner import _RULES_FILE
    assert _RULES_FILE.exists(), f"Rules file missing: {_RULES_FILE}"


def test_semgrep_fixture_missed_by_regex_scanner():
    # has_semgrep_taint.py uses 2-hop reassignment — confirm llm_injection regex misses it
    # (semgrep would catch it; this test documents the gap the scanner closes)
    findings = LlmInjectionScanner().scan(FIXTURES)
    semgrep_fixture_hits = [f for f in findings if "has_semgrep_taint" in f.file]
    assert semgrep_fixture_hits == [], (
        "llm_injection regex scanner now catches multi-hop — "
        "semgrep scanner may be redundant for this pattern"
    )


# --- pickle_usage ---

def test_pickle_loads_variable_is_critical(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import pickle\nobj = pickle.loads(payload)\n")
    findings = PickleUsageScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"


def test_pickle_load_call_arg_is_critical(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import pickle\nobj = pickle.load(open(path, 'rb'))\n")
    findings = PickleUsageScanner().scan(tmp_path)
    assert any(x.severity.value == "CRITICAL" for x in findings)


def test_pickle_loads_literal_is_not_flagged(tmp_path):
    # constant bytes literal is not attacker-controlled — literal guard excludes it
    f = tmp_path / "m.py"
    f.write_text("import pickle\nobj = pickle.loads(b'\\x80\\x04')\n")
    assert PickleUsageScanner().scan(tmp_path) == []


def test_pickle_unpickler_is_critical(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import pickle\nu = pickle.Unpickler(stream)\n")
    findings = PickleUsageScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "CRITICAL"


def test_pickle_gate_ignore_suppresses(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import pickle\nobj = pickle.loads(trusted)  # gate: ignore - local trusted cache\n")
    assert PickleUsageScanner().scan(tmp_path) == []


# --- missing_timeout ---

def test_requests_without_timeout_is_medium(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import requests\nr = requests.get(url)\n")
    findings = HardcodedTimeoutScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"


def test_requests_with_timeout_is_clean(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import requests\nr = requests.get(url, timeout=5)\n")
    assert HardcodedTimeoutScanner().scan(tmp_path) == []


def test_requests_with_multiline_timeout_is_clean(tmp_path):
    f = tmp_path / "m.py"
    f.write_text(
        "import requests\n"
        "r = requests.post(\n"
        "    url,\n"
        "    json=body,\n"
        "    timeout=10,\n"
        ")\n"
    )
    assert HardcodedTimeoutScanner().scan(tmp_path) == []


def test_neighbouring_timeout_does_not_mask_bare_call(tmp_path):
    # a timeout= on the next call must not suppress the bare call above it
    f = tmp_path / "m.py"
    f.write_text(
        "import requests\n"
        "a = requests.get(url1)\n"
        "b = requests.get(url2, timeout=5)\n"
    )
    findings = HardcodedTimeoutScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 2


def test_httpx_without_timeout_not_flagged(tmp_path):
    # httpx ships a 5s default timeout — omitting it is not a hang risk
    f = tmp_path / "m.py"
    f.write_text("import httpx\nr = httpx.get(url)\n")
    assert HardcodedTimeoutScanner().scan(tmp_path) == []
