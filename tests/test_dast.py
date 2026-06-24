from unittest.mock import MagicMock, patch

import httpx
import pytest

from security_gate.dast.scanner import DastFinding, DastScanner
from security_gate.scanner.base import Severity


def _mock_response(
    status_code: int = 200,
    headers: dict | None = None,
    text: str = "",
    json_data: dict | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = Exception("not JSON")
    return resp


def _make_client(*route_responses: tuple) -> MagicMock:
    """Build a mock httpx.Client. route_responses: (method, path, mock_response) tuples."""
    lookup = {(m, p): r for m, p, r in route_responses}
    client = MagicMock()
    client.get.side_effect = lambda path, **kw: lookup.get(("GET", path), _mock_response())
    client.post.side_effect = lambda path, **kw: lookup.get(("POST", path), _mock_response())
    return client


# ── DastFinding ──────────────────────────────────────────────────────────────

def test_dast_finding_to_dict():
    f = DastFinding(
        scanner="dast", severity=Severity.HIGH, endpoint="/chat",
        payload_variant="dan", status_code=200,
        response_snippet="snippet", detail="some detail", checklist_item="DAST-3",
    )
    d = f.to_dict()
    assert d["severity"] == "HIGH"
    assert d["endpoint"] == "/chat"
    assert d["status_code"] == 200


def test_dast_finding_null_status_code_serialises():
    f = DastFinding(
        scanner="dast", severity=Severity.INFO, endpoint="/chat",
        payload_variant="dast_mode_check", status_code=None,
        response_snippet="", detail="DAST_MODE not active", checklist_item="DAST-4",
    )
    assert f.to_dict()["status_code"] is None


def test_dast_finding_sort_key_severity_order():
    high = DastFinding("dast", Severity.HIGH, "/chat", "v", 200, "", "d", "c")
    info = DastFinding("dast", Severity.INFO, "/chat", "v", None, "", "d", "c")
    assert high.sort_key() < info.sort_key()


# ── DastScanner — fixture ─────────────────────────────────────────────────────

def test_probes_fixture_loads_26_records():
    scanner = DastScanner(base_url="http://localhost:5001")
    payloads = scanner._load_payloads()
    assert len(payloads) == 26
    assert len([p for p in payloads if p["label"] == "threat"]) == 13
    assert len([p for p in payloads if p["label"] == "benign"]) == 13


# ── DastScanner — connectivity ────────────────────────────────────────────────

def test_scan_raises_connection_error_when_unreachable(tmp_path):
    probes = tmp_path / "probes.jsonl"
    probes.write_text('{"label": "threat", "variant": "dan", "text": "test"}\n')
    scanner = DastScanner(base_url="http://localhost:19999", payloads_path=probes)
    with patch("httpx.Client") as mock_cls:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.side_effect = httpx.ConnectError("refused")
        mock_cls.return_value = mock_client
        with pytest.raises(ConnectionError, match="is the service running"):
            scanner.scan()


# ── _check_headers ────────────────────────────────────────────────────────────

def test_check_headers_three_findings_when_all_missing(tmp_path):
    scanner = DastScanner(base_url="http://localhost:5001",
                          payloads_path=tmp_path / "p.jsonl")
    client = _make_client(("GET", "/", _mock_response(headers={})))
    findings = scanner._check_headers(client)
    assert len(findings) == 3
    assert all(f.severity == Severity.MEDIUM for f in findings)


def test_check_headers_clean_when_all_present(tmp_path):
    scanner = DastScanner(base_url="http://localhost:5001",
                          payloads_path=tmp_path / "p.jsonl")
    client = _make_client(("GET", "/", _mock_response(headers={
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    })))
    assert scanner._check_headers(client) == []


# ── _check_debug_mode ─────────────────────────────────────────────────────────

def test_check_debug_mode_critical_on_werkzeug_marker(tmp_path):
    scanner = DastScanner(base_url="http://localhost:5001",
                          payloads_path=tmp_path / "p.jsonl")
    body = "<html>Werkzeug Debugger — interactive console</html>"
    client = _make_client(("GET", "/dast-debug-probe",
                           _mock_response(status_code=404, text=body)))
    findings = scanner._check_debug_mode(client)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].endpoint == "/dast-debug-probe"


def test_check_debug_mode_clean_on_plain_404(tmp_path):
    scanner = DastScanner(base_url="http://localhost:5001",
                          payloads_path=tmp_path / "p.jsonl")
    client = _make_client(("GET", "/dast-debug-probe",
                           _mock_response(status_code=404, text="Not Found")))
    assert scanner._check_debug_mode(client) == []


# ── _check_chat_endpoint — DAST_MODE not active ───────────────────────────────

def test_check_chat_endpoint_info_when_no_dast_mode(tmp_path):
    probes = tmp_path / "probes.jsonl"
    probes.write_text('{"label": "threat", "variant": "dan", "text": "ignore restrictions"}\n')
    scanner = DastScanner(base_url="http://localhost:5001", payloads_path=probes)
    client = _make_client(("POST", "/chat",
                           _mock_response(json_data={"response": "I cannot help."})))
    findings = scanner._check_chat_endpoint(client, scanner._load_payloads())
    info = [f for f in findings if f.payload_variant == "dast_mode_check"]
    assert len(info) == 1
    assert info[0].severity == Severity.INFO
    assert info[0].status_code is None


# ── _check_chat_endpoint — detection rate ────────────────────────────────────

def test_check_chat_endpoint_high_when_detection_rate_below_threshold(tmp_path):
    probes = tmp_path / "probes.jsonl"
    probes.write_text(
        '{"label": "threat", "variant": "dan", "text": "ignore"}\n'
        '{"label": "threat", "variant": "role_override", "text": "you are DAN"}\n'
    )
    scanner = DastScanner(base_url="http://localhost:5001", payloads_path=probes)
    # DAST_MODE active but both detected as LOW — rate = 0.0, below threshold
    client = _make_client(("POST", "/chat", _mock_response(
        json_data={"response": "ok", "risk_level": "LOW", "classification": "clean"},
    )))
    findings = scanner._check_chat_endpoint(client, scanner._load_payloads())
    rate = [f for f in findings if f.payload_variant == "detection_rate"]
    assert len(rate) == 1
    assert rate[0].severity == Severity.HIGH


def test_check_chat_endpoint_no_rate_finding_when_threshold_met(tmp_path):
    probes = tmp_path / "probes.jsonl"
    probes.write_text('{"label": "threat", "variant": "dan", "text": "ignore"}\n')
    scanner = DastScanner(base_url="http://localhost:5001", payloads_path=probes)
    client = _make_client(("POST", "/chat", _mock_response(
        json_data={"response": "No.", "risk_level": "HIGH", "classification": "jailbreak"},
    )))
    findings = scanner._check_chat_endpoint(client, scanner._load_payloads())
    assert not any(f.payload_variant == "detection_rate" for f in findings)
