"""Dirty fixture for SecurityToolScanner — exploit strings present."""

# Path traversal / system file targets
TRAVERSAL_PAYLOAD = "../../etc/passwd"
SHADOW_PAYLOAD = "/etc/shadow"

# Injection payloads
SQL_PAYLOAD = "'; DROP TABLE users; --"
XSS_PAYLOAD = "<script>alert('XSS')</script>"
XSS_EVENT = "onerror=alert(1)"
