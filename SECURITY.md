# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

**Email:** firefoxxy101@gmail.com  
**Subject line:** `[security-gate] Vulnerability report`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You will receive an acknowledgement within 48 hours. Confirmed vulnerabilities will be patched and disclosed publicly once a fix is available, with credit to the reporter if desired.

## Scope

In scope:
- False negatives that would allow a real violation to pass the gate undetected
- Scanner bypass techniques (crafted input that defeats pattern matching)
- Arbitrary code execution via malicious repo content during scanning
- Dependency vulnerabilities in security-gate itself

Out of scope:
- Findings in repos being scanned (those are the tool's intended output, not bugs)
- False positives (open a regular issue)

## Security design notes

security-gate runs statically — it reads files, it does not execute them. The scanner processes untrusted repo content via regex and file I/O only. No subprocess calls, no imports of scanned code, no network calls during scanning.

The tool gates itself on every CI run (`self-scan` job in `.github/workflows/ci.yml`).
