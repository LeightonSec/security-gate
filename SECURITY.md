# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest (main) | ✅ |

security-gate is under active development. Only the current `main` branch receives fixes.

## Reporting a vulnerability

If you find a security vulnerability in security-gate — including false negatives in scanner rules, bypass techniques, or issues in the CLI itself — please report it privately before disclosing publicly.

**Contact:** open a [GitHub Security Advisory](https://github.com/LeightonSec/security-gate/security/advisories/new) on this repo.

Do not open a public issue for security vulnerabilities.

## What to include

- Description of the vulnerability
- Steps to reproduce
- Impact — what could an attacker achieve?
- Suggested fix if you have one

## Response timeline

- **Acknowledgement:** within 5 business days
- **Assessment:** within 14 days
- **Fix or mitigation:** timeline communicated after assessment

## Scope

In scope:
- Scanner rules that can be bypassed to produce false negatives on real vulnerabilities
- CLI input handling (path traversal, malicious fixture files)
- Dependency vulnerabilities in security-gate itself

Out of scope:
- False positives (open a regular issue)
- Findings in codebases security-gate is run against (that's the tool working as intended)

## Credit

Responsible disclosures will be credited in the release notes unless you prefer to remain anonymous.
