# security-gate

Static security gate scanner for Python security projects. Catches the violations that matter most before code ships.

Each finding maps directly to a checklist gate item. The scanner auto-populates what it can find statically; human-judgement items remain for manual sign-off.

## Framework alignment

| Framework | Version | Date | Coverage |
|-----------|---------|------|----------|
| OWASP SAMM | v2.0 | February 2020 (actively maintained) | Implementation/Verification functions |
| NIST SSDF | SP 800-218 v1.1 | February 2022 | PW and RV practices (v1.2 IPD December 2025, not yet final) |
| NIST SSDF AI Profile | SP 800-218A | July 26, 2024 | AI model provenance and supply chain |
| OWASP Top 10 | 2025 | January 2026 final | A03 Injection, A05 Security Misconfiguration, A06 Vulnerable Components |
| CIS Supply Chain | Software Supply Chain Security Guide v1.0 | 2022 | Source code, build pipeline, dependency controls |

## What it catches

| Scanner | What it detects | Severity |
|---------|----------------|----------|
| `outbound_calls` | External HTTP calls, Anthropic/OpenAI SDK usage, boto3 — data leaving the trust boundary | HIGH |
| `path_manipulation` | `sys.path.insert/append` — implicit repo coupling, brittle and exploitable | HIGH |
| `unpinned_deps` | `requirements.txt` without exact version pins or `--hash=` — supply chain attack surface | HIGH/MEDIUM |
| `hardcoded_secrets` | Insecure default values in `getenv()`, inline API key assignments | CRITICAL/HIGH |
| `retention_policy` | Database writes and file appends with no TTL/purge logic in scope | MEDIUM |
| `missing_validation` | Flask input (`request.get_json`, `request.args`) without Pydantic schema validation | HIGH |

## Gate logic

- **GATE BLOCKED** — any CRITICAL or HIGH finding. Do not proceed to next phase.
- **GATE PASSED** — zero CRITICAL/HIGH. MEDIUM and below require review but do not block.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan a repo, print report to stdout
security-gate scan /path/to/repo

# Save reports to disk
security-gate scan /path/to/repo --save

# JSON output (for CI integration)
security-gate scan /path/to/repo --output json --save

# Both formats
security-gate scan /path/to/repo --output both --save

# Don't fail CI on gate block (still shows findings)
security-gate scan /path/to/repo --no-exit-code
```

## Example output

```
security-gate v0.1.0 — scanning /path/to/ai-firewall

  outbound_calls         3 findings
  path_manipulation      1 findings
  unpinned_deps          2 findings
  hardcoded_secrets      1 findings
  retention_policy       1 findings
  missing_validation     0 findings

❌ GATE BLOCKED — resolve CRITICAL/HIGH findings before proceeding

  HIGH     detector.py:4   outbound_calls
           Anthropic SDK instantiated — prompts/data sent to external API
           → PRE-BUILD-4: Confirm offline inference

  HIGH     classifier.py:3  path_manipulation
           sys.path manipulation — implicit trust between repos, brittle path coupling
           → PHASE-1-7: No relative-path repo coupling
```

## CI integration

The included GitHub Actions workflow runs security-gate against your repo on every push and PR, and uploads the gate report as an artifact:

```yaml
- name: Run security-gate
  run: security-gate scan . --output json --save
```

Exit code 1 on any CRITICAL/HIGH finding — blocks merge until resolved.

## What the scanner can't verify

These gate items require human sign-off — documented in every report's manual sign-off section:

- Trust boundary map reviewed
- HF model provenance verified (SHA checksum pinned)
- Offline inference confirmed (verified with Wireshark/Little Snitch)
- Data retention policy defined and implemented
- Test fixtures confirmed synthetic (no real IOCs/IPs/payloads)

## Known limitations

security-gate is a SAST tool. It catches what can be detected by reading source files statically. These violation patterns are outside its current scope:

| Limitation | What it means | How to address |
|------------|---------------|----------------|
| Runtime behaviour | No sandboxed execution or network traffic monitoring | Wireshark/Little Snitch for outbound; runtime sandbox (v1.1 stretch goal) |
| Transitive dependencies | Only direct deps scanned, not the full tree | `pip-audit` or `safety` for transitive SCA |
| Git history | Working tree only; committed secrets in history not caught | `gitleaks --source=git` on full history (v1.1 roadmap) |
| Container/environment layer | No Dockerfile or docker-compose scanning | hadolint integration (v1.1 roadmap, `iac` profile) |
| Tamper detection | Reports are not signed; integrity relies on CI enforcement | Signed gate reports (v1.1 roadmap) |
| Import-time side effects | Statically undetectable | Requires sandboxed execution |
| Unknown violation patterns | Only catches patterns found manually first | Submit findings as issues; patterns are added after real-world discovery |

### Where security-gate sits in the testing stack

```
SAST (← you are here)  →  SCA  →  DAST  →  IAST  →  Fuzzing
static source analysis     deps    running   instrumented  boundary
                           tree    app        runtime       inputs
```

security-gate covers the SAST layer and a subset of SCA (direct deps, no transitive tree). The v1.1 roadmap adds full SCA. DAST, IAST, and fuzzing remain out of scope.

## Roadmap

v1.0 ships with a flat scanner that runs all rules against any Python project. v1.1 introduces profile-based scanning — the tool auto-detects project type and applies the relevant rule set.

| Issue | Profile | Additional checks |
|-------|---------|-------------------|
| [#1](https://github.com/LeightonSec/security-gate/issues/1) | `ai_ml` | `from_pretrained()` without `revision=`, `trust_remote_code=True`, HF telemetry, NIST 800-218A model card validation |
| [#2](https://github.com/LeightonSec/security-gate/issues/2) | `web_app` | Debug mode, SQL injection via string concatenation, CORS wildcard, unauthenticated POST routes |
| [#3](https://github.com/LeightonSec/security-gate/issues/3) | `security_tool` | Stricter gate threshold (MEDIUM blocks), payload/IOC detection in test fixtures |
| [#4](https://github.com/LeightonSec/security-gate/issues/4) | `iac` | Terraform/Dockerfile/Ansible — hardcoded creds, public exposure patterns |

Detection is automatic — no `--profile` flag needed. The tool reads requirements.txt and file extensions to classify, then applies the matching rule set.

**v1.1 also adds:** full transitive dependency tree scanning, `gitleaks --source=git` on full history, Dockerfile scanning (hadolint integration), signed gate reports, and per-repo findings persistence.

## Origin

Built while auditing signal source repos ahead of building [threat-classifier](https://github.com/LeightonSec/threat-classifier). Before a single line of classifier code was written, a manual pre-build threat model surfaced 6 real violations across the existing LeightonSec SOC toolkit:

- `ai-firewall` was sending verbatim attacker prompts to the Anthropic API
- `pcap-analyser` was sending real network IPs to AbuseIPDB
- `llm-honeypot` coupled to `ai-firewall` via `sys.path.insert('../ai-firewall')` — a hardcoded relative path that loads silently from the wrong location if the repo layout changes
- `incident-tracker` had `SECRET_KEY = os.getenv('SECRET_KEY', 'changeme')` as a production fallback
- Two repos accumulated threat data indefinitely with no retention policy

security-gate was built to automate the repeatable half of that audit. Every rule it enforces was found manually first. The scanner catches them on the next repo before anyone has to look.

Every violation it detects was real before it was a test fixture.

---

*LeightonSec — security-engineered, gate by gate.*
