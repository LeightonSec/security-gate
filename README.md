# security-gate

Before a single line of [threat-classifier](https://github.com/LeightonSec/threat-classifier) was written, a manual audit found verbatim attacker prompts being forwarded to the Anthropic API, a `sys.path.insert('../ai-firewall')` that would silently load from the wrong location if the repo layout changed, and production credentials falling back to `"changeme"`. Six violations across four repos — none of them caught by existing tooling.

security-gate automates the repeatable half of that audit. Every rule it enforces was found manually first. Teams building AI products routinely ship with trust boundaries they haven't mapped, training data of unknown provenance, and inference pipelines that pass attacker-controlled strings to external APIs. The scanner catches the violations before they reach production. The gate forces a decision on the ones it can't.

## The gate philosophy

A linter tells you what's wrong. A gate forces you to decide before you proceed.

Every finding maps to a checklist item. The scanner closes what it can verify automatically. Anything requiring human judgement — trust boundary map, model provenance, offline inference confirmation — stays open until a person signs off. Nothing moves to the next phase with unresolved CRITICAL or HIGH findings.

This is the difference between a security scanner and a security gate: the gate has teeth.

## What each gate protects against

| Gate | Threat it exists to prevent |
|------|-----------------------------|
| `outbound_calls` | Attacker prompts exfiltrated to external APIs; data leaving your trust boundary without a documented decision |
| `path_manipulation` | Implicit repo coupling that loads the wrong code silently when directory layout changes |
| `unpinned_deps` | Dependency confusion and supply chain attacks via package registry poisoning |
| `hardcoded_secrets` | Credentials committed to version history or hardcoded fallbacks that fail open in production |
| `retention_policy` | Indefinite accumulation of threat data, network captures, or attacker payloads with no purge path |
| `missing_validation` | Attacker-controlled input reaching business logic without a schema contract |
| `ai_ml` | Unpinned model downloads, arbitrary code execution via `trust_remote_code`, telemetry sending training data to third parties |
| `web_app` | Debug mode in production, SQL injection, CORS wildcard, unauthenticated state-changing endpoints |
| `security_tool` | Test fixtures containing real attack payloads or path traversal strings — synthetic fixtures only |
| `crypto` | Weak CSPRNG in crypto paths, unauthenticated GCM envelopes, HKDF undefined salt, silent catch blocks discarding auth failures, timing-unsafe secret comparison, sensitive key material in logs |

This table covers 10 of the 21 scanners; every scanner is listed in [Scanners](#scanners) below.

## The crypto scanner that caught a live H2 finding

v1.2 added a TypeScript-capable crypto scanner built from a Gate 0 manual audit of a post-quantum messaging protocol. Before a single fix was written, the scanner was run against the live codebase. It returned six production findings across seven files:

```
crypto  6 findings
HIGH    src/crypto/hybrid.ts:30    CRYPTO-02  createCipheriv without setAAD — GCM envelope fields unauthenticated
HIGH    src/ruflo/context.ts:17    CRYPTO-01  Math.random() used for session ID — not a CSPRNG
HIGH    src/ruflo/taskqueue.ts:53  CRYPTO-01  Math.random() used for task ID — not a CSPRNG
MEDIUM  src/guardian/client.ts:108 CRYPTO-04  silent catch — decryption failure swallowed with no log
MEDIUM  src/ruflo/orchestrator.ts  CRYPTO-04  silent catch — decrypt error swallowed with no log
LOW     src/crypto/hybrid.ts:70    CRYPTO-03  hkdf with undefined salt
```

The H2 finding was the one that mattered. `createCipheriv('aes-256-gcm', ...)` with no `setAAD` call meant the outer envelope fields — sender identity, recipient identity, timestamp — were completely unauthenticated. An attacker who intercepted a ciphertext could swap the recipient public key or replay the timestamp to bypass the 30-second replay window. The GCM auth tag covered the ciphertext body but not the wire format around it.

The fix: `setAAD` now binds `version || type || sender_pk || recipient_pk || timestamp || mlkem_ciphertext` (1644 bytes) on both encrypt and decrypt. The scanner rule confirmed the fix: CRYPTO-02 clear on rescan.

The two `CRYPTO-04` findings were found in production catch blocks — one in the orchestrator's decrypt path, one in the guardian's chain lookup. Both were silently returning `null`. Neither would have surfaced until a decryption failure was investigated manually.

Every rule in the scanner was written from a finding first.

## DAST: the scanner that found a real bug

The runtime scanner (`--url`) fires against a live service alongside the static analysis pass. On the first real run against `llm-honeypot`, a Flask honeypot built in the same portfolio, it reported:

```
dast    1 findings
HIGH    /chat  detection_rate
        LLM threat detection rate 92.3% is below 95% threshold
```

That finding was real. One of the 13 probe payloads slipped through the classifier with `risk_level: LOW`. The root cause: the keyword pattern `r"ignore previous instructions"` didn't match `"Ignore your previous instructions"` — the word "your" broke the match. The fix was a one-character regex change. The rescan returned 13/13 and `dast clean`.

The scanner found a genuine gap in the system it was built alongside. That's what the tool is for.

## What's not in scope — and why

security-gate is intentionally narrow. It covers SAST and SCA of pinned versions: `sca` checks every `==` pin in the `requirements*.txt` and `pyproject.toml` files it reads, so in a compiled lockfile it checks transitive packages too, but it does not resolve a dependency tree and does not check unpinned dependencies. Source scanning reads Python (.py) files; only two scanners read TypeScript (.ts): `crypto`, which reads TypeScript only, and `bare_suppress`, which reads both. It does not attempt runtime sandboxing, dependency-tree resolution, container scanning, or fuzzing. Each of those is a distinct discipline with better dedicated tools.

The `# gate: ignore` suppression pattern exists because the scanner is not always right. When a finding is a false positive, the suppression requires a documented rationale inline — not a blanket exclusion, not a config file, a sentence at the callsite explaining why this specific instance is safe:

```python
tokenizer = DistilBertTokenizerFast.from_pretrained(str(path))  # gate: ignore — local MODEL_PATH, not HuggingFace hub
```

TypeScript files use `//` comment syntax — both forms are accepted:

```typescript
const id = `${Date.now()}-${Math.random().toString(36).slice(2)}` // gate: ignore — test helper only, not a crypto path
```

That decision lives in the code where the future reader will look for it.

---

## Usage

```bash
# SAST scan
security-gate scan /path/to/repo

# SAST + DAST (requires running service)
security-gate scan /path/to/repo --url http://localhost:5001

# Save reports to disk
security-gate scan /path/to/repo --save

# JSON output for CI
security-gate scan /path/to/repo --output json --save
```

## Gate logic

- **GATE BLOCKED** — any CRITICAL or HIGH finding. Do not proceed.
- **GATE PASSED** — zero CRITICAL/HIGH. MEDIUM and below require review but don't block.

## Scanners

| Scanner | Detects | Severity |
|---------|---------|----------|
| `outbound_calls` | HTTP calls, Anthropic/OpenAI SDK, boto3 | HIGH |
| `path_manipulation` | `sys.path.insert/append` | HIGH |
| `unpinned_deps` | Missing version pins or hashes | HIGH/MEDIUM |
| `sca` | Known vulnerabilities in `==` pins in `requirements*.txt` and `pyproject.toml`, via one OSV.dev batch query. Limits: the batch reply carries only advisory IDs and modified dates, so every advisory is reported as HIGH whatever its real severity, the summary is empty (the detail shows only the advisory ID), no fix version is shown, and GHSA and PYSEC records for the same CVE are reported as separate findings. Pins with extras (`pkg[x]==`) are skipped. If OSV cannot be reached, the result is one MEDIUM finding, which does not block. The fix is planned in HARDENING-ROADMAP.md, "SCA labels and counts (found 2026-10-13, fleet CVE sweep)". | HIGH (MEDIUM if OSV is unreachable) |
| `hardcoded_secrets` | Insecure `getenv()` fallbacks, inline key assignments | CRITICAL/HIGH |
| `retention_policy` | DB writes and file appends without TTL/purge logic | MEDIUM |
| `missing_validation` | Attacker-controlled input reaching logic without a schema contract (recognises Pydantic models/validators in or around the call; manual guard clauses are not auto-cleared) | HIGH/CRITICAL |
| `pickle_usage` | `pickle.load`/`loads` on non-literal input, `pickle.Unpickler` — RCE on untrusted deserialization | CRITICAL |
| `missing_timeout` | `requests`/`urllib` outbound calls without a `timeout=` (hang/DoS risk) | MEDIUM |
| `ai_ml` | `from_pretrained()` without `revision=`, `trust_remote_code=True`, permissive HF telemetry | CRITICAL/HIGH/MEDIUM |
| `web_app` | Debug mode, SQL injection, CORS wildcard, unauthenticated routes | CRITICAL/HIGH/MEDIUM |
| `security_tool` | Path traversal and injection payload strings in test fixtures | MEDIUM |
| `crypto` | Math.random in crypto paths, GCM without setAAD, HKDF undefined salt, silent catch in crypto context, timing-unsafe secret comparison, key material in logs; reads TypeScript (.ts) files only | HIGH/MEDIUM/LOW |
| `llm_injection` | Flask `request` data assigned to a variable that reaches an LLM call (Anthropic or OpenAI create calls, `llm.predict`, `llm.invoke`, `chain.run`) later in the same function with no sanitiser in between; taint is not followed across functions | HIGH |
| `git_history` | Secret patterns in any commit diff, found with `git log -G`: AWS access key IDs, OpenAI keys, GitHub tokens and Slack tokens (CRITICAL), `API_KEY=` and `SECRET_KEY=` assignments (HIGH); HIGH if the history cannot be scanned; INFO for a shallow clone | CRITICAL/HIGH/INFO |
| `bare_suppress` | `# gate: ignore` or `// gate: ignore` with no rationale after it, in .py and .ts files | HIGH |
| `cmd_injection` | `eval`/`exec` or `os.system` with a non-literal argument; `subprocess` run/Popen/call/check_output/check_call with `shell=True` within a 15-line window | CRITICAL |
| `ssti` | `render_template_string` or `jinja2.Template` with a non-literal argument | CRITICAL |
| `ssrf` | `requests`, `httpx` or `urllib.request` calls whose URL argument is not a string literal (aiohttp is not covered) | CRITICAL |
| `semgrep` | Runs 4 bundled Python taint rules (LLM injection, command injection, SSRF, path traversal) through the semgrep CLI, following data through reassignment within one function; INFO if semgrep is not installed, MEDIUM if it fails | MEDIUM/INFO (does not block) |
| `agent_context_integrity` | Agent-context files (CLAUDE.md, SKILL.md, prompt and agent-config files) whose content, with `@` imports expanded, does not match the SHA-256 pinned in `.agent-context-manifest.json`, or that are unpinned, missing, or import from outside the repo; INFO for text that reads like an instruction to the agent | CRITICAL/HIGH/INFO |
| `dast` | Runtime: headers, debug mode, stack trace leakage, LLM detection rate, model artefact leakage | CRITICAL/HIGH/MEDIUM/INFO |

## DAST checks (requires `--url`)

| Check | What it tests | Finding if failed |
|-------|--------------|-------------------|
| DAST-1 | Security headers present (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`) | MEDIUM |
| DAST-2 | Debug mode off (probes `/dast-debug-probe` for Werkzeug markers) | CRITICAL |
| DAST-3 | Stack traces not exposed in API responses | HIGH |
| DAST-4 | LLM detection pipeline active and ≥95% detection rate on threat probes | HIGH (or INFO if `DAST_MODE` not enabled) |
| DAST-5 | No model artefact leakage (`logits`, `token_ids`, `hidden_states`) in responses | HIGH |

To enable DAST-4 evaluation, start the target service with `DAST_MODE=true`. The service must return `risk_level` and `classification` fields in its response.

## Manual sign-off required

Every gate report includes items the scanner cannot verify automatically:

- [ ] Trust boundary map complete and reviewed
- [ ] Adversarial input paths assessed
- [ ] HF model provenance verified (SHA checksum pinned)
- [ ] Offline inference confirmed (network capture verification)
- [ ] Data retention policy defined and implemented
- [ ] Test fixtures confirmed synthetic (no real IOCs/IPs/payloads)

## CI integration

```yaml
- name: Run security-gate
  run: security-gate scan . --output json --save
```

Exit code 1 on CRITICAL/HIGH — blocks merge until resolved.

### It gates itself

security-gate runs against its own repository in CI with the same teeth it gives everyone else:

```yaml
run: security-gate scan . --exclude tests
```

No `--no-exit-code` escape hatch — a CRITICAL or HIGH in the product source or dependency manifests blocks the build. `tests/` is excluded because `tests/fixtures/` deliberately contains malicious patterns to verify the scanners fire; gating them would be meaningless. Source self-matches (a scanner's own regex strings and docstring examples) are suppressed inline with `# gate: ignore - <reason>`, and the handful of remaining accepted findings are documented in `accepted-findings.toml` with a rationale and reviewer. The gate holds itself to its own standard.

This CI runs on push and pull request to `main` only; there is no scheduled run. An advisory published for an already-pinned dependency is not reported until the next push or pull request.

## Framework alignment

Aligned with OWASP SAMM v2.0, NIST SSDF SP 800-218 v1.1, NIST SSDF AI Profile SP 800-218A, and OWASP Top 10 2025.

---

Every violation it detects was real before it was a test fixture.

*LeightonSec — security-engineered, gate by gate.*
