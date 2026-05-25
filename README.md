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

v1.3 added a runtime scanner (`--url`) that fires against a live service alongside the static analysis pass. On the first real run against `llm-honeypot` — a Flask honeypot built in the same portfolio — it reported:

```
dast    1 findings
HIGH    /chat  detection_rate
        LLM threat detection rate 92.3% is below 95% threshold
```

That finding was real. One of the 13 probe payloads slipped through the classifier with `risk_level: LOW`. The root cause: the keyword pattern `r"ignore previous instructions"` didn't match `"Ignore your previous instructions"` — the word "your" broke the match. The fix was a one-character regex change. The rescan returned 13/13 and `dast clean`.

The scanner found a genuine gap in the system it was built alongside. That's what the tool is for.

## What's not in scope — and why

security-gate is intentionally narrow. It covers SAST and direct dependency SCA. It does not attempt runtime sandboxing, transitive dependency analysis, container scanning, or fuzzing. Each of those is a distinct discipline with better dedicated tools.

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
| `hardcoded_secrets` | Insecure `getenv()` fallbacks, inline key assignments | CRITICAL/HIGH |
| `retention_policy` | DB writes and file appends without TTL/purge logic | MEDIUM |
| `missing_validation` | Flask input without Pydantic validation | HIGH |
| `ai_ml` | `from_pretrained()` without `revision=`, `trust_remote_code=True`, permissive HF telemetry | CRITICAL/HIGH/MEDIUM |
| `web_app` | Debug mode, SQL injection, CORS wildcard, unauthenticated routes | CRITICAL/HIGH/MEDIUM |
| `security_tool` | Path traversal and injection payload strings in test fixtures | MEDIUM |
| `crypto` | Math.random in crypto paths, GCM without setAAD, HKDF undefined salt, silent catch in crypto context, timing-unsafe secret comparison, key material in logs | HIGH/MEDIUM/LOW |
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

## Framework alignment

Aligned with OWASP SAMM v2.0, NIST SSDF SP 800-218 v1.1, NIST SSDF AI Profile SP 800-218A, and OWASP Top 10 2025.

---

Every violation it detects was real before it was a test fixture.

*LeightonSec — security-engineered, gate by gate.*
