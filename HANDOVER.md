# Security-Gate Audit — Session Handover

**Date:** 2026-05-24  
**Scope:** Scanner improvements + portfolio-wide remediation (continued from 2026-05-22)  
**Status:** Active — remediation in progress

---

## Scanner Improvements Shipped 2026-06-30 (180 tests, 17 file-based scanners + 4 semgrep taint rules)

Hardened `missing_validation` and added two scanners plus one taint rule. Verified
against the full portfolio (every LeightonSec repo + ai-firewall) before shipping.

### scanner/validation.py — `missing_validation` window hardened

The 5-line forward window was variable-agnostic and only recognised a narrow set of
validator idioms, producing false positives waived in almost every repo. Rewritten
with three precise suppression mechanisms (a paren-tracking pass underpins #1):

1. **Enclosing validator call** — the entry point is an argument inside an open
   validator/model constructor call, however many lines it spans. Clears the
   incident-tracker `TicketFilter(...)` multi-line kwargs case and pcap-analyser's
   `_AbuseIPDBData.model_validate(response.json())` (validator opening on the line
   above the source).
2. **Variable flows into a validator** — `raw = request.get_json()` then
   `TicketCreate(**raw)` / `Model.model_validate(raw)`. Bound to the assigned
   variable, so validation of an *unrelated* value in the window no longer suppresses
   the finding (closes a false-negative the old proximity heuristic had).
3. **Same-line validator wrap** — `validate(...)` on the entry-point line.

**Decision A (deliberate scope):** manual guard-clause validation (`if not data`,
`isinstance(...)` + early return) is NOT auto-suppressed — a regex can't tell an
adequate guard from a weak presence check, and auto-clearing it would create false
negatives. Those stay findings for human review / accepted-findings.toml (ai-firewall,
unified-dashboard, threat-classifier).

Portfolio diff (old scanner vs new): incident-tracker −7, pcap-analyser −1, **zero new
findings on any app code**. Their `missing_validation` accepted-findings entries are
now obsolete and should be removed when each repo bumps the pin.

### scanner/pickle_usage.py (new) — `pickle_usage`

CRITICAL: `pickle.load`/`pickle.loads` with a non-literal argument (same literal guard
as eval/exec) and `pickle.Unpickler(...)` — arbitrary code execution on deserialization
of untrusted data. Known limit: bare `loads(` after `from pickle import loads` is not
detected (indistinguishable from json/marshmallow at the regex level).

### scanner/hardcoded_timeout.py (new) — `missing_timeout`

MEDIUM (non-gating): `requests.<verb>(...)` and `urllib.request.urlopen(...)` without a
`timeout=` — indefinite hang / availability risk. Argument list is read by tracking
parens so a `timeout=` on a neighbouring call can't mask a bare one. **httpx is
intentionally excluded** — it ships a 5s default timeout, so omitting it is not a hang.

### rules/semgrep_rules.yml — `sgw-path-traversal-taint` (new)

WARNING/MEDIUM (non-gating): request input flowing into `open`/`io.open`/`os.open`/
`os.remove`/`os.unlink`/`send_file`, sanitized by `secure_filename`/`os.path.basename`.
Placed in the semgrep (AST taint) layer rather than a regex gating scanner deliberately:
a regex false positive on `open(var)` would block CI across every pinned repo until a
re-pin; a non-gating MEDIUM surfaces the issue without that blast radius.

### Verification

- 180 unit tests pass (was 165; +15: 5 validation, 5 pickle, 5 timeout).
- Source self-scan clean; CI self-scan (`scan . --exclude tests`) simulation = no
  CRITICAL/HIGH.
- `pickle_usage`/`missing_timeout` produce zero findings on portfolio app code (only
  security-gate's own excluded `tests/`).
- semgrep rules validate (4 rules); path-traversal rule fires on the tainted case and
  is suppressed by `secure_filename`.

---

## Scanner Improvements Shipped 2026-05-30 EOD (138/138 tests, 16 scanners total)

### Additional scanners (session 2)
- `bare_suppress` — HIGH: bare `# gate: ignore` with no rationale. `\s*$` anchor prevents false positives on docstring/string mentions of the syntax. Self-scan test enforces the codebase itself stays clean.
- `cmd_injection` — CRITICAL: eval/exec with non-literal arg, os.system with non-literal arg, subprocess.run/Popen/call with shell=True in 15-line window. Literal guard excludes string/bytes/raw prefixes; f-strings not excluded.
- `ssti` — CRITICAL: render_template_string and jinja2.Template with non-literal argument. Same literal guard as cmd_injection.
- Scope declaration added to CLI output: always-present dimmed note clarifying single-file scope limitation. Addresses "does clean mean clean" honesty problem from council review.
- git_history HIGH patterns recalibrated: `[A-Za-z0-9+/_-]{20,}` → `[A-Za-z0-9+/]{32,}`. Removed hyphens/underscores, raised minimum to 32. Eliminated 3 false positives on `sk-ant-your-key-here` placeholder across multiple commits.
- accepted-findings mechanism (`accepted.py`, CLI, report): `accepted-findings.toml` in scanned repo root, partition before gate decision, accepted findings shown dimmed with severity+rationale+reviewer.

### LLM council findings (2026-05-30)
- "Does clean mean clean?" — addressed with scope declaration in output
- Command injection and SSTI were CRITICAL gaps — both shipped
- Semgrep integration deferred: separate session, separate scope document
- Pre-commit hook angle (Outsider): filed for future consideration
- accepted-findings schema as credential — already interview-ready, not a product yet

### Portfolio fixes this session
- port-scanner: 8 bare `# gate: ignore` suppressions in tests/test_reporter.py — all updated with rationale
- llm-honeypot: accepted-findings.toml updated for git_history false positives; HIGH pattern recalibration means these entries are now superseded but harmless

## Scanner Improvements Shipped 2026-05-30 (81/81 tests, 3 new scanners)

### scanner/llm_injection.py (new)
- Two-pass taint tracker: collects variables assigned from `request.*` sources, then checks if they appear in LLM API sink calls within 15-line window without sanitization in between
- Sanitization regex requires actual function call syntax (e.g. `sanitize_input(`) — avoids matching bare words in comments
- Suppression via `# gate: ignore` inherited from BaseScanner
- **Known limitation:** intra-function scope only — cross-function taint paths (e.g. helper functions calling LLM) are not followed. Documented in scanner docstring.
- 6 tests covering: true positive, detail format, sanitized (clean), gate: ignore suppression, no findings without both patterns

### scanner/git_history.py (new)
- Uses `git log --all -G<pattern>` to find commits where secret patterns appear in diffs (additions OR deletions)
- CRITICAL for high-precision formats (AKIA, sk-, ghp_, xox) — HIGH for broad patterns (API_KEY=, SECRET_KEY=)
- Shallow clone guard: detects `.git/shallow` and emits INFO finding — "shallow clone, scan incomplete"
- Configurable timeout via `GIT_SCAN_TIMEOUT` env var (default: 30s)
- 7 tests covering: non-git dir skip, shallow clone INFO, unshallow hint, CRITICAL/HIGH mocks, clean output, timeout handling

### scanner/web_app.py — WEB-5 rate limiting check (added)
- File-level heuristic: if file has Flask route + LLM API call + no rate limiter import → MEDIUM on LLM call line
- Per-sink fallback: checks 20-line window before LLM call for `@limiter.limit` / `@rate_limit` decorator
- Suppression via `# gate: ignore` with rationale (e.g. `# gate: ignore — rate limited at nginx`)
- **Known limitation:** cross-file Limiter config (app factory pattern) is invisible; infrastructure rate limiting is always invisible
- 5 tests covering: unguarded route fires, flask_limiter import suppresses, decorator suppresses, gate: ignore suppresses, non-Flask LLM call does not fire

### Known design gap identified
- No `accepted-findings.yaml` mechanism — git_history false positives (e.g. example placeholders in committed .env.example files) block the gate on every scan with no inline suppression option. Candidate for v1.1.

---

## Scanner Improvements Shipped 2026-05-24 (52/52 tests)

### base.py
- Added `_DEFAULT_EXCLUDE_DIRS`: `.venv`, `venv`, `dist`, `build`, `.eggs` now excluded by default
- Added `excludes` parameter to `BaseScanner.__init__()` for per-scan additional exclusions
- Added `_suppressed(line)` helper — returns True if line contains `# gate: ignore`
- Added `_SUPPRESS` pattern: `re.compile(r"#\s*gate:\s*ignore", re.IGNORECASE)`

### cli.py
- Added `--exclude` / `-e` option (repeatable) — passes additional dir names to all scanner instances

### scanner/web_app.py
- Added `_SQL_DDL` pattern: `r"\b(ALTER|CREATE|DROP)\s+TABLE\b|\bPRAGMA\b"` (IGNORECASE)
- SQL injection rule now skips DDL statements — fixes false positive on migration functions

### scanner/deps.py
- Fixed `_OPTION` pattern: `r"^\s*-[a-zA-Z]"` → `r"^\s*--?[a-zA-Z]"`
- `--hash=sha256:...` continuation lines in pip-compiled files were being flagged as unpinned deps

### scanner/validation.py
- Wired `self._suppressed(line)` into per-line loop — `# gate: ignore` now suppresses findings

### Tests added (52 total, up from 46)
- `test_web_app_ddl_fstring_no_finding` — ALTER TABLE f-string does not fire CRITICAL
- `test_web_app_dml_fstring_still_fires` — SELECT f-string still fires CRITICAL
- `test_deps_hash_pinned_requirements_no_medium` — hash continuation lines not flagged
- `test_deps_unpinned_requirement_still_fires` — bare unpinned dep still fires
- `test_validation_gate_ignore_suppresses_finding` — `# gate: ignore` suppresses HIGH
- `test_validation_without_suppression_still_fires` — unsuppressed finding still fires

---

## Portfolio State (post this session)

| Repo | CRITICAL | HIGH | MEDIUM | Status |
|------|----------|------|--------|--------|
| llm-honeypot | 0 | 0 | 1 | ✅ Patched — **commit pending** (hash-pinned requirements, Pydantic patches from 2026-05-22) |
| market-recon | 0 | 3 | 6 | ✅ Pushed — 3H accepted (httpx outbound by design); 6M are pyproject.toml (req.txt is lock) |
| pcap-analyser | 0 | 1 | 1 | ✅ Patched — **commit pending** (pydantic model for AbuseIPDB, hash-pinned deps) |
| security-gate | 0 | 0 | 0 | ✅ Clean — self-scan passes with teeth (CI blocks on CRITICAL/HIGH; `--exclude tests`; 4 pyproject MEDIUM accepted) |
| threat-classifier | 0 | 0 | 0 | ✅ Clean |
| llm-redteam (local) | — | — | — | Not scanned — generator only, stays local |

**Repos not yet cloned/scanned (exist on GitHub only):**
- `port-scanner` — 11 HIGH per HANDOVER-2026-05-22; clone and scan next
- `intel-pipeline` — 8 HIGH
- `unified-dashboard` — 5 HIGH
- `intel-dashboard` — 5 HIGH
- `ai-firewall` — 4 HIGH (outbound calls by design — review carefully)
- `mfa-coverage-tracker` — 4 HIGH
- `incident-tracker` — hash-pinning needed + Pydantic patches from 2026-05-22
- `leightsec-template` — hash-pinning needed (`make pin && make pin-dev`)
- `password-policy-checker` — hash-pinning needed

---

## Commits Pending (do before anything else on return)

### llm-honeypot
```bash
cd ~/projects/LeightonSec/llm-honeypot
git add requirements.txt
git commit -m "chore: pin dependencies with hashes"
git push
```

### pcap-analyser
```bash
cd ~/projects/LeightonSec/pcap-analyser
git add requirements.txt threat_intel.py
git commit -m "fix: validate AbuseIPDB response with Pydantic; pin deps with hashes"
git push
```

---

## Accepted False Positives (documented, not fixed)

| Repo | File | Finding | Reason |
|------|------|---------|--------|
| market-recon | `recon/quiver.py`, `ark.py`, `edgar.py` | outbound_calls HIGH | httpx calls to financial APIs — by design |
| market-recon | `recon/state.py:43` | missing_validation | reads tool's own `~/.market-recon/state.json` — suppressed with `# gate: ignore` |
| market-recon | `tests/test_cli.py:61` | missing_validation | test fixture — suppressed with `# gate: ignore` |
| pcap-analyser | `threat_intel.py:33` | outbound_calls HIGH | AbuseIPDB call — risk accepted in Gate 2 trust boundary mapping |
| pcap-analyser | `app.py:33` | web_app MEDIUM | unauthenticated POST route — local analysis tool, no auth layer by design |
| llm-honeypot | `app.py` | web_app MEDIUM | unauthenticated POST route — honeypot by design |
| llm-honeypot | git history | git_history HIGH — commit `4562cfee` | `API_KEY=` broad pattern matched `ANTHROPIC_API_KEY=sk-ant-your-key-here` in `.env.example` — confirmed placeholder, not a real credential. Note: `# gate: ignore` added to `.env.example` for documentation but does not suppress the git history scanner (which reads commit diffs, not current file content). |

---

## Next Session Priority Order

1. **Commit pending** — llm-honeypot and pcap-analyser (commands above)
2. **Open GitHub issue on security-gate** — `accepted-findings.yaml` v1.1 candidate: structured override file with `{commit, pattern, rationale, reviewer}` fields so git_history false positives (example placeholders in .env.example files) can be suppressed without rewriting history or blocking the gate indefinitely. First affected repo: llm-honeypot commit `4562cfee`.
3. **Clone and scan port-scanner** — `git clone https://github.com/LeightonSec/port-scanner`
4. **Hash-pin remaining repos** — incident-tracker, leightsec-template, password-policy-checker
5. **Patch remaining HIGH findings** — intel-pipeline, unified-dashboard, intel-dashboard, ai-firewall, mfa-coverage-tracker

---

## Manual Review Flags (scanner cannot verify)

| Repo | Location | Flag | Reason |
|------|----------|------|--------|
| llm-honeypot | `app.py:151` — `raw = request.get_json(silent=True) or {}` | llm_injection intra-function scope limitation | Request input enters a multi-step pipeline (sentiment → firewall → classifier) before reaching the Anthropic API call. Scanner correctly returned clean — taint path crosses function boundaries that regex-based taint tracking cannot follow. Verify manually in trust boundary review that `raw` is sanitised before reaching `client.messages.create`. |

---

## Scanner Design Decisions (this session)

| Decision | Reason |
|----------|--------|
| Default excludes `.venv`/`venv`/`dist`/`build` | Eliminates noise from vendored dependencies without requiring `--exclude` flag |
| `# gate: ignore` suppression in ValidationScanner | Escape hatch for false positives that can't be expressed as a rule (local files, test fixtures) |
| DDL excluded from SQL injection rule | ALTER/CREATE/DROP TABLE and PRAGMA can't be parameterised; flagging them as SQLi is always a false positive |
| `--hash=` lines skipped in deps scanner | `_OPTION` pattern was `^\s*-[a-zA-Z]` — didn't match `--hash=` double-dash continuations |
| Pydantic model for AbuseIPDB response in pcap-analyser | Silent wrong `is_malicious` results are worse than a crash for a security tool |
| security-gate self-scan runs with teeth | CI runs `security-gate scan . --exclude tests` and blocks on CRITICAL/HIGH (no `--no-exit-code`). `tests/` is excluded because `tests/fixtures/` deliberately contains malicious patterns to verify the scanners fire — gating them is meaningless, not a real finding. Source self-matches (scanner regexes and docstring examples) are suppressed inline with `# gate: ignore - <reason>`; the 4 pyproject.toml compatible-release ranges are documented in `accepted-findings.toml`. Result: source + dependency manifests gate clean with real enforcement. |
| bare_suppress severity is HIGH (not MEDIUM) | A bare `# gate: ignore` is an integrity violation against the gate itself — it bypasses a security control without an audit trail. A developer who suppresses something without rationale undermines the gate's enforceability more than any individual finding. HIGH blocks the gate, which is the correct forcing function. |
