# Security-Gate Audit — Session Handover

**Date:** 2026-05-24  
**Scope:** Scanner improvements + portfolio-wide remediation (continued from 2026-05-22)  
**Status:** Active — remediation in progress

---

## Scanner Improvements Shipped This Session (all pushed to main, 52/52 tests)

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
| security-gate | 0 | 0 | 0 | ✅ Clean — self-scan passes |
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

---

## Next Session Priority Order

1. **Commit pending** — llm-honeypot and pcap-analyser (commands above)
2. **Clone and scan port-scanner** — `git clone https://github.com/LeightonSec/port-scanner`
3. **Hash-pin remaining repos** — incident-tracker, leightsec-template, password-policy-checker
4. **Patch remaining HIGH findings** — intel-pipeline, unified-dashboard, intel-dashboard, ai-firewall, mfa-coverage-tracker

---

## Scanner Design Decisions (this session)

| Decision | Reason |
|----------|--------|
| Default excludes `.venv`/`venv`/`dist`/`build` | Eliminates noise from vendored dependencies without requiring `--exclude` flag |
| `# gate: ignore` suppression in ValidationScanner | Escape hatch for false positives that can't be expressed as a rule (local files, test fixtures) |
| DDL excluded from SQL injection rule | ALTER/CREATE/DROP TABLE and PRAGMA can't be parameterised; flagging them as SQLi is always a false positive |
| `--hash=` lines skipped in deps scanner | `_OPTION` pattern was `^\s*-[a-zA-Z]` — didn't match `--hash=` double-dash continuations |
| Pydantic model for AbuseIPDB response in pcap-analyser | Silent wrong `is_malicious` results are worse than a crash for a security tool |
