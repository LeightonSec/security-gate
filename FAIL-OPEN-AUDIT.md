# Fail-Open Audit — 2026-07-03

Systematic audit of every error-handling path in security-gate for silent
failure: places where a scan that could not run reported the same result as a
scan that ran clean. Every path below is now either **gating**, **visible**,
or **loud** — none are silent.

## The severity rule (locked — apply to every future scanner)

> **A tool, parse, or read failure gates (HIGH) if and only if it silently
> removes coverage from a gating check. External-service availability never
> gates, but is always visible.**

Severity tracks *what the failure removes coverage from*, not local-vs-external
or convenience. INFO is reserved for expected, configured absence (an optional
tool not installed); a tool that is present but failed is at minimum MEDIUM.
Do not relitigate this per-tool — check the failure against the rule.

## Classes and dispositions

### Class A — silent file-read skip (was fail-open → now HIGH, gating)

~20 sites: every per-file scanner wrapped its read in `except OSError:
continue`, so an unreadable file was excluded with no trace — the gate could
pass on files it never inspected. Additionally `errors="replace"` masked
undecodable bytes (a corrupt or binary-masquerading file was scanned as
garbage text and reported clean; `UnicodeDecodeError` is a `ValueError`, so
the `OSError` handler would never have caught it).

**Fix:** `BaseScanner._read_text/_read_lines` decode strictly, catch
`(OSError, UnicodeDecodeError)`, and record every failure into
`scanner.integrity_errors`. The CLI dedupes across scanners (one finding per
file, most severe wins via the explicit `_SEVERITY_ORDER` ranking) and emits a
**HIGH `scan_integrity` finding** per unreadable/undecodable file. Waivable via
`accepted-findings.toml` for deliberate cases (e.g. a non-UTF-8 fixture) —
note a legitimately non-UTF-8 source file (`# -*- coding: latin-1 -*-`) now
gates until waived or converted; that is intended.

### Class B — tool failure treated as clean (was fail-open)

| Site | Old behaviour | New behaviour |
|---|---|---|
| `git_history`: git binary missing | `return []` (history "clean") | **HIGH** finding |
| `git_history`: git exits ∉ {0, 1} | `return []` | **HIGH** finding with stderr |
| `git_history`: timeout | MEDIUM finding | **HIGH** finding (local, controllable via `GIT_SCAN_TIMEOUT`) |
| `semgrep`: exit > 1 (crash) | `return []` | **MEDIUM** finding with stderr |
| `semgrep`: empty stdout | `return []` | **MEDIUM** finding |
| `semgrep`: undecodable JSON | `return []` | **MEDIUM** finding |
| `semgrep`: timeout | INFO finding | **MEDIUM** finding |
| `semgrep`: not installed | INFO finding | INFO (unchanged — expected absence) |

git gates because history-secrets findings are CRITICAL/HIGH (gating);
semgrep stays non-gating because its own findings are MEDIUM-max by design
(all bundled rules are WARNING severity). `git log -G` exit codes verified
against real repos: 0 = match **and** no-match (empty stdout is the signal),
128 = real failure; the `(0, 1)` allowance is inherited slack.

### Class C — parse failure treated as no findings (was fail-open → now HIGH)

`pyproject.toml` feeds gating coverage twice: `unpinned_deps` (including the
HIGH not-hash-locked finding when pyproject is the primary spec) and `sca`
CVE queries (up to CRITICAL). Both scanners swallowed parse failures with
`except Exception: return []` — a malformed pyproject silently skipped CVE
checks for every dependency in it.

**Fix:** both catch `tomllib.TOMLDecodeError` only (verified: the tomli
backport exposes the same top-level name, so the narrow catch resolves on the
3.10 matrix leg too) and record into `integrity_errors` → HIGH via
`scan_integrity`. The missing-tomli case (broken install — tomli is a declared
dependency on <3.11) diverges by module, deliberately: `deps.py` guards its
import, sets `tomllib = None`, and records an integrity error instead of
silently skipping; `sca.py` imports tomli unconditionally, so the same broken
install crashes at import (see Accepted residuals). Both directions are
fail-closed; neither is silent.

### Class D — external-service degradation (unchanged, correct by rule)

OSV timeout/error → MEDIUM finding. Cannot gate on internet availability;
the degradation is visible in every report. This is the pattern classes A–C
were converged onto.

### Class E — fail-closed but silent (diagnosability fix)

`accepted-findings.toml` load failures (malformed TOML, missing tomli,
incomplete entries) dropped waivers with no explanation — the safe direction,
but the gate went red with no hint why accepted findings returned.
`load_accepted` now returns `(entries, warnings)` and the CLI prints each
warning. Fail-closed direction preserved.

### Class F — DAST probe drop (was fail-open → now HIGH)

A probe raising `httpx.RequestError` was silently skipped and the detection
rate computed over the remainder. DAST-4 certifies ">95% detection rate on
threat probes" — a dropped probe falsifies the measured denominator; DAST-3/5
are universal claims over responses that were never elicited. Failed probes
are collected and emitted as **one HIGH finding against DAST-4** (one root
cause = one finding, matching git_history and scan_integrity; DAST-3/5 impact
stated in the detail). Never fires in fleet CI — DAST only runs with `--url`.

## Accepted residuals (documented, not bugs)

- **`sbom.py` keeps lossy reads**: any requirements file it skips or
  mis-decodes already produced a HIGH `scan_integrity` finding via deps/sca on
  the same file, so the gate blocks before the SBOM's completeness matters.
- **`sca.py` imports tomli unconditionally on <3.11**: a broken install
  crashes the scan at import (fail-closed, loud). Deliberately not softened —
  contrast with `deps.py`, which degrades to a recorded integrity error.
- **DAST non-JSON responses** are excluded from the DAST-4 rate (a service
  may legitimately return non-JSON); stack-trace checks still run on the body.
- **git exit-1 slack**: exit 1 remains in the success set (inherited); probes
  show git log uses 0 for both match and no-match, so 1 may be dead slack.
- **Stale waivers** (entries matching nothing) warn-vs-finding is deferred to
  the waiver-expiry schema session, where `review_by`/`expires` land.

## Verification

- 201 tests green (182 pre-existing — 3 re-pinned from old fail-open
  behaviour to the locked rule — plus 19 new failure-visibility tests in
  `tests/test_fail_open.py`).
- End-to-end: a chmod-000 file in a scanned repo produces exactly one HIGH
  `scan_integrity` finding, blocks the gate (exit 1), and passes when
  explicitly waived.
- Severity-rank invariant pinned: every `Severity` member must have an
  explicit `_SEVERITY_ORDER` entry.
- Fleet blast radius: none until each repo's SHA pin is bumped; the re-pin
  tooling's findings-diff halts on new gating findings for review before any
  repo moves.
