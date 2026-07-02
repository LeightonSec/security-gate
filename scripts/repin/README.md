# scripts/repin — security-gate SHA re-pin tooling

Safely re-pins consumer repos from one `security-gate` commit SHA to another.

## Why this exists

Every repo that gates on `security-gate` pins an exact commit in its
`.github/workflows/ci.yml`:

    pip install "git+https://github.com/LeightonSec/security-gate.git@<SHA>"

When `security-gate` ships a new version, all of those pins must move. A blind
SHA bump is **not safe**: a scanner rewrite can silently *drop* a finding the old
version caught (invisible from a still-green gate), and a new scanner can *newly
block* CI. So this tooling **diffs each repo's findings at the OLD vs NEW SHA
before bumping**, and HALTS any repo whose findings changed unexpectedly instead
of pushing blindly.

## Files

| File | Role |
|------|------|
| `repin.sh`         | Orchestrator. Per repo: canonical-tree + `gh` visibility checks, findings diff (OLD vs NEW SHA, mirroring each repo's own CI scan args), SHA bump, commit + push + watch CI. **Dry-run by default**; `APPLY=1` writes/pushes. `ONLY="a b"` limits the run. Source-guarded — must be *executed*, never *sourced*. |
| `findings_diff.py` | The diff engine. Compares two `security-gate` JSON reports, keyed on `(scanner, file)` counts + severity multiset (robust to line/match shifts from a rewrite). Categories: **DROP / BLOCKER / CHURN / FLIP** (halt-worthy) and **ADD / RELOCATION** (informational). Verdict: `CLEAN` or `REVIEW`. |
| `make_fixtures.py` | Generates the 10 test fixtures — the case table in it *is* the spec. |
| `run_fixtures.sh`  | Acceptance test: 10 cases, asserts verdict **and** exact category markers (no missing, no extra). Regenerates fixtures itself. |

`fixtures/` and `*.diff.log` are generated artifacts (gitignored).

## Usage

    ./scripts/repin/run_fixtures.sh          # verify the diff engine — expect 10/10
    ./scripts/repin/repin.sh                 # DRY RUN: per-repo findings diff + plan, no writes
    APPLY=1 ./scripts/repin/repin.sh         # apply to CLEAN repos only (commit + push + watch CI)

Config lives at the top of `repin.sh`: `OLD_SHA`, `NEW_SHA`, and the `REPIN=( … )`
list of repos (canonical tree under `~/Projects`). **Always read the per-repo
`*.diff.log` in the run dir before ever using `APPLY=1`.** A repo whose diff is not
`CLEAN` is halted (no bump, no push) for manual review — that is the whole point.

## Notes

- Waiver removal is a *separate* concern from an SHA bump and is deliberately out
  of scope here (bump first, all green; waivers as their own pass).
- Runs the gate in two isolated venvs (OLD SHA, NEW SHA) installed from git exactly
  as CI does, so the diff reproduces CI's findings.
