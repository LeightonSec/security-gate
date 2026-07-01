#!/usr/bin/env bash
#
# repin.sh — security-gate SHA re-pin pass (SHA BUMP ONLY; waiver removal is a
#            separate script/pass — see repin-waivers.sh, not this one).
#
# What this enforces, in order, per repo — and refuses to skip:
#   1. canonical-tree confirm   (in ~/Projects, NOT an iCloud mirror; clean; HEAD==@{u})
#   2. visibility check          (gh repo view <slug> --json visibility)
#   3. findings diff OLD vs NEW  (runs the gate at both SHAs, mirrors CI's own args)
#   4. SHA update in ci.yml      (asserts exactly-one OLD present -> NEW)
#   5. commit + push + watch CI  (ONLY on APPLY=1 AND a clean findings diff)
#
# Default is DRY_RUN: it produces the diff logs and the intended sed change, and
# touches nothing. Re-run with APPLY=1 once you have READ the per-repo diff logs.
#
#   ./repin.sh            # dry run: diff + plan only, no writes
#   APPLY=1 ./repin.sh    # apply: bump SHA, commit, push, watch CI (clean repos only)
#
# A repo whose findings diff is not CLEAN is HALTED (no bump, no push) and left
# for manual review. One halted repo does not abort the rest of the batch.

# --------------------------------------------------------------------------- source-guard
# BEFORE any `set`/side-effect: this script is meant to be EXECUTED (./repin.sh), never
# sourced. Sourcing would re-run preflight, the venv builds and the repo loop in the
# caller's shell — with ONLY unset, a 14-repo fan-out. Make sourcing a pure no-op.
#   * placed before `set -euo pipefail` so a refused source sets NOTHING in the caller.
#   * `${BASH_SOURCE[0]:-}` (with :- default) is required: zsh — the ambient shell where
#     the 2026-07-01 near-miss `source repin.sh` happened — does not set BASH_SOURCE, and
#     an earlier guard placed after `set -u` errored on the unset var and fell THROUGH,
#     loading the body (failed open). This version fires cleanly in bash and zsh.
if [[ "${BASH_SOURCE[0]:-}" != "${0}" ]]; then
  echo "repin.sh must be executed (./repin.sh), not sourced — refusing to run body." >&2
  return 0 2>/dev/null || exit 0
fi

set -euo pipefail

# ----------------------------------------------------------------------------- config
OLD_SHA="531d618231269b490fd2800484aee7e0feebca38"
NEW_SHA="c52a8b56b3e164f9854c646bedb5d9e70446d98e"
GATE_GIT="https://github.com/LeightonSec/security-gate.git"
CANON="${CANON:-$HOME/Projects}"          # LeightonSec/<name> and ai-firewall live here
APPLY="${APPLY:-0}"                        # 0 = dry run (default), 1 = actually write/push
COMMIT_MSG="ci: re-pin security-gate to ${NEW_SHA:0:7}"

TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_DIR:-$HOME/.cache/repin/$TS}"
VENV_OLD="$HOME/.cache/repin/venv-${OLD_SHA:0:12}"
VENV_NEW="$HOME/.cache/repin/venv-${NEW_SHA:0:12}"
mkdir -p "$RUN_DIR"
SUMMARY="$RUN_DIR/SUMMARY.tsv"
printf "repo\tvisibility\tgate_old\tgate_new\tverdict\taction\n" > "$SUMMARY"

# Repos to re-pin (path relative to $CANON). These are the ONLY ones with a
# security-gate CI pin that live in the canonical tree.
REPIN=(
  LeightonSec/leightsec-template
  LeightonSec/incident-tracker
  LeightonSec/password-policy-checker
  LeightonSec/port-scanner
  LeightonSec/pcap-analyser
  LeightonSec/unified-dashboard
  LeightonSec/intel-pipeline
  LeightonSec/dolphin-watch
  LeightonSec/threat-classifier
  LeightonSec/llm-honeypot
  LeightonSec/llm-attack-runner
  ai-firewall
  LeightonSec/mfa-coverage-tracker   # cloned + verified 2026-07-01: pin=531d618, scan .
  LeightonSec/intel-dashboard        # cloned + verified 2026-07-01: pin=531d618, scan .
)

# Deliberately excluded, with reason (logged, never processed):
#   nis2-vendor-risk-framework  docs only, no gate step
#   market-recon                private, no security-gate CI step (waiver-only concern)
#   security-toolkit            NO .github ever existed (verified git log --all): hand-hardened,
#                               CI gate never wired. Nothing to re-pin. SEPARATE task = wire a gate.
#   llm-redteam                 stale local orphan, no remote / no workflows

# ----------------------------------------------------------------------------- helpers
c()   { printf '\033[%sm%s\033[0m' "$1" "$2"; }
info() { printf '%s %s\n' "$(c '36' '›')" "$*"; }
ok()   { printf '%s %s\n' "$(c '32' '✓')" "$*"; }
warn() { printf '%s %s\n' "$(c '33' '!')" "$*"; }
die()  { printf '%s %s\n' "$(c '1;31' '✗')" "$*" >&2; exit 1; }

# Parse `--exclude X` tokens out of a repo's own CI scan line so our diff scans
# exactly what CI scans (some repos exclude tests/ or *.db).
ci_excludes() {
  local ci="$1"
  grep -E "security-gate scan" "$ci" 2>/dev/null \
    | grep -oE -- "--exclude[= ]+'?[^' ]+'?" \
    | sed -E "s/--exclude[= ]+'?([^' ]+)'?/--exclude \1/" \
    | tr '\n' ' '
}

# owner/repo slug from the git remote (for the visibility check + push target).
remote_slug() {
  git -C "$1" remote get-url origin 2>/dev/null \
    | sed -E 's#^git@github.com:##; s#^https://github.com/##; s#\.git$##'
}

build_venv() {
  local venv="$1" sha="$2"
  if [[ -x "$venv/bin/security-gate" ]]; then return 0; fi
  info "building venv for ${sha:0:7} …"
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q --upgrade pip
  "$venv/bin/pip" install -q "git+${GATE_GIT}@${sha}" \
    || die "pip install of security-gate@${sha:0:7} failed"
}

# Run the gate at $venv against $repo with $excludes; drop JSON at $out.
run_gate() {
  local venv="$1" repo="$2" excludes="$3" out="$4"
  local work; work="$(mktemp -d)"
  ( cd "$work"
    # shellcheck disable=SC2086
    "$venv/bin/security-gate" scan "$repo" $excludes \
      --output json --save --no-exit-code >/dev/null 2>"$work/err" \
      || { cat "$work/err" >&2; exit 1; }
  ) || die "gate run failed for $repo (venv $(basename "$venv"))"
  cp "$work/security-gate-report.json" "$out"
  rm -rf "$work"
}

# ------------------------------------------------------------------ findings diff (py)
# Robust to the missing_validation rewrite: keys on (scanner,file) counts +
# severity multiset, NOT on line/match (which shift). Compares the RAW set
# (active findings ∪ accepted) so waiver churn is visible and drops aren't
# masked by suppression. Writes a human-readable report to $3.
# Exit 0 = CLEAN (safe to re-pin), 2 = REVIEW (halt this repo), 1 = error.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIFF_PY="$SCRIPT_DIR/findings_diff.py"
[[ -f "$DIFF_PY" ]] || die "findings_diff.py not found beside repin.sh at $DIFF_PY"

# Delegates to the standalone, fixture-validated findings_diff.py so the
# dry-run exercises EXACTLY the logic run_fixtures.sh covers — no embedded twin.
diff_findings() {
  python3 "$DIFF_PY" "$1" "$2" "$3"
}

# ----------------------------------------------------------------------------- preflight
command -v gh  >/dev/null || die "gh not found"
command -v git >/dev/null || die "git not found"
[[ "$(git -C "$CANON/LeightonSec/security-gate" rev-parse HEAD)" == "$NEW_SHA" ]] \
  || die "local security-gate HEAD != NEW_SHA — refusing to run against a stale gate"

build_venv "$VENV_OLD" "$OLD_SHA"
build_venv "$VENV_NEW" "$NEW_SHA"

info "mode: $([[ $APPLY == 1 ]] && c '1;31' 'APPLY (will commit + push)' || c '32' 'DRY RUN (no writes)')"
info "logs: $RUN_DIR"
echo

# ----------------------------------------------------------------------------- per repo
process_repo() (            # subshell so `set -e` protects each step but one repo
  set -euo pipefail         # failing does not abort the whole batch
  rel="$1"
  repo="$CANON/$rel"
  name="$(basename "$rel")"
  ci="$repo/.github/workflows/ci.yml"
  log="$RUN_DIR/$name.diff.log"

  echo "──────── $name ────────"

  # 1. canonical-tree confirm
  [[ -d "$repo/.git" ]]            || die "$name: not a git repo at $repo"
  [[ -f "$ci" ]]                   || die "$name: no ci.yml"
  [[ -w "$ci" ]]                   || die "$name: ci.yml not writable (iCloud mirror?)"
  case "$(cd "$repo" && pwd -P)" in
    *"/Mobile Documents/"*|*"/Documents/Projects/"*) die "$name: resolves into an iCloud mirror path" ;;
  esac
  [[ -z "$(git -C "$repo" status --porcelain)" ]] || die "$name: working tree not clean"
  head="$(git -C "$repo" rev-parse HEAD)"
  up="$(git -C "$repo" rev-parse '@{u}' 2>/dev/null)" || die "$name: no upstream"
  [[ "$head" == "$up" ]]           || die "$name: HEAD != @{u} (out of sync with remote)"
  ok "canonical + clean + in sync"

  # 2. visibility check
  slug="$(remote_slug "$repo")"
  vis="$(gh repo view "$slug" --json visibility -q .visibility)" || die "$name: gh repo view failed"
  ok "visibility: $slug -> $vis"

  # 3. findings diff OLD vs NEW (mirror CI's own excludes)
  excludes="$(ci_excludes "$ci")"
  info "scan args mirrored from CI: 'scan . ${excludes}'"
  run_gate "$VENV_OLD" "$repo" "$excludes" "$RUN_DIR/$name.old.json"
  run_gate "$VENV_NEW" "$repo" "$excludes" "$RUN_DIR/$name.new.json"
  set +e
  res="$(diff_findings "$RUN_DIR/$name.old.json" "$RUN_DIR/$name.new.json" "$log")"
  dv=$?
  set -e
  IFS=$'\t' read -r g_old g_new verdict <<<"$res"
  if [[ $dv -ne 0 ]]; then
    warn "findings diff: $verdict  (gate $g_old -> $g_new)  — see $log"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$vis" "$g_old" "$g_new" "$verdict" "HALTED-review" >> "$SUMMARY"
    warn "$name HALTED — no SHA bump, no push. Read $log."
    exit 0
  fi
  ok "findings diff: CLEAN (gate $g_old -> $g_new) — $log"

  # 4. SHA update (assert exactly-one OLD present)
  n="$(grep -c "$OLD_SHA" "$ci" || true)"
  if [[ "$n" -eq 0 ]] && grep -q "$NEW_SHA" "$ci"; then
    ok "$name already pinned to NEW_SHA"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$vis" "$g_old" "$g_new" "$verdict" "already-pinned" >> "$SUMMARY"
    exit 0
  fi
  [[ "$n" -eq 1 ]] || die "$name: expected exactly 1 OLD_SHA in ci.yml, found $n"

  if [[ "$APPLY" != 1 ]]; then
    info "[dry run] would replace $OLD_SHA -> $NEW_SHA in ci.yml and push"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$vis" "$g_old" "$g_new" "$verdict" "dry-run-ready" >> "$SUMMARY"
    exit 0
  fi

  # 5. apply: bump, verify, commit, push, watch
  sed -i.bak "s/$OLD_SHA/$NEW_SHA/" "$ci" && rm -f "$ci.bak"
  grep -q "$NEW_SHA" "$ci" || die "$name: NEW_SHA not present after sed"
  grep -q "$OLD_SHA" "$ci" && die "$name: OLD_SHA still present after sed"
  [[ "$(git -C "$repo" diff --name-only)" == ".github/workflows/ci.yml" ]] \
    || die "$name: unexpected files changed — refusing to commit"
  git -C "$repo" add .github/workflows/ci.yml
  git -C "$repo" commit -q -m "$COMMIT_MSG"
  git -C "$repo" push -q
  ok "$name pushed — watching CI"
  gh -R "$slug" run watch "$(gh -R "$slug" run list -L1 --json databaseId -q '.[0].databaseId')" --exit-status \
    && cires="green" || cires="RED"
  printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$vis" "$g_old" "$g_new" "$verdict" "pushed:$cires" >> "$SUMMARY"
  ok "$name CI: $cires"
)

# ONLY="repoA repoB" restricts the run to those repos (by basename) — for a
# one-repo smoke test, or re-running a single halted repo. Empty = all of REPIN.
ONLY="${ONLY:-}"
for rel in "${REPIN[@]}"; do
  if [[ -n "$ONLY" ]]; then
    case " $ONLY " in *" $(basename "$rel") "*) ;; *) continue ;; esac
  fi
  process_repo "$rel" || warn "process_repo $rel returned nonzero (recorded, continuing)"
  echo
done

echo "════════ summary ════════"
column -t -s $'\t' "$SUMMARY"
echo
info "per-repo findings diffs in $RUN_DIR/*.diff.log — READ THEM before APPLY=1"
