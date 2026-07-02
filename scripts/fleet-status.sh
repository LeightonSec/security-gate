#!/usr/bin/env bash
# fleet-status.sh — LeightonSec session-close checklist, fleet-wide.
#
# One line per repo, fail-closed: exits non-zero if ANY repo fails a check.
# Run it BEFORE calling a session done. Every check maps to a failure class
# that actually happened (dates are the day it was found systemically):
#
#   DIRTY      uncommitted changes           (security-gate repin.sh, 2026-07-01)
#   UNPUSHED   HEAD != origin                (add-repin-tooling branch, 2026-07-01)
#   BRANCH     not on main                   (dolphin-watch on master, 2026-07-02)
#   CI         latest run at HEAD not green  (market-recon red since May, 2026-07-02)
#   PIN        gate SHA != fleet pin         (incident-tracker/pcap stale, 2026-07-01)
#   FLOOR      lockfile compiled above CI    (4 fixes then a sweep, 2026-07-02)
#              matrix floor
#
# Source-guard BEFORE set -u: the ambient shell may be zsh, where
# BASH_SOURCE is unset (see feedback_zsh_ambient_shell) — fail CLOSED.
if [[ "${BASH_SOURCE[0]:-}" != "$0" ]]; then
  echo "fleet-status.sh must be executed, not sourced" >&2
  return 1 2>/dev/null || exit 1
fi
set -euo pipefail

# Bumped by re-pin passes (scripts/repin/). Repos whose CI installs the gate
# must pin exactly this SHA.
FLEET_PIN="c52a8b56b3e164f9854c646bedb5d9e70446d98e"

CANON="${CANON:-$HOME/Projects/LeightonSec}"
EXTRA_REPOS=("$HOME/Projects/ai-firewall")  # canonical clones living outside CANON
ORG="LeightonSec"

# GitHub repos deliberately NOT checked, each with a reason. Anything on
# GitHub that is neither scanned nor listed here is a FAIL: the checklist
# must not report green while silently not looking at a repo.
# (case-based, not declare -A: macOS ships bash 3.2, no associative arrays)
skip_reason() {
  case "$1" in
    LeightonSec)                echo "org profile README, no code/CI" ;;
    nis2-vendor-risk-framework) echo "docs-only framework, no code/CI" ;;
    *)                          echo "" ;;
  esac
}

fail_count=0
warn_count=0
scanned_repos=""

check_repo() {
  local dir="$1" repo status=() warns=()
  repo="$(basename "$dir")"
  [[ -d "$dir/.git" ]] || return 0
  scanned_repos="$scanned_repos $repo"
  cd "$dir"

  # DIRTY
  [[ -z "$(git status --porcelain)" ]] || status+=("DIRTY")

  # BRANCH
  local branch
  branch="$(git branch --show-current)"
  [[ "$branch" == "main" ]] || status+=("BRANCH=$branch")

  # UNPUSHED / remote checks — skipped for deliberately local-only repos
  local head
  head="$(git rev-parse HEAD)"
  if git remote get-url origin >/dev/null 2>&1; then
    git fetch -q origin 2>/dev/null || warns+=("FETCH-FAILED")
    local upstream
    upstream="$(git rev-parse "origin/$branch" 2>/dev/null || echo MISSING)"
    [[ "$head" == "$upstream" ]] || status+=("UNPUSHED")

    # CI at HEAD (not just latest-anywhere: a green run on an old SHA is stale)
    local run
    run="$(gh run list -R "$ORG/$repo" --commit "$head" --limit 1 \
           --json status,conclusion \
           --jq '.[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo "")"
    case "$run" in
      completed/success) ;;
      "")                warns+=("CI-NO-RUN") ;;
      completed/*)       status+=("CI=$run") ;;
      *)                 warns+=("CI-PENDING") ;;
    esac
  else
    warns+=("LOCAL-ONLY")
  fi

  # PIN — gate presence is a "security-gate scan" invocation; the pin
  # requirement applies only where the gate is installed from git (the
  # gate's own repo self-scans from source, no install line). Install
  # syntax varies: both security-gate.git@SHA and security-gate@SHA are
  # live in the fleet — match both or the check false-negatives to NO-GATE.
  if grep -rqs "security-gate scan" .github/workflows/ 2>/dev/null; then
    if grep -rqsE "security-gate(\.git)?@" .github/workflows/ 2>/dev/null; then
      grep -rqsE "security-gate(\.git)?@$FLEET_PIN" .github/workflows/ \
        || status+=("PIN-STALE")
    fi
  elif ls .github/workflows/*.yml >/dev/null 2>&1; then
    warns+=("NO-GATE")
  fi

  # FLOOR — lockfile compile floor must not exceed the CI matrix floor.
  # NO-PROVENANCE is a warn: read the header yourself, don't trust the regex.
  local lf prov floor
  floor="$(grep -ohE '"3\.[0-9]+"' .github/workflows/*.yml 2>/dev/null \
           | grep -oE '3\.[0-9]+' | sort -V | head -1 || true)"
  for lf in requirements*.txt; do
    [[ -f "$lf" ]] || continue
    prov="$(head -3 "$lf" \
            | grep -oE 'python-version 3\.[0-9]+|with Python 3\.[0-9]+' \
            | grep -oE '3\.[0-9]+' | head -1 || true)"
    if [[ -z "$prov" ]]; then
      warns+=("NO-PROVENANCE:$lf")
    elif [[ -n "$floor" ]] && [[ "$(printf '%s\n' "$floor" "$prov" | sort -V | head -1)" != "$prov" ]]; then
      status+=("FLOOR:$lf=$prov>ci=$floor")
    fi
  done

  if ((${#status[@]})); then
    printf 'FAIL  %-24s %s' "$repo" "${status[*]}"
    ((${#warns[@]})) && printf '  [%s]' "${warns[*]}"
    printf '\n'
    ((fail_count++)) || true
  elif ((${#warns[@]})); then
    printf 'WARN  %-24s [%s]\n' "$repo" "${warns[*]}"
    ((warn_count++)) || true
  else
    printf 'ok    %s\n' "$repo"
  fi
}

for d in "$CANON"/*/ "${EXTRA_REPOS[@]}"; do
  check_repo "${d%/}"
done

# Coverage self-check: every GitHub repo must be scanned or skipped-with-reason.
# A checklist with silent scope gaps manufactures false confidence.
while IFS= read -r gh_repo; do
  [[ " $scanned_repos " == *" $gh_repo "* ]] && continue
  reason="$(skip_reason "$gh_repo")"
  if [[ -n "$reason" ]]; then
    printf 'skip  %-24s [%s]\n' "$gh_repo" "$reason"
  else
    printf 'FAIL  %-24s NOT-COVERED (on GitHub, not in CANON/EXTRA_REPOS/skip-list)\n' "$gh_repo"
    ((fail_count++)) || true
  fi
done < <(gh repo list "$ORG" --limit 100 --json name --jq '.[].name')

echo
if ((fail_count)); then
  echo "fleet-status: $fail_count repo(s) FAILED the close checklist" >&2
  exit 1
fi
echo "fleet-status: all repos pass (${warn_count} warning(s) — read them, don't skim them)"
