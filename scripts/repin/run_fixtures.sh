#!/usr/bin/env bash
# Acceptance test for findings_diff.py against the fixtures.
# Asserts, per case: (a) verdict matches expected, and (b) EXACTLY the expected
# category markers appear in the log — no missing categories, no extra ones.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DIFF="$HERE/findings_diff.py"
FIX="$HERE/fixtures"
# Regenerate fixtures from the spec (make_fixtures.py) so this test is self-contained
# and reproducible; fixtures/ is a generated artifact — gitignored, never committed.
python3 "$HERE/make_fixtures.py" >/dev/null
OUT="$(mktemp -d)"

# bash 3.2 (macOS default) has no associative arrays — use a case lookup.
marker() {
  case "$1" in
    drop)    echo "!! DROPS" ;;
    blocker) echo "!! NEW ACTIVE" ;;
    churn)   echo "!! WAIVER CHURN" ;;
    flip)    echo "!! GATE FLIP" ;;
    add)     echo "## ADDS" ;;
    reloc)   echo "?? POSSIBLE RELOCATION" ;;
  esac
}
ALLCATS="drop blocker churn flip add reloc"

pass=0; fail=0
while IFS=$'\t' read -r name exp_verdict exp_cats; do
  [[ -z "$name" ]] && continue
  log="$OUT/$name.log"
  got="$(python3 "$DIFF" "$FIX/$name/old.json" "$FIX/$name/new.json" "$log")"
  verdict="$(cut -f3 <<<"$got")"
  errs=""
  [[ "$verdict" == "$exp_verdict" ]] || errs="${errs}verdict $verdict != $exp_verdict; "
  for cat in $ALLCATS; do
    want=no; [[ ",$exp_cats," == *",$cat,"* ]] && want=yes
    have=no; grep -qF "$(marker "$cat")" "$log" && have=yes
    [[ "$want" == "$have" ]] || errs="${errs}$cat: want=$want have=$have; "
  done
  if [[ -z "$errs" ]]; then
    printf '  ok   %-30s %s [%s]\n' "$name" "$verdict" "$exp_cats"; pass=$((pass+1))
  else
    printf '  FAIL %-30s %s\n' "$name" "$errs"; fail=$((fail+1))
  fi
done < "$FIX/expected.tsv"

echo "── $pass passed, $fail failed"
rm -rf "$OUT"
[[ $fail -eq 0 ]]
