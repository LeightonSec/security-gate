#!/usr/bin/env python3
"""Findings diff for the security-gate re-pin pass.

Compares two security-gate JSON reports (OLD SHA vs NEW SHA) for the SAME repo
and decides whether it is safe to re-pin, or whether the repo must be HALTED for
human review.

Design (locked before code — see repin.sh header):
  * RAW set = active `findings` ∪ `accepted`, so a real drop can't hide behind a
    waiver and waiver churn is visible.
  * Coarse key = (scanner, file) with a per-severity multiset. NEVER keys on
    `line` or `match`, which shift under the missing_validation rewrite — those
    are logged for a human to read, not used to trigger a verdict.
  * Four distinct categories, tracked separately so they can't mask each other:
      DROP     raw findings for a (scanner,file) reduced/lost a CRIT|HIGH
      BLOCKER  new active CRITICAL|HIGH not active at OLD -> will block CI
      CHURN    was suppressed (accepted) at OLD, now active at NEW (match drifted)
      FLIP     gate PASSED -> BLOCKED

Usage:  findings_diff.py OLD.json NEW.json LOG.out
Prints: "<gate_old>\t<gate_new>\t<verdict>"   verdict in {CLEAN, REVIEW}
Exit:   0 = CLEAN (safe to re-pin), 2 = REVIEW (halt this repo), 1 = error
"""
import json
import sys
from collections import Counter, defaultdict


def _raw(d):
    """Active findings PLUS accepted — the pre-waiver scanner truth."""
    return list(d.get("findings", [])) + list(d.get("accepted", []))


def _active(d):
    return list(d.get("findings", []))


def _coarse(items):
    """(scanner, file) -> Counter(severity). file is IN the key on purpose, so a
    same-scanner same-severity move between files shows as drop+add, not cancel."""
    m = defaultdict(Counter)
    for f in items:
        m[(f["scanner"], f["file"])][f["severity"]] += 1
    return m


def _dump(d, title):
    # Tag each line active/accepted — WITHOUT this, a waived CRITICAL prints
    # identically to a gating one and reads as "CRITICAL ... VERDICT CLEAN",
    # which a tired operator misreads. The tag also makes a churn (accepted@OLD
    # -> active@NEW) visible in the dump itself.
    items = ([(f, "active") for f in d.get("findings", [])]
             + [(f, "accepted") for f in d.get("accepted", [])])
    out = [f"\n## {title} ({len(items)})"]
    for f, tag in sorted(items, key=lambda x: (x[0]["scanner"], x[0]["file"], x[0].get("line", 0))):
        out.append(f'  [{tag:<8}] {f["severity"]:<8} {f["scanner"]:<22} {f["file"]}:{f.get("line","?")}')
        out.append(f'             {f.get("detail","")}')
    return "\n".join(out)


def analyze(old, new):
    """Return (verdict, categories dict, lines[])."""
    ro, rn = _coarse(_raw(old)), _coarse(_raw(new))
    ao, an = _coarse(_active(old)), _coarse(_active(new))

    drops, blockers, churn = [], [], []

    # DROP: raw findings for a (scanner,file) reduced, or lost a CRIT/HIGH.
    for key, oc in ro.items():
        nc = rn.get(key, Counter())
        if sum(nc.values()) < sum(oc.values()):
            drops.append((key, dict(oc), dict(nc)))
            continue
        for sev in ("CRITICAL", "HIGH"):
            if nc[sev] < oc[sev]:
                drops.append((key, dict(oc), dict(nc)))
                break

    # BLOCKER: CRIT/HIGH active at NEW beyond what was active at OLD -> blocks CI.
    for key, nc in an.items():
        oc = ao.get(key, Counter())
        for sev in ("CRITICAL", "HIGH"):
            if nc[sev] > oc[sev]:
                blockers.append((key, sev, nc[sev] - oc[sev]))

    # CHURN: suppressed at OLD, now active at NEW (waiver match text drifted).
    old_accept_keys = {(a["scanner"], a["file"]) for a in old.get("accepted", [])}
    for key in an:
        if key in old_accept_keys and key not in ao:
            churn.append(key)

    # ADDS (informational): raw count increases NOT already counted as blockers.
    # A lone add does not force REVIEW — expected new-scanner MEDIUMs live here —
    # but it must be visible so a plain drop (nothing replaced it) reads
    # differently from a drop+add (something took its place).
    blocker_keys = {k for k, _, _ in blockers}
    adds = []
    for key, nc in rn.items():
        if key in blocker_keys:
            continue
        inc = nc - ro.get(key, Counter())   # Counter subtraction keeps only positives
        if inc:
            adds.append((key, dict(inc)))

    # POSSIBLE RELOCATION: a drop and an add sharing scanner+severity. This is a
    # verify-this prompt, NOT a conclusion — an unrelated add can coincide with a
    # real drop and look like a move. The operator must read both matches.
    reloc = []
    for dkey, doc, dnc in drops:
        lost = Counter(doc) - Counter(dnc)
        for akey, inc in adds:
            if akey[0] == dkey[0]:                       # same scanner
                for sev in set(lost) & set(inc):         # same severity
                    reloc.append((dkey[0], sev, dkey[1], akey[1]))

    gate_old, gate_new = old.get("gate"), new.get("gate")
    flip = gate_old == "PASSED" and gate_new == "BLOCKED"

    # Verdict is driven ONLY by halt-worthy categories. adds/reloc are legibility
    # aids, never a reason to halt on their own.
    verdict = "REVIEW" if (drops or blockers or churn or flip) else "CLEAN"
    cats = {"drops": drops, "blockers": blockers, "churn": churn,
            "flip": flip, "adds": adds, "reloc": reloc}

    lines = [
        f"gate: {gate_old} -> {gate_new}",
        f"raw findings: {len(_raw(old))} -> {len(_raw(new))}   "
        f"active: {len(_active(old))} -> {len(_active(new))}",
    ]
    if drops:
        lines.append(f"\n!! DROPS ({len(drops)}) — present at OLD, gone/reduced at NEW:")
        for key, oc, nc in drops:
            lines.append(f"   {key[0]} :: {key[1]}   {oc} -> {nc}")
    if blockers:
        lines.append(f"\n!! NEW ACTIVE CRITICAL/HIGH ({len(blockers)}) — will BLOCK CI:")
        for key, sev, n in blockers:
            lines.append(f"   {sev} x{n}   {key[0]} :: {key[1]}")
    if churn:
        lines.append(f"\n!! WAIVER CHURN ({len(churn)}) — suppressed at OLD, active at NEW:")
        for key in churn:
            lines.append(f"   {key[0]} :: {key[1]}   (waiver match text likely moved — go READ the new match)")
    if flip:
        lines.append("\n!! GATE FLIP: PASSED -> BLOCKED")
    if adds:
        lines.append(f"\n## ADDS ({len(adds)}) — new findings (informational, non-gating):")
        for key, inc in adds:
            lines.append(f"   {key[0]} :: {key[1]}   +{inc}")
    if reloc:
        lines.append(f"\n?? POSSIBLE RELOCATION ({len(reloc)}) — a drop + a same-scanner "
                     "same-severity add. READ both matches to confirm it is the SAME finding "
                     "moved, not a real drop that an unrelated add is masking:")
        for scanner, sev, fa, fb in reloc:
            lines.append(f"   {scanner} {sev}: {fa} -> {fb}")
    lines.append(_dump(old, "RAW FINDINGS @ OLD"))
    lines.append(_dump(new, "RAW FINDINGS @ NEW"))
    lines.append(f"\nVERDICT: {verdict}")
    return verdict, cats, lines, gate_old, gate_new


def main(argv):
    if len(argv) != 4:
        print("usage: findings_diff.py OLD.json NEW.json LOG.out", file=sys.stderr)
        return 1
    old = json.load(open(argv[1]))
    new = json.load(open(argv[2]))
    verdict, _cats, lines, gate_old, gate_new = analyze(old, new)
    header = f"# findings diff  OLD {argv[1]}  vs  NEW {argv[2]}"
    open(argv[3], "w").write(header + "\n" + "\n".join(lines) + "\n")
    print(f"{gate_old}\t{gate_new}\t{verdict}")
    return 0 if verdict == "CLEAN" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
