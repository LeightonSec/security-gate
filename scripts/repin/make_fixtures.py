#!/usr/bin/env python3
"""Build findings-diff fixtures. The case table below IS the spec — read it.

Each case is (old_active, old_accepted, new_active, new_accepted). Findings are
tuples (scanner, file, severity[, line]). `gate` is DERIVED from active findings
(BLOCKED iff any active CRITICAL/HIGH) so PASSED/BLOCKED can't be hand-mislabeled.

Writes fixtures/<case>/{old,new}.json and fixtures/expected.tsv.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")


def finding(t):
    scanner, file, sev = t[0], t[1], t[2]
    line = t[3] if len(t) > 3 else 10
    return {
        "scanner": scanner, "severity": sev, "file": file, "line": line,
        "match": f"{scanner}:{file}:{line}",
        "detail": f"{scanner} finding in {file}",
        "checklist_item": f"resolve {scanner}",
    }


def gate_of(active):
    return "BLOCKED" if any(f["severity"] in ("CRITICAL", "HIGH") for f in active) else "PASSED"


def report(active_t, accepted_t):
    active = [finding(t) for t in active_t]
    accepted = [{**finding(t), "rationale": "waived", "reviewer": "leighton", "date": "2026-06-24"}
                for t in accepted_t]
    return {
        "generated": "2026-07-01T00:00:00+00:00", "repo": "/fixture",
        "gate": gate_of(active), "summary": {},
        "findings": active, "accepted": accepted,
    }


# ---------------------------------------------------------------- the case table
# case: (old_active, old_accepted, new_active, new_accepted, expected_verdict, expected_cats)
CASES = {
    # 00 baseline: identical empty reports -> nothing changed.
    "00_noop_clean": ([], [], [], [], "CLEAN", []),

    # 01 new scanner adds a MEDIUM (missing_timeout). Gate stays PASSED. Expected
    #    MEDIUM additions from the new scanners must NOT halt a repo — CLEAN, but
    #    the add IS logged (the 'add' category is informational, not halt-worthy).
    "01_benign_medium_add": (
        [], [],
        [("missing_timeout", "net.py", "MEDIUM")], [],
        "CLEAN", ["add"]),

    # 02 THE invisible case: a MEDIUM finding the old scanner caught is gone at
    #    NEW. Both gates PASSED, so exit code alone shows nothing. Must be DROP.
    "02_silent_drop_medium": (
        [("missing_validation", "parser.py", "MEDIUM")], [],
        [], [],
        "REVIEW", ["drop"]),

    # 03 new scanner surfaces a real CRITICAL (pickle_usage). Blocks CI + flips gate.
    "03_new_critical": (
        [], [],
        [("pickle_usage", "loader.py", "CRITICAL")], [],
        "REVIEW", ["blocker", "flip"]),

    # 04 waiver churn: a waived MEDIUM un-suppresses because the match text drifted
    #    under the rewrite. No drop, no blocker — but the waiver stopped matching.
    "04_waiver_churn": (
        [], [("missing_validation", "tickets.py", "MEDIUM")],
        [("missing_validation", "tickets.py", "MEDIUM")], [],
        "REVIEW", ["churn"]),

    # 05 scanner AND file both change, total raw count preserved (1 -> 1). Must NOT
    #    cancel to CLEAN: (scanner,file) key keeps them distinct -> old key DROPs.
    "05_scanner_and_file_change": (
        [("missing_validation", "a.py", "MEDIUM")], [],
        [("pickle_usage", "b.py", "MEDIUM")], [],
        "REVIEW", ["drop", "add"]),   # different scanner -> add, but NO reloc hint

    # 06 count-preserving swap, SAME scanner + SAME severity, different file. The
    #    sharpest key-granularity test: file is in the key, so this is drop+add,
    #    not a wash.
    "06_count_preserving_swap": (
        [("missing_validation", "a.py", "MEDIUM")], [],
        [("missing_validation", "b.py", "MEDIUM")], [],
        "REVIEW", ["drop", "add", "reloc"]),   # same scanner+sev -> reloc hint fires

    # 07 churn AND a real new CRITICAL in the SAME file. The two must both appear —
    #    neither masks the other in the log.
    "07_churn_plus_new_same_file": (
        [], [("missing_validation", "handlers.py", "MEDIUM")],
        [("missing_validation", "handlers.py", "MEDIUM"),
         ("pickle_usage", "handlers.py", "CRITICAL")], [],
        "REVIEW", ["churn", "blocker", "flip"]),

    # 08 NULL HYPOTHESIS for churn: a legitimately-waived CRITICAL that stays
    #    correctly suppressed old->new. Proves the churn matcher does NOT fire on
    #    an unchanged waiver, and that a waived CRITICAL stays out of active/gate.
    #    If this isn't CLEAN, churn detection is just "REVIEW anything accepted".
    "08_waived_critical_suppressed": (
        [], [("pickle_usage", "legacy.py", "CRITICAL")],
        [], [("pickle_usage", "legacy.py", "CRITICAL")],
        "CLEAN", []),

    # 09 STEADY STATE: a real unchanged waiver (MEDIUM) AND a real unchanged active
    #    finding (MEDIUM), identical old->new. Proves unchanged content — accepted
    #    or active — produces no drop/add/churn noise. Non-trivial CLEAN (unlike 00).
    "09_steady_state_waivers": (
        [("missing_timeout", "client.py", "MEDIUM")],
        [("missing_validation", "models.py", "MEDIUM")],
        [("missing_timeout", "client.py", "MEDIUM")],
        [("missing_validation", "models.py", "MEDIUM")],
        "CLEAN", []),
}


def main():
    os.makedirs(FIX, exist_ok=True)
    exp_lines = []
    for name, (oa, oac, na, nac, verdict, cats) in CASES.items():
        d = os.path.join(FIX, name)
        os.makedirs(d, exist_ok=True)
        json.dump(report(oa, oac), open(os.path.join(d, "old.json"), "w"), indent=2)
        json.dump(report(na, nac), open(os.path.join(d, "new.json"), "w"), indent=2)
        exp_lines.append(f"{name}\t{verdict}\t{','.join(cats) if cats else '-'}")
    open(os.path.join(FIX, "expected.tsv"), "w").write("\n".join(exp_lines) + "\n")
    print(f"wrote {len(CASES)} fixtures to {FIX}")


if __name__ == "__main__":
    main()
