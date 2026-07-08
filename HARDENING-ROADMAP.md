# security-gate — Hardening & Detection Roadmap

*Drafted 2026-07-06 from an external-architect review pass. Status: BACKLOG.
Nothing here is sanctioned build work until the focus-doctrine build-resumption
condition (hired) — except where an item is marked **[RIDER]** (config-shaped,
rides along the next legitimate fleet touch) or **[DOCS]** (writing, POUR-compatible).
Chip at items in order within each part; every item is sized to be finishable
in one sitting and has a definition of done. No item is done without its check.*

**Standing rules for every item (house doctrine):**
- Lock the decision in this doc before writing code; if implementation wants to
  deviate, come back here first.
- Every new rule/check ships with a **must-fire** and a **must-not-fire** fixture.
- Never claim a capability the test suite doesn't prove. Update the honest-ceiling
  section of the README/docs in the same commit as any capability change.
- Gates and commits run bare, full output shown, exit codes checked.
- Public write-up per shipped chunk (see Part D) — the improvement isn't finished
  until it's documented.

---

## Part A — Integrity backlog (protect the verdicts)

*Theme: the gate is the fleet's root of trust and its #1 supply-chain target
(the Glasswing lesson pointed inward: compromise the gate, blind 18 repos).*

### A1. Waiver expiry — FIRST, cheapest real hole
- [ ] Add mandatory `expires` field to `accepted-findings.toml` schema
      (loader rejects entries without it; existing entries get dated at migration).
- [ ] Gate FAILS on any expired waiver (fail-closed: expired = finding is live again).
- [ ] Fixture pair: expired-waiver repo must fail; valid-waiver repo must pass.
- **Why:** entries currently carry reviewer/rationale/date but no expiry — every
  acceptance decays silently into permanent blindness. The waiver file is also the
  natural channel for smuggling a suppression; expiry forces periodic re-review.
- **Done when:** self-scan + fleet scan green with all waivers carrying expiry;
  README waiver section updated. *(Also unblocks the "expiring waivers" claim in
  the Post #4 draft — see fact anchors there.)*
- Est: 1 session.

### A2. Detection ledger + honest-ceiling doc **[DOCS — may start pre-hire]**
- [ ] `DETECTION-LEDGER.md`: every real finding (fleet-wide, any discovery method)
      recorded against *which check should have caught it* — automated / would-need-X / human-only.
      Seed it retroactively: msgpack CVE (SCA ✓), XSS pair (human-only, cross-file taint),
      2026-07-06 retrospective score (automated 0, fuzz-would-have 1, human-only 1).
- [ ] Honest-ceiling doc: what the gate structurally cannot catch, stated plainly
      (line-local regex limits, no cross-file taint, no semantics). Claim-honesty
      applied to the gate itself.
- **Done when:** ledger has all known historical findings; ceiling doc linked from README.
- Est: 1 session, no code.

### A3. Supply-chain: signed releases + pin single-source
- [ ] Signed v0.2.0 release (already in re-pin backlog).
- [ ] FLEET_PIN single-sourced (currently hardcoded in fleet-status.sh — known limit).
- [ ] Repos pin by SHA (already true) and verify against the single source.
- **Done when:** a re-pin pass touches exactly one pin definition; release artifact verifiable.
- Est: 1–2 sessions.

### A4. Continuous canary — test the checker, not just the code
- [ ] Per-scanner must-fire proof in CI: every scanner demonstrably fires on its
      fixture on every run (a silent-zero scanner = red build).
- **Why:** a skimmed WARN once hid a bug in the checker itself. A rule that never
  fires is either eradicating a class or broken — canaries distinguish.
- **Done when:** disabling any scanner's detection logic turns CI red.
- Est: 1 session.

### A5. Hostile-repo threat model **[DOCS — may start pre-hire]**
- [ ] Extend TAINT_SCOPE.md: can a malicious repo make *its own gate pass*?
      Enumerate: regex catastrophic backtracking → timeout behaviour (fail open or
      closed?), exclude-path abuse, findings-file poisoning, symlink games.
- [ ] Convert each enumerated vector into either a test or a documented accepted risk.
- **Done when:** every vector has a fixture or a written waiver-style acceptance.
- Est: 1 session docs + 1 session tests.

### A6. Fail-closed chaos harness
- [ ] Extend FAIL-OPEN-AUDIT (b2da559, 201 tests): injected tool-missing /
      tool-crash / malformed-output for every external dependency (semgrep CLI first).
- **Done when:** every external tool failure mode has a test proving the gate goes red, not silent.
- Est: 1 session.

---

## Part B — Detection-power backlog (catch more bugs)

*Theme: raise the detection ceiling deterministically. AI tier explicitly
deferred (see `~/Projects/LeightonSec/ai-gateway-post-draft.md` for that design).
Known blind spot being attacked: cross-file/cross-language taint — the class
both stored XSS lived in.*

### B1. CodeQL on public repos **[RIDER — one workflow file per repo]**
- [ ] Enable GitHub code scanning (CodeQL default queries) on public fleet repos.
- [ ] Advisory first; promote to required check per-repo after observing FP temperament.
- **Why:** free interprocedural dataflow on public repos — the strongest
  deterministic taint engine available, at the cost of a workflow file. Directly
  targets the pcap-analyser XSS class (Python source → JS sink).
- **Done when:** all public repos scanning; one month of results triaged into the ledger.
- Est: rider on next re-pin pass + triage time.

### B2. Semgrep graduation pipeline
- [ ] Shadow mode: semgrep rules run and report fleet-wide without gating (current state, formalised).
- [ ] Per-rule FP ledger (fleet-wide count, dated).
- [ ] Promotion rule: individual rule → gating after N weeks at 0 FP (pick N, lock it here: proposed 4).
- [ ] Demotion rule: any FP in a gating semgrep rule → back to advisory + ledger entry.
- **Why:** the AST engine is already in the tool, deliberately defanged because a
  pinned-rule FP breaks every repo until re-pin. Promotion-by-evidence fixes that
  without accepting permanent advisory status.
- **Done when:** first rule promoted to gating on ledger evidence.
- Est: 1 session pipeline + calendar time.

### B3. Sink-inventory scanner — FIRST BUILD when build resumes
- [ ] New scanner: fire on dangerous sinks unless the escaping/parameterising idiom
      is present on the same statement. Initial sink list (lock before code):
      `|safe`, f-string/`.format()` into HTML context, `.innerHTML =`,
      `render_template_string`, unparameterised `execute()`, `send_file(<var>)`,
      `mark_safe`, `dangerouslySetInnerHTML`.
- [ ] Must-fire fixture per sink; must-not-fire fixture per escaped idiom.
- [ ] Fleet dry-run before gating (expect real findings — budget triage time).
- **Why:** when taint can't be followed, gate the sink. Line-local, so it's
  regex-tractable; would have caught the pcap-analyser XSS from the sink side.
  "Validate at boundary, escape at sink" made enforceable instead of advisory.
- **Done when:** scanner gating fleet-wide, findings triaged/waived with rationale.
- Est: 2 sessions (1 lock+build, 1 fleet triage).

### B4. Workflow/Actions scanner
- [ ] Detect: `${{ github.event.* }}` interpolated into `run:` blocks,
      `pull_request_target` with checkout of PR head, unpinned third-party actions.
- [ ] Decide (lock here): wrap zizmor like semgrep, or write top-3 rules natively.
      *Proposed: native rules — zero new external dependency, and the 3 rules are simple.*
- **Why:** the gate's own CI is currently unscanned attack surface.
- **Done when:** fleet workflows scanned and clean/waived.
- Est: 1 session.

### B5. Ledger-driven rule growth (process, not code)
- [ ] Standing rule: every confirmed miss in DETECTION-LEDGER.md gets triaged to
      → harden existing rule / new rule spec / documented ceiling entry.
- **Done when:** it's in the contribution/dev docs and has happened once.

### B6. Fuzz-smoke job in leightsec-template
- [ ] Property-based test job (hypothesis; consider atheris if coverage-guided is
      warranted) for fleet tools that parse hostile bytes — pcap-analyser first.
- [ ] Non-gating first; gate per-repo once stable.
- **Why:** retrospective scored "fuzz would have caught: 1." Extends the Bastion
  WS3 logic fleet-wide.
- **Done when:** template job exists; pcap-analyser running it in CI.
- Est: 1–2 sessions.

---

## Part C — Phase plan (after Parts A+B are done)

*Each phase has an entry gate, not a start date. The entry gate for the whole
program remains: build resumption = hired.*

**Phase 1 — Prove it.**
Score the gate (and CodeQL alongside) against a known-answer corpus: a deliberately
vulnerable benchmark suite + the detection ledger replayed. Publish the honest
scorecard — catch rate by class, FP rate per rule, explicit out-of-scope column.
Converts the honest-ceiling doc from prose to numbers.
*Entry gate: ledger has enough history to score. Exit artifact: the scorecard (also the strongest post in the series).*

**Phase 2 — Let strangers use it.**
Stable v1.0 config surface, published GitHub Action, versioned rule packs,
install story that survives a non-author, contribution model (new rule accepted
only with fixture pair). External adoption is the endgame of evidence.
*Entry gate: Phase 1 scorecard exists — don't invite users onto unmeasured claims.*

**Phase 3 — Move up the supply chain.**
Gate verdicts become signed artifacts (sigstore); builds carry SLSA-style
provenance; "passed gate vX at commit Y" becomes third-party-verifiable.
Extends sbom.py toward attestation.
*Entry gate: A3 (signed releases) shipped and boring.*

**Phase 4 — The counsel tier (AI).**
The two-tier design from `ai-gateway-post-draft.md`: deterministic gate stays law,
model is advisory counsel — evidence-anchored findings, deterministic verifier,
canary findings per run, pinned model + temp 0 + prompt hash, ledger flywheel
(confirmed AI finding → candidate deterministic rule). Deliberately last: everything
before it is what makes an AI tier safe to add.
*Entry gate: Phases 1–2 done (the corpus, ledger, and verification culture it depends on).*

---

## Part D — Publish-in-public map

*Every shipped chunk produces a post. The improvement isn't done until it's documented.
Existing queue first: Post #2 (XSS) Jul 7, Post #3 (waiver story) Jul 14–16,
Post #4 (AI reviewer ≠ gate, drafted) Jul 21–23. Roadmap posts slot after, ~1/week max.*

| Shipped item | Post angle |
|---|---|
| A1 waiver expiry | "I made my own security exceptions expire" — acceptance decay; pairs with Post #3, and unblocks Post #4's 'expiring waivers' claim |
| A2 ledger + ceiling | "My scanner's honest scorecard: what it catches, what it can't" — claim-honesty as a feature |
| A4 canary checks | "Who tests the tests? Making a silent scanner impossible" |
| A5 hostile-repo model | "Can a malicious repo pass its own security gate?" — threat-modelling your own tooling |
| B1 CodeQL | "The free taint analysis most repos never turn on" — practical, high-reach |
| B2 semgrep graduation | "Promoting rules on evidence, not vibes" — the FP ledger pattern |
| B3 sink scanner | "When you can't follow the taint, gate the sink" — the XSS-pair lesson made enforceable (flagship of the series) |
| B4 Actions scanner | "Your CI is attack surface" — workflow injection primer |
| Phase 1 scorecard | Benchmark write-up — the credibility anchor for everything above |
| Phase 4 | The ai-gateway post + spec, already drafted |

**Post rules (from narrative doctrine):** verify every number against the live repo
on publish day; links in first comment; no Bastion specifics (named-unlinked);
never shipped-tense for unbuilt work; honest limits stated in the post itself.

---

## Chip order (when time exists, smallest-first)

1. **A2** ledger + ceiling doc — docs-only, POUR-compatible, no build-freeze conflict
2. **A5** hostile-repo threat model (docs half) — same
3. **A1** waiver expiry — first code item; small, closes a real hole, unblocks Post #4 claim
4. **B1** CodeQL — rider on next fleet touch
5. **A4** canary checks
6. **B4** Actions scanner
7. **B2** semgrep pipeline (then calendar time does the work)
8. **A6** chaos harness · **A3** signing/pin — with the next release
9. **B3** sink scanner — the first *substantial* build; deserves a fresh, focused session
10. **B6** fuzz template
11. Part C phases, in order, each behind its entry gate
