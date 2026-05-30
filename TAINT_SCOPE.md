# Taint Analysis Scope — v1.x Boundary Decision

**Date:** 2026-05-30  
**Status:** Accepted — v1.x boundary formalised

---

## Background

An LLM council review of the scanner architecture identified two gaps explicitly out of scope for regex-based scanners:

1. **Cross-function taint tracking** — a source (e.g. `request.json`) in one function, a sink (e.g. `eval()`) in another, with user-controlled data passed between them via arguments or return values.
2. **Cross-file config analysis** — an insecure setting defined in one file (e.g. `DEBUG = True` in `config.py`) consumed in another (e.g. `app.run(debug=app.config['DEBUG'])` in `app.py`).

The council's stated next step: a scope document and decision before either gap is addressed. This is that document.

---

## What v1.x covers

SemgrepScanner (shipped 2026-05-30) extended coverage from regex pattern matching to **intra-procedural taint analysis** — tracking data flow through variable reassignment chains within a single function body. This closes the gap that regex scanners miss:

```python
# regex scanner: misses this (no direct sink call on request.json)
# SemgrepScanner: catches this (taint tracks x → y → eval)
data = request.json
cmd = data['command']
eval(cmd)
```

Three taint rules are active: LLM injection, command injection, SSRF. All operate within a single function scope.

---

## Options evaluated for cross-function and cross-file gaps

### Option A — semgrep Pro (interprocedural taint)

semgrep Pro adds cross-function taint tracking to the open-source engine. It can follow a tainted value from a source function through call chains to a sink in a different function.

**Strengths:** Same rule syntax as the existing bundled rules; low migration cost; purpose-built for this gap.  
**Weaknesses:** Paid licence required; not viable for an open-source portfolio tool with no billing model. Closes cross-function taint but not cross-file config analysis (different problem domain).  
**Decision:** Rejected — licence cost incompatible with an open-source, zero-dependency design goal.

### Option B — CodeQL

CodeQL provides full interprocedural and cross-file dataflow analysis via a query language (QL). Used by GitHub Advanced Security.

**Strengths:** Extremely thorough; well-documented; free for open-source repos via GitHub Actions.  
**Weaknesses:** Significant complexity overhead — QL is a separate language to learn and maintain; database extraction step required before queries run; scan times measured in minutes not seconds; would require a parallel analysis pipeline alongside the existing scanner. Overkill for the threat model of this tool's target repos.  
**Decision:** Rejected — complexity and runtime cost disproportionate to the gap being closed.

### Option C — Pysa (Facebook/Meta)

Pysa is a Python-specific taint analysis tool built on Pyre. Designed for cross-function and cross-file taint.

**Strengths:** Free; interprocedural; designed for production Python codebases.  
**Weaknesses:** Python only — security-gate scans multi-language repos; Pysa requires a type-checked codebase (Pyre must resolve types); significant configuration overhead for taint sources/sinks; not actively maintained at the cadence needed for dependency confidence.  
**Decision:** Rejected — Python-only constraint and configuration overhead are blockers.

### Option D — Accept as out-of-scope for v1.x, document the boundary

Define the v1.x analysis boundary explicitly. Document what the tool covers, what it does not cover, and why. Require human review for the patterns the tool cannot reach.

**Strengths:** Honest about tool limits; keeps the codebase simple and auditable; no new dependencies; forces teams to do manual review for the hard cases (which they should be doing anyway for a security gate).  
**Decision:** **Accepted.**

---

## v1.x boundary — formal statement

security-gate performs **intra-procedural static analysis**. For each scanner:

- Regex scanners detect dangerous patterns at the call site.
- SemgrepScanner extends this to intra-function taint — tracking user-controlled data through reassignment chains within a single function body.

**The following are out of scope for v1.x:**

| Gap | Why out of scope | Mitigation |
|-----|-----------------|------------|
| Cross-function taint | Requires interprocedural analysis; available tools either require a paid licence (semgrep Pro) or introduce complexity disproportionate to the threat model (CodeQL) | Manual code review checklist item in gate sign-off |
| Cross-file config analysis | Requires whole-program dataflow; distinct from taint analysis; no lightweight tool covers this well for multi-language repos | Manual review of config files as part of gate checklist |

These gaps are known, documented, and accepted. They are not oversights.

---

## What this means in practice

A codebase can pass the gate with a cross-function injection path that the scanner cannot see. The gate sign-off process must include:

- Review of functions that accept user-controlled arguments and pass them to other functions
- Review of config files for insecure defaults that reach runtime sinks in other files

This is a manual step. The gate's checklist mechanism exists precisely to hold open the items that automation cannot close.

---

## Revisiting this decision

Re-evaluate if:

- semgrep Pro becomes available at no cost for open-source projects
- A lightweight cross-file config analysis tool emerges that fits the zero-dependency design goal
- The tool's target repos grow to a scale where the false-negative rate from cross-function taint becomes a material risk

Until then, v1.x boundary stands.
