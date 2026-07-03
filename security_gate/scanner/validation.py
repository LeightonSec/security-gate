import re
from pathlib import Path

from .base import BaseScanner, Finding, Severity

# _ENTRY_POINTS: (pattern, detail, severity)
# yaml.load is CRITICAL (arbitrary code execution if input is attacker-controlled).
# All other entry points are HIGH (missing validation boundary).
_ENTRY_POINTS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"request\.get_json\s*\("),
     "Flask request.get_json() — validate with Pydantic before use",  # gate: ignore - scanner detail string, not a runtime call
     Severity.HIGH),
    (re.compile(r"request\.(form|args|data|json)\b"),
     "Flask request input — validate with Pydantic before use",
     Severity.HIGH),
    (re.compile(r"response\.json\s*\(\s*\)"),
     "External API response.json() used directly — validate schema before processing",  # gate: ignore - scanner detail string, not a runtime call
     Severity.HIGH),
    (re.compile(r"json\.loads\s*\("),
     "json.loads on external data — validate structure before use",
     Severity.HIGH),
    (re.compile(r"yaml\.safe_load\s*\("),
     "yaml.safe_load — validate schema before use",
     Severity.HIGH),
    (re.compile(r"yaml\.load\s*\("),
     "yaml.load (unsafe) — arbitrary code execution if input is attacker-controlled; "  # gate: ignore - scanner detail string, not a runtime call
     "use yaml.safe_load and validate schema",
     Severity.CRITICAL),
]

# Validator methods recognised as a validation boundary when called on a value.
# 'load' is deliberately excluded — yaml.load / json.load / pickle.load are sinks,
# not validators, and would mask findings.
_VALIDATOR_METHODS = frozenset({
    "model_validate", "model_validate_json", "parse_obj", "parse_raw", "from_orm",
})

# A CapWords constructor is treated as a validation boundary only when its name
# follows the model/schema naming convention. This is deliberately narrow: "any
# CapWords call" would let non-validating constructors (Dict, Request, Response,
# Exception, Logger, Path, ...) suppress real findings. Names outside this set err
# toward a finding (the safe direction for a gate) and can be accepted via
# accepted-findings.toml if they genuinely validate.
_MODEL_SUFFIXES = (
    "Model", "Schema", "Create", "Update", "Filter", "Params",
    "Payload", "Body", "Input", "Form", "Config", "Settings", "Query", "DTO",
)
_MODEL_NAME_RE = r"[A-Z]\w*(?:" + "|".join(_MODEL_SUFFIXES) + r")"

# Same-line validation usage — instantiation, validator method, or schema library.
# Used only to suppress a finding whose entry point shares a line with the validation
# call (e.g. `validate(request.json())`).
_VALIDATION_USAGE = re.compile(
    r"(?:BaseModel|Schema|Validator|TypedDict)\s*\(|"
    r"\.(?:parse_obj|parse_raw|model_validate|model_validate_json|from_orm)\s*\(|"
    r"\bvalidate\w*\s*\(|"
    r"marshmallow\.\w+|cerberus\.\w+|voluptuous\.\w+",
    re.IGNORECASE,
)

# A simple `var = ...` assignment (not `==`, not an annotated target).
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(?!=)")

# Identifier (optionally dotted) immediately preceding a '(' — used to classify the
# call that an open paren belongs to.
_NAME_BEFORE_PAREN = re.compile(r"([A-Za-z_][\w.]*)\s*$")

_VALIDATION_WINDOW = 5  # lines forward from an assignment to trace var → validator


class ValidationScanner(BaseScanner):
    """Flags attacker-controlled entry points that reach business logic without a
    schema-validation boundary.

    Suppression is intentionally precise to avoid masking real findings:

      1. *Enclosing validator call* — the entry point is an argument inside an open
         validator/model constructor call (possibly spanning several lines), e.g. a
         ``TicketFilter(...)`` built from query-string fields, or a
         ``Model.model_validate(...)`` wrapping an external response. Detected via a
         paren-tracking pass, so it works regardless of how many lines the call spans.

      2. *Variable flows into a validator* — a value read from the request, then
         passed within the window to ``TicketCreate(**data)`` / a
         ``Model.model_validate(data)`` call. The check is bound to the assigned
         variable, so validation of an *unrelated* value in the window cannot
         suppress the finding.

      3. *Same-line validator wrap* — a ``validate(...)`` call on the entry-point line.

    Manual guard-clause validation (``if not data``, ``isinstance(...)`` + early
    return) is deliberately NOT treated as validation: a regex cannot distinguish an
    adequate guard from a weak presence check, and auto-suppressing it would create
    false negatives in a security gate. Those cases stay as findings, to be human-
    reviewed and accepted via accepted-findings.toml when adequate.
    """

    name = "missing_validation"

    def scan(self, root: Path) -> list[Finding]:
        findings = []
        for py_file in self._py_files(root):
            lines = self._read_lines(py_file)
            if lines is None:
                continue
            findings.extend(self._scan_file(root, py_file, lines))
        return findings

    def _scan_file(self, root: Path, py_file: Path, lines: list[str]) -> list[Finding]:
        findings = []
        rel = self._rel(root, py_file)
        inside_validator, depth_at_start = self._paren_context(lines)

        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or self._suppressed(line):
                continue

            for pattern, detail, severity in _ENTRY_POINTS:
                if not pattern.search(line):
                    continue

                if self._is_validated(lines, idx, line, inside_validator, depth_at_start):
                    break  # validated — not a finding

                findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    file=rel,
                    line=idx + 1,
                    match=stripped[:120],
                    detail=detail,
                    checklist_item="PHASE-1-1: Schema validation on all inputs",
                ))
                break  # one finding per line

        return findings

    def _is_validated(
        self,
        lines: list[str],
        idx: int,
        line: str,
        inside_validator: list[bool],
        depth_at_start: list[int],
    ) -> bool:
        # (1) entry point is an argument inside an open validator/model call.
        if inside_validator[idx]:
            return True

        # (2) same-line validator wrap, e.g. validate(request.json()).
        if _VALIDATION_USAGE.search(line):
            return True

        # (3) variable-precise: an assignment whose bound variable flows into a
        #     validator/model call within the forward window. Only when not already
        #     inside an open call (otherwise a leading `name=` is a kwarg, not a bind).
        if depth_at_start[idx] == 0:
            m = _ASSIGN.match(line)
            if m:
                var = m.group(1)
                window = "\n".join(lines[idx : idx + _VALIDATION_WINDOW + 1])
                if re.search(self._var_validator_re(var), window):
                    return True

        return False

    @staticmethod
    def _var_validator_re(var: str) -> str:
        v = re.escape(var)
        return (
            # Model.model_validate(var) / parse_obj(var) / validate(var)
            r"(?:model_validate|model_validate_json|parse_obj|parse_raw|from_orm|validate\w*)"
            r"\s*\(\s*(?:\*\*\s*)?" + v + r"\b"
            # ModelCreate(var) / ModelCreate(**var) — model-named constructor only
            r"|(?<![\w.])" + _MODEL_NAME_RE + r"\s*\(\s*(?:\*\*\s*)?" + v + r"\b"
        )

    def _paren_context(self, lines: list[str]) -> tuple[list[bool], list[int]]:
        """For each line, compute whether it begins inside an open validator/model
        call, and the paren-nesting depth at its start.

        Single forward pass over characters tracking a stack of booleans (one per open
        paren) recording whether each open paren belongs to a validator/model call.
        String and comment contents are not parsed out — an acceptable imprecision,
        consistent with the line-oriented heuristics used across the other scanners.
        """
        inside_validator: list[bool] = []
        depth_at_start: list[int] = []
        validator_stack: list[bool] = []
        depth = 0

        for line in lines:
            inside_validator.append(any(validator_stack))
            depth_at_start.append(depth)
            for pos, ch in enumerate(line):
                if ch == "(":
                    nm = _NAME_BEFORE_PAREN.search(line[:pos])
                    validator_stack.append(self._is_validator_name(nm.group(1) if nm else ""))
                    depth += 1
                elif ch == ")":
                    if validator_stack:
                        validator_stack.pop()
                    if depth > 0:
                        depth -= 1

        return inside_validator, depth_at_start

    @staticmethod
    def _is_validator_name(name: str) -> bool:
        if not name:
            return False
        last = name.split(".")[-1]
        if last in _VALIDATOR_METHODS or last.startswith("validate"):
            return True
        # Model-named CapWords constructor (TicketCreate, OrderSchema, ...) — NOT
        # arbitrary CapWords, so Dict/Request/Response/Exception don't suppress.
        return last[:1].isupper() and last.endswith(_MODEL_SUFFIXES)
