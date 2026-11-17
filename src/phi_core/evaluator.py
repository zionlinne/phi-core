"""The feasibility operator Phi(T, S, E) -> {TRUE, FALSE, UNKNOWN}.

Three-valued extension of Phi(p, sigma) = prod_i I[C_i(p, sigma)] over the
necessary hard constraints applicable at a checkpoint:

1. any hard constraint VIOLATED on valid evidence / state  -> FALSE
2. otherwise any hard constraint UNRESOLVED, or a contract-level
   precondition unresolved (scope not declared complete, task absent
   from S, ...)                                              -> UNKNOWN
3. otherwise (all SATISFIED; an empty set only when the scope is
   explicitly declared complete)                             -> TRUE

No weights, probabilities or model calls. Soft constraints are evaluated and
reported separately and never influence the verdict. Only TRUE releases.

``PhiEngine.judge`` is pure: same (T, S, verification results, checkpoint)
-> same result, no filesystem, clock or randomness. ``PhiEngine.evaluate``
first runs the Evidence Verifier, which observes the workspace (an explicit
input) and the explicit time ``S.now``.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import freeze, parse_time, safe_hash_obj
from .contracts import (
    CHECKPOINTS,
    CONTRACT_VERSION,
    LEGACY_CONTRACT_VERSION,
    CompiledConstraint,
    compile_constraints,
    contract_hash,
    semantic_errors,
)
from .evidence import (
    TrustStore,
    VerificationContext,
    VerificationResult,
    VerifierRegistry,
    VStatus,
    default_verifier_registry,
    verify_evidence,
)
from .predicates import (
    RESERVED_NON_EXECUTABLE,
    Outcome,
    PredicateRegistry,
    Status,
    default_predicate_registry,
)
from .schemas import schema_errors

EVALUATOR_VERSION = "phi-core/1.0.2"
DEFAULT_MAX_AGE_SECONDS = 3600


class Verdict(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


ACTIONS = {
    Verdict.TRUE: "PROCEED",
    Verdict.FALSE: "BLOCK",
    Verdict.UNKNOWN: "PAUSE_REQUEST_EVIDENCE",
}


@dataclass(frozen=True)
class ConstraintResult:
    constraint_id: str
    kind: str
    predicate_type: str
    origin: str
    status: Status
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()
    detail: str = ""
    statement: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "kind": self.kind,
            "predicate_type": self.predicate_type,
            "origin": self.origin,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
            "statement": self.statement,
        }


@dataclass(frozen=True)
class EvaluationResult:
    verdict: Verdict
    checkpoint: str
    task_id: str | None
    contract_hash: str
    state_hash: str
    evidence_hash: str
    evaluator_version: str
    reason_codes: tuple[str, ...]
    constraint_results: tuple[ConstraintResult, ...] = ()
    soft_results: tuple[ConstraintResult, ...] = ()
    evidence_results: tuple[VerificationResult, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    unmatched_evidence: tuple[str, ...] = ()

    @property
    def release(self) -> bool:
        return self.verdict is Verdict.TRUE

    @property
    def action(self) -> str:
        return ACTIONS[self.verdict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "release": self.release,
            "action": self.action,
            "checkpoint": self.checkpoint,
            "task_id": self.task_id,
            "contract_hash": self.contract_hash,
            "state_hash": self.state_hash,
            "evidence_hash": self.evidence_hash,
            "evaluator_version": self.evaluator_version,
            "reason_codes": list(self.reason_codes),
            "constraint_results": [r.to_dict() for r in self.constraint_results],
            "soft_results": [r.to_dict() for r in self.soft_results],
            "evidence_results": [r.to_dict() for r in self.evidence_results],
            "missing_evidence": list(self.missing_evidence),
            "unmatched_evidence": list(self.unmatched_evidence),
        }


@dataclass(frozen=True)
class PlanResult:
    verdict: Verdict
    reason_codes: tuple[str, ...]
    plan_issues: tuple[Mapping[str, Any], ...]
    task_results: Mapping[str, EvaluationResult]
    plan_hash: str
    state_hash: str
    evidence_hash: str
    evaluator_version: str = EVALUATOR_VERSION

    @property
    def release(self) -> bool:
        return self.verdict is Verdict.TRUE

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "release": self.release,
            "action": ACTIONS[self.verdict],
            "checkpoint": "PLAN",
            "plan_hash": self.plan_hash,
            "state_hash": self.state_hash,
            "evidence_hash": self.evidence_hash,
            "evaluator_version": self.evaluator_version,
            "reason_codes": list(self.reason_codes),
            "plan_issues": [dict(i) for i in self.plan_issues],
            "task_results": {k: v.to_dict() for k, v in sorted(self.task_results.items())},
        }


def _state_now(state: Any):
    if isinstance(state, Mapping):
        try:
            return parse_time(state.get("now"))
        except ValueError:
            return None
    return None


def _check_checkpoint(checkpoint: str) -> None:
    if checkpoint not in CHECKPOINTS:
        raise ValueError(f"checkpoint must be one of {CHECKPOINTS}, got {checkpoint!r}")


def _contract_hash_any(contract: Any) -> str:
    if isinstance(contract, Mapping):
        return safe_hash_obj({k: v for k, v in contract.items() if k != "integrity"})
    return safe_hash_obj(contract)


def _sorted_unique(codes) -> tuple[str, ...]:
    return tuple(sorted(set(codes)))


def _binding_problem(binding: Any, context, reobserved: bool = False) -> str | None:
    """Evidence is usable only for the task (and, when stated, the contract hash
    and checkpoints) it is bound to. Cross-task use is rejected by default.

    Unbound evidence is tolerated only when ``reobserved``: its verifier recomputed
    the value from this evaluation's workspace, so nothing is carried over from
    another task. Claims (attestations, custom verifiers) must be bound."""
    task_id, c_hash, checkpoint = context
    if binding is None and reobserved:
        return None
    if not isinstance(binding, Mapping) or "task_id" not in binding:
        return "EVIDENCE_NOT_BOUND_TO_TASK"
    if binding["task_id"] != task_id:
        return "EVIDENCE_BOUND_TO_OTHER_TASK"
    if "contract_hash" in binding and binding["contract_hash"] != c_hash:
        return "EVIDENCE_BOUND_TO_OTHER_CONTRACT"
    if "checkpoints" in binding and checkpoint not in binding["checkpoints"]:
        return "EVIDENCE_NOT_BOUND_TO_CHECKPOINT"
    return None


class PhiEngine:
    def __init__(self, predicates: PredicateRegistry | None = None,
                 verifiers: VerifierRegistry | None = None,
                 evaluator_version: str = EVALUATOR_VERSION):
        self.predicates = predicates if predicates is not None else default_predicate_registry()
        self.verifiers = verifiers if verifiers is not None else default_verifier_registry()
        self.evaluator_version = evaluator_version

    # ------------------------------------------------------------------ verification stage

    def verify(self, state: Any, evidence: Any, *, workspace: str | Path | None = None,
               trust_store: TrustStore | None = None) -> list[VerificationResult]:
        ctx = VerificationContext(
            now=_state_now(state),
            workspace=Path(workspace) if workspace is not None else None,
            trust_store=trust_store if trust_store is not None else TrustStore(),
        )
        return verify_evidence(copy.deepcopy(evidence), ctx, self.verifiers)

    def evaluate(self, contract: Any, state: Any, evidence: Any, *, checkpoint: str,
                 workspace: str | Path | None = None,
                 trust_store: TrustStore | None = None) -> EvaluationResult:
        _check_checkpoint(checkpoint)
        contract, state, evidence = copy.deepcopy(contract), copy.deepcopy(state), copy.deepcopy(evidence)
        vresults = self.verify(state, evidence, workspace=workspace, trust_store=trust_store)
        return self.judge(contract, state, vresults, checkpoint=checkpoint,
                          evidence_hash=safe_hash_obj(evidence))

    # ------------------------------------------------------------------ pure judgement

    def judge(self, contract: Any, state: Any, verification_results: Sequence[VerificationResult], *,
              checkpoint: str, evidence_hash: str | None = None) -> EvaluationResult:
        _check_checkpoint(checkpoint)
        contract = copy.deepcopy(contract)
        state = copy.deepcopy(state)
        vresults = tuple(verification_results)
        c_hash = _contract_hash_any(contract)
        s_hash = safe_hash_obj(state)
        e_hash = evidence_hash if evidence_hash is not None else safe_hash_obj([r.to_dict() for r in vresults])
        task_id = contract.get("task_id") if isinstance(contract, Mapping) and isinstance(contract.get("task_id"), str) else None

        def finish(verdict, reasons, hard=(), soft=(), missing=(), unmatched=()):
            return EvaluationResult(
                verdict=verdict, checkpoint=checkpoint, task_id=task_id, contract_hash=c_hash,
                state_hash=s_hash, evidence_hash=e_hash, evaluator_version=self.evaluator_version,
                reason_codes=_sorted_unique(reasons), constraint_results=tuple(hard),
                soft_results=tuple(soft), evidence_results=vresults, missing_evidence=tuple(missing),
                unmatched_evidence=tuple(unmatched),
            )

        if not isinstance(contract, Mapping):
            return finish(Verdict.UNKNOWN, ["CONTRACT_SCHEMA_INVALID"])
        if contract.get("contract_version") == LEGACY_CONTRACT_VERSION:
            return finish(Verdict.UNKNOWN, ["CONTRACT_VERSION_UNSUPPORTED"])
        if contract.get("contract_version") != CONTRACT_VERSION or schema_errors("contract", contract):
            return finish(Verdict.UNKNOWN, ["CONTRACT_SCHEMA_INVALID"])
        if semantic_errors(contract):
            return finish(Verdict.UNKNOWN, ["CONTRACT_SEMANTIC_INVALID"])
        integrity = contract.get("integrity")
        if integrity is not None and integrity.get("contract_hash") != contract_hash(contract):
            return finish(Verdict.UNKNOWN, ["CONTRACT_INTEGRITY_MISMATCH"])
        if not isinstance(state, Mapping) or schema_errors("state", state):
            return finish(Verdict.UNKNOWN, ["STATE_SCHEMA_INVALID"])
        pin = state.get("contract_pins", {}).get(task_id)
        if pin is not None and pin != c_hash:
            return finish(Verdict.UNKNOWN, ["CONTRACT_PIN_MISMATCH"])
        if any("EVIDENCE_PAYLOAD_NOT_A_LIST" in r.reason_codes for r in vresults):
            return finish(Verdict.UNKNOWN, ["EVIDENCE_PAYLOAD_INVALID"])

        global_unresolved = []
        if task_id not in state["tasks"]:
            global_unresolved.append("TASK_NOT_IN_STATE")
        if contract["constraint_scope"].get("complete") is not True:
            global_unresolved.append("SCOPE_NOT_DECLARED_COMPLETE")

        compiled = compile_constraints(contract)
        known = {c.constraint_id for c in compiled}
        unmatched = sorted(r.evidence_id for r in vresults if r.constraint_id not in known)
        now = parse_time(state["now"])
        policy = contract.get("evidence_policy", {})

        frozen_state = freeze(state)
        by_constraint: dict[str, list[VerificationResult]] = {}
        for r in vresults:
            by_constraint.setdefault(r.constraint_id, []).append(r)
        hard, soft = [], []
        for c in compiled:
            if checkpoint not in c.checkpoints:
                continue
            res = self._eval_constraint(c, frozen_state, by_constraint.get(c.constraint_id, []), now, policy,
                                        (task_id, c_hash, checkpoint))
            (hard if c.kind == "hard" else soft).append(res)

        violated = [r for r in hard if r.status is Status.VIOLATED]
        unresolved_ = [r for r in hard if r.status is Status.UNRESOLVED]
        missing = sorted(
            r.constraint_id for r in unresolved_ if any(code.startswith("EVIDENCE_") for code in r.reason_codes)
        )
        if violated:
            reasons = ["VERIFIED_HARD_VIOLATION"] + [code for r in violated for code in r.reason_codes]
            return finish(Verdict.FALSE, reasons, hard, soft, missing, unmatched)
        if unresolved_ or global_unresolved:
            reasons = ["UNRESOLVED_REQUIRED"] + global_unresolved + [code for r in unresolved_ for code in r.reason_codes]
            return finish(Verdict.UNKNOWN, reasons, hard, soft, missing, unmatched)
        reasons = ["ALL_REQUIRED_SATISFIED"]
        if not hard:
            reasons.append("NO_APPLICABLE_HARD_CONSTRAINTS_SCOPE_DECLARED_COMPLETE")
        return finish(Verdict.TRUE, reasons, hard, soft, missing, unmatched)

    def _eval_constraint(self, c: CompiledConstraint, state, candidates, now, policy,
                         context=(None, None, None)) -> ConstraintResult:
        """``state`` is a read-only frozen view; ``candidates`` are the verifier results
        whose constraint_id equals this constraint's id; ``context`` is
        (task_id, contract_hash, checkpoint) that evidence bindings must match."""
        def mk(outcome: Outcome, refs=()):
            return ConstraintResult(
                constraint_id=c.constraint_id, kind=c.kind, predicate_type=c.predicate_type,
                origin=c.origin, status=outcome.status, reason_codes=_sorted_unique(outcome.reason_codes),
                evidence_refs=tuple(refs), detail=outcome.detail, statement=c.statement,
            )

        pred = self.predicates.get(c.predicate_type)
        if pred is None:
            codes = ["PREDICATE_NOT_EXECUTABLE"]
            if c.predicate_type in RESERVED_NON_EXECUTABLE:
                codes.append("NATURAL_LANGUAGE_NOT_EXECUTABLE")
            return mk(Outcome(Status.UNRESOLVED, tuple(codes), f"no registered predicate {c.predicate_type!r}"))
        params = copy.deepcopy(dict(c.params))
        perrs = pred.param_errors(params)
        if perrs:
            return mk(Outcome(Status.UNRESOLVED, ("PREDICATE_PARAMS_INVALID",), "; ".join(perrs)))

        if pred.kind == "state":
            return mk(self._safe_call(pred.evaluate, params, state))

        allowed = c.verifiers if c.verifiers is not None else tuple(pred.default_verifiers)
        max_age = c.max_age_seconds if c.max_age_seconds is not None else policy.get(
            "default_max_age_seconds", DEFAULT_MAX_AGE_SECONDS)
        refs = sorted(r.evidence_id for r in candidates)
        ignored: set[str] = set()
        usable = []
        for r in candidates:
            if r.status is not VStatus.VERIFIED:
                ignored.add(f"EVIDENCE_{r.status.value}")
                ignored.update(r.reason_codes)
                continue
            if r.verifier_id not in allowed:
                ignored.add("EVIDENCE_VERIFIER_NOT_ALLOWED")
                continue
            verifier = self.verifiers.get(r.verifier_id)
            binding_code = _binding_problem(r.binding, context, getattr(verifier, "reobserves", False) is True)
            if binding_code is not None:
                ignored.add(binding_code)
                continue
            try:
                ts = parse_time(r.timestamp)
            except ValueError:
                ignored.add("EVIDENCE_TIMESTAMP_INVALID")
                continue
            if ts > now:
                ignored.add("EVIDENCE_TIMESTAMP_IN_FUTURE")
                continue
            if (now - ts).total_seconds() > max_age:
                ignored.add("EVIDENCE_STALE")
                continue
            try:
                matches = bool(pred.subject_matches(params, copy.deepcopy(r.observed)))
            except Exception:  # noqa: BLE001
                matches = False
            if not matches:
                ignored.add("EVIDENCE_SUBJECT_MISMATCH")
                continue
            usable.append(r)

        if len(usable) < c.min_items:
            code = "EVIDENCE_MISSING" if not usable else "EVIDENCE_INSUFFICIENT"
            return mk(Outcome(Status.UNRESOLVED, (code, *sorted(ignored))), refs)

        judged = [(r, self._safe_call(pred.judge, params, copy.deepcopy(r.observed))) for r in usable]
        note = ("IGNORED_UNUSABLE_EVIDENCE",) if ignored else ()
        statuses = {o.status for _, o in judged}
        if len(statuses) == 1:
            status = statuses.pop()
            codes = tuple(code for _, o in judged for code in o.reason_codes) + note
            detail = "; ".join(sorted({o.detail for _, o in judged if o.detail}))
            return mk(Outcome(status, codes, detail), refs)

        conflict = policy.get("conflict_resolution", {"type": "none"})
        if conflict.get("type") == "source_precedence":
            order = conflict["order"]
            ranked = [(order.index(r.source), r, o) for r, o in judged if r.source in order]
            if ranked:
                best = min(rank for rank, _, _ in ranked)
                group = [o for rank, _, o in ranked if rank == best]
                group_statuses = {o.status for o in group}
                if len(group_statuses) == 1:
                    status = group_statuses.pop()
                    codes = ("CONFLICT_RESOLVED_BY_SOURCE_PRECEDENCE",) + tuple(
                        code for o in group for code in o.reason_codes) + note
                    return mk(Outcome(status, codes, f"source={order[best]}"), refs)
        return mk(Outcome(Status.UNRESOLVED, ("EVIDENCE_CONFLICT",) + note,
                          "verified evidence disagrees: " + ", ".join(sorted(s.value for s in statuses))), refs)

    @staticmethod
    def _safe_call(fn, *args) -> Outcome:
        try:
            out = fn(*args)
        except Exception as exc:  # noqa: BLE001 - a failing predicate must never yield TRUE
            return Outcome(Status.UNRESOLVED, ("PREDICATE_ERROR",), type(exc).__name__)
        if not isinstance(out, Outcome) or not isinstance(out.status, Status):
            return Outcome(Status.UNRESOLVED, ("PREDICATE_RESULT_INVALID",))
        return out

    # ------------------------------------------------------------------ plan level

    def evaluate_plan(self, contracts: Sequence[Any], state: Any, evidence: Any, *,
                      workspace: str | Path | None = None,
                      trust_store: TrustStore | None = None) -> PlanResult:
        contracts = copy.deepcopy(list(contracts))
        state = copy.deepcopy(state)
        evidence = copy.deepcopy(evidence)
        vresults = self.verify(state, evidence, workspace=workspace, trust_store=trust_store)
        issues: list[dict[str, Any]] = []

        def issue(status: Status, code: str, **info):
            issues.append({"status": status.value, "reason_code": code, **info})

        valid = []
        for index, c in enumerate(contracts):
            if (isinstance(c, Mapping) and c.get("contract_version") == CONTRACT_VERSION
                    and not schema_errors("contract", c) and not semantic_errors(c)):
                valid.append(c)
            else:
                issue(Status.UNRESOLVED, "CONTRACT_SCHEMA_INVALID", index=index)
        if not contracts:
            issue(Status.UNRESOLVED, "EMPTY_PLAN")

        ids = [c["task_id"] for c in valid]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            issue(Status.VIOLATED, "DUPLICATE_TASK_ID", task_id=dup)
        by_id = {c["task_id"]: c for c in valid}
        state_tasks = state.get("tasks", {}) if isinstance(state, Mapping) and isinstance(state.get("tasks"), Mapping) else {}

        for c in valid:
            tid = c["task_id"]
            for dep in c.get("dependencies", []):
                if dep not in by_id and dep not in state_tasks:
                    issue(Status.UNRESOLVED, "DEPENDENCY_UNDECLARED", task_id=tid, dependency=dep)
            parent = c.get("parent_task_id")
            if parent is not None:
                if parent in by_id:
                    if tid not in by_id[parent].get("subtasks", []):
                        issue(Status.VIOLATED, "PARENT_CHILD_INCONSISTENT", task_id=tid, parent=parent)
                elif parent not in state_tasks:
                    issue(Status.UNRESOLVED, "PARENT_UNDECLARED", task_id=tid, parent=parent)
            for sub in c.get("subtasks", []):
                if sub in by_id:
                    if by_id[sub].get("parent_task_id") != tid:
                        issue(Status.VIOLATED, "PARENT_CHILD_INCONSISTENT", task_id=sub, parent=tid)
                elif sub not in state_tasks:
                    issue(Status.UNRESOLVED, "SUBTASK_UNDECLARED", task_id=tid, subtask=sub)

        cycle = _find_cycle({tid: [d for d in c.get("dependencies", []) if d in by_id] for tid, c in by_id.items()})
        if cycle:
            issue(Status.VIOLATED, "DEPENDENCY_CYCLE", cycle=cycle)

        owners: dict[str, set[str]] = {}
        for c in valid:
            for o in c.get("outputs", []):
                owners.setdefault(o["path"], set()).add(c["task_id"])
        for path, tasks in sorted(owners.items()):
            if len(tasks) > 1:
                issue(Status.VIOLATED, "OUTPUT_OWNERSHIP_CONFLICT", path=path, tasks=sorted(tasks))

        e_hash = safe_hash_obj(evidence)
        task_results = {tid: self.judge(c, state, vresults, checkpoint="PLAN", evidence_hash=e_hash)
                        for tid, c in by_id.items()}

        if any(i["status"] == "VIOLATED" for i in issues) or any(r.verdict is Verdict.FALSE for r in task_results.values()):
            verdict = Verdict.FALSE
        elif issues or any(r.verdict is Verdict.UNKNOWN for r in task_results.values()):
            verdict = Verdict.UNKNOWN
        else:
            verdict = Verdict.TRUE
        reasons = [i["reason_code"] for i in issues] + [
            f"TASK_{r.verdict.value}:{tid}" for tid, r in task_results.items() if r.verdict is not Verdict.TRUE]
        if verdict is Verdict.TRUE:
            reasons.append("ALL_REQUIRED_SATISFIED")
        return PlanResult(
            verdict=verdict, reason_codes=_sorted_unique(reasons),
            plan_issues=tuple(sorted(issues, key=lambda i: safe_hash_obj(i))),
            task_results=task_results,
            plan_hash=safe_hash_obj([_contract_hash_any(c) for c in contracts]),
            state_hash=safe_hash_obj(state), evidence_hash=e_hash,
            evaluator_version=self.evaluator_version,
        )


def _find_cycle(graph: Mapping[str, list[str]]) -> list[str] | None:
    WHITE, GREY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}
    stack: list[str] = []

    def visit(n):
        color[n] = GREY
        stack.append(n)
        for m in sorted(graph.get(n, [])):
            if color.get(m) == GREY:
                return stack[stack.index(m):] + [m]
            if color.get(m) == WHITE:
                found = visit(m)
                if found:
                    return found
        stack.pop()
        color[n] = BLACK
        return None

    for n in sorted(graph):
        if color[n] == WHITE:
            found = visit(n)
            if found:
                return found
    return None


_DEFAULT_ENGINE: PhiEngine | None = None


def default_engine() -> PhiEngine:
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = PhiEngine()
    return _DEFAULT_ENGINE


def evaluate(contract: Any, state: Any, evidence: Any, *, checkpoint: str,
             workspace: str | Path | None = None, trust_store: TrustStore | None = None,
             engine: PhiEngine | None = None) -> EvaluationResult:
    """Phi(T, S, E) at ``checkpoint``. See module docstring."""
    return (engine or default_engine()).evaluate(
        contract, state, evidence, checkpoint=checkpoint, workspace=workspace, trust_store=trust_store)
