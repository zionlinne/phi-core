"""In-process execution gate and generic Harness Adapter.

Supported execution entries (``PhiGate.guard``, ``GateSession.preflight/step/
commit`` with an ``action``, ``GatedRunner.run``, ``phi gate-exec``) re-evaluate
Phi with the *latest* state and evidence immediately before running the
action, and run it only when the verdict is TRUE. FALSE raises ``GateBlocked``,
UNKNOWN raises ``GateNeedsEvidence``; the action is not called in either case.

Boundary: this is an in-process library gate. It cannot stop code that never
calls it (another thread, process or user writing files directly, or a host
that patches the library). OS-level isolation (sandboxing, permissions,
separate service) is the host's responsibility.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .canonical import canonical_json
from .contracts import CHECKPOINTS
from .evaluator import EvaluationResult, PhiEngine, Verdict


class GateDenied(Exception):
    def __init__(self, decision: "Decision"):
        self.decision = decision
        super().__init__(f"{decision.result.verdict.value} at {decision.result.checkpoint}: "
                         f"{', '.join(decision.result.reason_codes)}")


class GateBlocked(GateDenied):
    """Verdict FALSE: verified hard-constraint violation."""


class GateNeedsEvidence(GateDenied):
    """Verdict UNKNOWN: paused until evidence / state resolves."""


class DecisionInvalid(Exception):
    pass


class GateSequenceError(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    result: EvaluationResult
    token: str
    audit_record_hash: str | None = None

    @property
    def release(self) -> bool:
        return self.result.release

    @property
    def action(self) -> str:
        return self.result.action

    def to_dict(self) -> dict[str, Any]:
        return {**self.result.to_dict(), "token": self.token, "audit_record_hash": self.audit_record_hash}


def _resolve(value: Any) -> Any:
    return value() if callable(value) else value


class EvidenceProviderError(TypeError):
    """The evidence provider's call signature cannot be determined, so the gate
    cannot know whether it would receive the checkpoint. Nothing is released."""


def _checkpoint_call(fn: Callable[..., Any]) -> str:
    """How to hand the checkpoint to a provider: "positional", "keyword" or "none".

    Any parameter that can receive the checkpoint receives it, defaulted or not:
    the first positional slot, ``*args``, a keyword-only ``checkpoint`` or
    ``**kwargs``. Only a provider with no parameter at all is called without it.
    """
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError) as exc:
        raise EvidenceProviderError(f"evidence provider signature cannot be inspected: {fn!r}") from exc
    if any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL) for p in params):
        return "positional"
    if any(p.kind is p.KEYWORD_ONLY and p.name == "checkpoint" or p.kind is p.VAR_KEYWORD for p in params):
        return "keyword"
    if params:
        raise EvidenceProviderError(
            f"evidence provider takes only keyword-only parameters other than 'checkpoint': {fn!r}")
    return "none"


def _resolve_evidence(evidence: Any, checkpoint: str) -> Any:
    """Evidence for one checkpoint (PLAN, DISPATCH, STEP and COMMIT each get their
    own). Exceptions raised by the provider propagate: the action is not released."""
    if not callable(evidence):
        return evidence
    how = _checkpoint_call(evidence)
    if how == "positional":
        return evidence(checkpoint)
    if how == "keyword":
        return evidence(checkpoint=checkpoint)
    return evidence()


class PhiGate:
    def __init__(self, engine: PhiEngine | None = None, *, workspace: str | Path | None = None,
                 trust_store=None, audit_log=None, secret: bytes | None = None):
        self.engine = engine or PhiEngine()
        self.workspace = workspace
        self.trust_store = trust_store
        self.audit_log = audit_log
        # Per-gate MAC key for decision tokens only; verdicts never depend on it.
        self._secret = secret if secret is not None else os.urandom(32)

    def _binding(self, r: EvaluationResult) -> bytes:
        return canonical_json({
            "checkpoint": r.checkpoint, "task_id": r.task_id, "contract_hash": r.contract_hash,
            "state_hash": r.state_hash, "evidence_hash": r.evidence_hash, "verdict": r.verdict.value,
            "evaluator_version": r.evaluator_version,
        }).encode()

    def _token(self, r: EvaluationResult) -> str:
        return hmac.new(self._secret, self._binding(r), hashlib.sha256).hexdigest()

    def check(self, checkpoint: str, contract: Any, state: Any, evidence: Any) -> Decision:
        if checkpoint not in CHECKPOINTS:
            raise ValueError(f"unknown checkpoint {checkpoint!r}")
        contract, state, evidence = _resolve(contract), _resolve(state), _resolve_evidence(evidence, checkpoint)
        result = self.engine.evaluate(contract, state, evidence, checkpoint=checkpoint,
                                      workspace=self.workspace, trust_store=self.trust_store)
        record_hash = None
        if self.audit_log is not None:
            ts = state.get("now") if isinstance(state, dict) and isinstance(state.get("now"), str) else "unknown"
            record_hash = self.audit_log.append_evaluation(
                result, contract=contract, state=state, evidence=evidence, timestamp=ts)["record_hash"]
        return Decision(result=result, token=self._token(result), audit_record_hash=record_hash)

    def authorize(self, decision: Decision, contract: Any, state: Any, evidence: Any) -> Decision:
        """Validate a previously issued decision against the *current* inputs.

        Always re-evaluates (re-running evidence verification); a decision is
        honoured only if it is authentic, TRUE, and the fresh evaluation is TRUE
        with identical contract/state/evidence hashes."""
        if not isinstance(decision, Decision) or not hmac.compare_digest(
                decision.token, self._token(decision.result)):
            raise DecisionInvalid("DECISION_TOKEN_INVALID")
        if not decision.result.release:
            raise DecisionInvalid("DECISION_NOT_RELEASING")
        fresh = self.check(decision.result.checkpoint, contract, state, evidence)
        for key in ("contract_hash", "state_hash", "evidence_hash"):
            if getattr(fresh.result, key) != getattr(decision.result, key):
                raise DecisionInvalid(f"STALE_DECISION:{key}")
        if not fresh.release:
            raise DecisionInvalid("STALE_DECISION:verdict_changed")
        return fresh

    def guard(self, checkpoint: str, contract: Any, state: Any, evidence: Any,
              action: Callable[[], Any]) -> tuple[Decision, Any]:
        """Evaluate with the latest inputs (callables are invoked now) and run
        ``action`` only on TRUE."""
        decision = self.check(checkpoint, contract, state, evidence)
        if decision.result.verdict is Verdict.FALSE:
            raise GateBlocked(decision)
        if decision.result.verdict is not Verdict.TRUE:
            raise GateNeedsEvidence(decision)
        return decision, action()


class GateSession:
    """One task's run through PLAN -> DISPATCH -> STEP* -> COMMIT.

    The contract hash seen at preflight is pinned: later checkpoints evaluate
    against a state copy carrying ``contract_pins[task_id]``, so a contract
    edited mid-run yields UNKNOWN (CONTRACT_PIN_MISMATCH)."""

    def __init__(self, gate: PhiGate, contract: Any):
        self.gate = gate
        self._contract = contract
        self._pin: str | None = None
        self._task_id: str | None = None
        self._dispatched = False
        self._committed = False
        self._lock = threading.Lock()
        self.decisions: list[Decision] = []

    def _pinned_state(self, state: Any) -> Any:
        state = _resolve(state)
        if self._pin is None or not isinstance(state, dict):
            return state
        out = dict(state)
        pins = dict(out.get("contract_pins", {}))
        pins[self._task_id] = self._pin
        out["contract_pins"] = pins
        return out

    def _run(self, checkpoint, state, evidence, action):
        contract = _resolve(self._contract)
        st = self._pinned_state(state)
        if action is None:
            decision = self.gate.check(checkpoint, contract, st, evidence)
            self.decisions.append(decision)
            return decision, None
        try:
            decision, value = self.gate.guard(checkpoint, contract, st, evidence, action)
        except GateDenied as denied:
            self.decisions.append(denied.decision)
            raise
        self.decisions.append(decision)
        return decision, value

    def preflight(self, state: Any, evidence: Any, action: Callable[[], Any] | None = None):
        with self._lock:
            contract = _resolve(self._contract)
            plan = self.gate.check("PLAN", contract, _resolve(state), evidence)
            self.decisions.append(plan)
            if not plan.release:
                if action is not None:
                    raise (GateBlocked if plan.result.verdict is Verdict.FALSE else GateNeedsEvidence)(plan)
                return plan, None
            self._task_id = plan.result.task_id
            self._pin = plan.result.contract_hash
            decision, value = self._run("DISPATCH", state, evidence, action)
            self._dispatched = decision.release
            return decision, value

    def step(self, state: Any, evidence: Any, action: Callable[[], Any] | None = None):
        with self._lock:
            if not self._dispatched or self._committed:
                raise GateSequenceError("step requires a released preflight and no prior commit")
            return self._run("STEP", state, evidence, action)

    def commit(self, state: Any, evidence: Any, action: Callable[[], Any] | None = None):
        with self._lock:
            if not self._dispatched or self._committed:
                raise GateSequenceError("commit requires a released preflight and no prior commit")
            decision, value = self._run("COMMIT", state, evidence, action)
            self._committed = decision.release
            return decision, value


# --------------------------------------------------------------------------- harness adapter


@dataclass
class Step:
    name: str
    run: Callable[[], Any]


class HarnessAdapter(ABC):
    """What a host implements to put any harness behind Phi. The host owns task
    decomposition (``plan_steps``); phi-core only checks execution conditions."""

    @abstractmethod
    def load_contract(self) -> dict: ...

    @abstractmethod
    def observe_state(self) -> dict: ...

    @abstractmethod
    def collect_evidence(self, checkpoint: str) -> list: ...

    @abstractmethod
    def plan_steps(self) -> Sequence[Step]: ...

    @abstractmethod
    def commit(self) -> Any: ...


@dataclass
class RunReport:
    status: str  # COMPLETED | BLOCKED | PAUSED
    stopped_at: str | None
    executed_steps: list[str] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "stopped_at": self.stopped_at,
                "executed_steps": list(self.executed_steps), "decisions": list(self.decisions)}


class GatedRunner:
    def __init__(self, gate: PhiGate, adapter: HarnessAdapter):
        self.gate = gate
        self.adapter = adapter

    def run(self) -> RunReport:
        a = self.adapter
        session = GateSession(self.gate, a.load_contract)
        report = RunReport(status="COMPLETED", stopped_at=None)

        def summarize(d: Decision, label: str):
            report.decisions.append({"label": label, "checkpoint": d.result.checkpoint,
                                     "verdict": d.result.verdict.value, "action": d.action,
                                     "reason_codes": list(d.result.reason_codes)})

        def stop(denied: GateDenied, label: str):
            report.status = "BLOCKED" if isinstance(denied, GateBlocked) else "PAUSED"
            report.stopped_at = label

        try:
            session.preflight(a.observe_state, a.collect_evidence, action=lambda: None)
            for d in session.decisions:
                summarize(d, "preflight")
        except GateDenied as denied:
            for d in session.decisions:
                summarize(d, "preflight")
            stop(denied, "preflight")
            return report
        for step in a.plan_steps():
            try:
                decision, _ = session.step(a.observe_state, a.collect_evidence, action=step.run)
            except GateDenied as denied:
                summarize(denied.decision, f"step:{step.name}")
                stop(denied, f"step:{step.name}")
                return report
            summarize(decision, f"step:{step.name}")
            report.executed_steps.append(step.name)
        try:
            decision, _ = session.commit(a.observe_state, a.collect_evidence, action=a.commit)
        except GateDenied as denied:
            summarize(denied.decision, "commit")
            stop(denied, "commit")
            return report
        summarize(decision, "commit")
        return report
