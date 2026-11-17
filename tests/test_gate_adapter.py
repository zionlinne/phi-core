import copy

import pytest

from conftest import EARLIER, TASK, attest, base_contract, base_state
from phi_core import (
    AuditLog,
    GateBlocked,
    GatedRunner,
    GateNeedsEvidence,
    GateSequenceError,
    GateSession,
    HarnessAdapter,
    PhiGate,
    Step,
)


def contract_with_test():
    return base_contract(dependencies=["dep-a"], constraints=[
        {"constraint_id": "tests", "kind": "hard", "checkpoints": ["COMMIT"],
         "predicate": {"type": "attested_value", "params": {"expected": True}}}])


class ListAdapter(HarnessAdapter):
    def __init__(self, contract, state, evidence_by_cp, side_effects):
        self.contract, self.state, self.evidence_by_cp, self.side = contract, state, evidence_by_cp, side_effects

    def load_contract(self):
        return self.contract

    def observe_state(self):
        return copy.deepcopy(self.state)

    def collect_evidence(self, checkpoint):
        return self.evidence_by_cp.get(checkpoint, [])

    def plan_steps(self):
        return [Step("one", lambda: self.side.append("one")), Step("two", lambda: self.side.append("two"))]

    def commit(self):
        self.side.append("commit")


def test_runner_completes_on_true(trust):
    side = []
    adapter = ListAdapter(contract_with_test(), base_state(), {"COMMIT": [attest("e", "tests", True)]}, side)
    report = GatedRunner(PhiGate(trust_store=trust), adapter).run()
    assert report.status == "COMPLETED" and side == ["one", "two", "commit"]
    assert [d["checkpoint"] for d in report.decisions] == ["PLAN", "DISPATCH", "STEP", "STEP", "COMMIT"]


def test_runner_pauses_at_commit_without_evidence(trust):
    side = []
    report = GatedRunner(PhiGate(trust_store=trust), ListAdapter(contract_with_test(), base_state(), {}, side)).run()
    assert report.status == "PAUSED" and report.stopped_at == "commit"
    assert side == ["one", "two"]


def test_runner_blocks_at_commit_on_violation(trust):
    side = []
    adapter = ListAdapter(contract_with_test(), base_state(), {"COMMIT": [attest("e", "tests", False)]}, side)
    report = GatedRunner(PhiGate(trust_store=trust), adapter).run()
    assert report.status == "BLOCKED" and "commit" not in side


def test_runner_stops_mid_steps_when_state_changes(trust):
    side = []
    state = base_state()

    class Flaky(ListAdapter):
        def plan_steps(self):
            def one():
                side.append("one")
                state["tasks"]["dep-a"]["status"] = "failed"
            return [Step("one", one), Step("two", lambda: side.append("two"))]

    report = GatedRunner(PhiGate(trust_store=trust), Flaky(contract_with_test(), state, {}, side)).run()
    assert report.status == "BLOCKED" and report.stopped_at == "step:two"
    assert side == ["one"]


def test_runner_preflight_plan_failure(trust):
    side = []
    c = base_contract(capabilities=["gpu"])
    report = GatedRunner(PhiGate(trust_store=trust), ListAdapter(c, base_state(), {}, side)).run()
    assert report.status == "BLOCKED" and report.stopped_at == "preflight" and side == []
    assert report.decisions[0]["checkpoint"] == "PLAN"


def test_session_order_enforced(trust):
    gate = PhiGate(trust_store=trust)
    s = GateSession(gate, contract_with_test())
    with pytest.raises(GateSequenceError):
        s.step(base_state(), [])
    d, _ = s.preflight(base_state(), [])
    assert d.release
    s.commit(base_state(), [attest("e", "tests", True)])
    with pytest.raises(GateSequenceError):
        s.step(base_state(), [])
    with pytest.raises(GateSequenceError):
        s.commit(base_state(), [])


def test_guard_uses_latest_inputs_from_providers(trust):
    calls = []
    state = base_state()

    def provider():
        calls.append(1)
        return copy.deepcopy(state)

    gate = PhiGate(trust_store=trust)
    gate.guard("DISPATCH", contract_with_test(), provider, [], lambda: None)
    state["tasks"]["dep-a"]["status"] = "failed"
    with pytest.raises(GateBlocked):
        gate.guard("DISPATCH", contract_with_test(), provider, [], lambda: None)
    assert len(calls) == 2


def test_gate_writes_audit_records(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    gate = PhiGate(trust_store=trust, audit_log=log)
    d = gate.check("PLAN", base_contract(), base_state(), [])
    recs = log.records()
    assert len(recs) == 1 and recs[0]["record_hash"] == d.audit_record_hash
    assert recs[0]["timestamp"] == base_state()["now"]


def test_paused_decision_carries_missing_evidence(trust):
    gate = PhiGate(trust_store=trust)
    with pytest.raises(GateNeedsEvidence) as exc:
        gate.guard("COMMIT", contract_with_test(), base_state(), [], lambda: None)
    assert exc.value.decision.result.missing_evidence == ("tests",)
    assert exc.value.decision.to_dict()["action"] == "PAUSE_REQUEST_EVIDENCE"
