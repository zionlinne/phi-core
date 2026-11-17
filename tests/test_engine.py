import copy
import json

import pytest

from conftest import EARLIER, NOW, ROOT, TASK, attest, base_contract, base_state, file_ev, sha
from phi_core import (
    FunctionPredicate,
    Outcome,
    PhiEngine,
    Status,
    Verdict,
    default_predicate_registry,
    evaluate,
    seal_contract,
)
from phi_core.predicates import sat, unresolved, violated


def attested_constraint(cid="c-att", kind="hard", expected=True, **ev):
    c = {"constraint_id": cid, "kind": kind,
         "predicate": {"type": "attested_value", "params": {"expected": expected}}}
    if ev:
        c["evidence"] = ev
    return c


def ev_for(result, cid):
    return next(r for r in result.constraint_results + result.soft_results if r.constraint_id == cid)


# --------------------------------------------------------------------------- combinator semantics


def test_priority_violation_beats_unresolved(trust):
    c = base_contract(dependencies=["dep-a", "dep-b"], constraints=[attested_constraint()])
    s = base_state()
    s["tasks"]["dep-a"]["status"] = "failed"
    r = evaluate(c, s, [], checkpoint="DISPATCH", trust_store=trust)
    assert r.verdict is Verdict.FALSE
    assert ev_for(r, "dep:dep-b").status is Status.UNRESOLVED
    assert ev_for(r, "c-att").status is Status.UNRESOLVED


def test_violation_beats_incomplete_scope(trust):
    c = base_contract(dependencies=["dep-a"], constraint_scope={"complete": False})
    s = base_state()
    s["tasks"]["dep-a"]["status"] = "cancelled"
    assert evaluate(c, s, [], checkpoint="DISPATCH").verdict is Verdict.FALSE


def test_incomplete_scope_never_true():
    c = base_contract(dependencies=["dep-a"], constraint_scope={"complete": False})
    r = evaluate(c, base_state(), [], checkpoint="DISPATCH")
    assert r.verdict is Verdict.UNKNOWN and "SCOPE_NOT_DECLARED_COMPLETE" in r.reason_codes


def test_task_must_be_present_in_state():
    s = base_state(tasks={"dep-a": {"status": "completed"}})
    r = evaluate(base_contract(), s, [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "TASK_NOT_IN_STATE" in r.reason_codes


def test_soft_constraints_reported_separately_and_never_decide(trust):
    soft_violated = attested_constraint("soft-1", kind="soft", expected=True)
    c = base_contract(constraints=[soft_violated,
                                   {"constraint_id": "soft-2", "kind": "soft",
                                    "predicate": {"type": "natural_language", "params": {}}}])
    r = evaluate(c, base_state(), [attest("e", "soft-1", False)], checkpoint="DISPATCH", trust_store=trust)
    assert r.verdict is Verdict.TRUE
    assert {x.constraint_id: x.status for x in r.soft_results} == {"soft-1": Status.VIOLATED, "soft-2": Status.UNRESOLVED}
    assert r.constraint_results == ()


def test_checkpoint_applicability(ws):
    c = base_contract(outputs=[{"path": "out.txt"}])
    s = base_state(file_owners={"out.txt": TASK})
    r_dispatch = evaluate(c, s, [], checkpoint="DISPATCH", workspace=ws)
    assert r_dispatch.verdict is Verdict.TRUE
    assert [x.constraint_id for x in r_dispatch.constraint_results] == ["output:out.txt:ownership"]
    r_commit = evaluate(c, s, [file_ev("e", "output:out.txt:exists", "out.txt")], checkpoint="COMMIT", workspace=ws)
    assert r_commit.verdict is Verdict.FALSE and "OUTPUT_MISSING" in r_commit.reason_codes
    (ws / "out.txt").write_text("done")
    r_commit = evaluate(c, s, [file_ev("e", "output:out.txt:exists", "out.txt")], checkpoint="COMMIT", workspace=ws)
    assert r_commit.verdict is Verdict.TRUE


def test_invalid_checkpoint_raises():
    with pytest.raises(ValueError):
        evaluate(base_contract(), base_state(), [], checkpoint="LATER")


@pytest.mark.parametrize("contract, code", [
    (None, "CONTRACT_SCHEMA_INVALID"),
    ([], "CONTRACT_SCHEMA_INVALID"),
    ({"contract_version": "2.0"}, "CONTRACT_SCHEMA_INVALID"),
    (base_contract(dependencies=[TASK]), "CONTRACT_SEMANTIC_INVALID"),
])
def test_invalid_contracts_unknown(contract, code):
    r = evaluate(contract, base_state(), [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and code in r.reason_codes


@pytest.mark.parametrize("state", [None, {}, {"state_version": "1.0", "tasks": {}}, base_state(now="noon")])
def test_invalid_state_unknown(state):
    r = evaluate(base_contract(), state, [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "STATE_SCHEMA_INVALID" in r.reason_codes


def test_evidence_payload_not_list_unknown():
    r = evaluate(base_contract(), base_state(), {"x": 1}, checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_PAYLOAD_INVALID" in r.reason_codes


# --------------------------------------------------------------------------- state predicates


@pytest.mark.parametrize("status, expected", [
    ("completed", Status.SATISFIED), ("failed", Status.VIOLATED), ("cancelled", Status.VIOLATED),
    ("running", Status.UNRESOLVED), ("pending", Status.UNRESOLVED), (None, Status.UNRESOLVED),
])
def test_dependency_predicate(status, expected):
    s = base_state()
    if status is None:
        del s["tasks"]["dep-a"]
    else:
        s["tasks"]["dep-a"]["status"] = status
    r = evaluate(base_contract(dependencies=["dep-a"]), s, [], checkpoint="DISPATCH")
    assert ev_for(r, "dep:dep-a").status is expected


def test_resource_capability_time_predicates():
    c = base_contract(resources=[{"name": "cpu", "amount": 2}, {"name": "gpu", "amount": 1}],
                      capabilities=["python3", "rust"],
                      time_bounds={"not_before": "2026-11-18T00:00:00Z", "deadline": "2026-11-16T00:00:00Z"})
    s = base_state(resources={"cpu": 1})
    r = evaluate(c, s, [], checkpoint="DISPATCH")
    got = {x.constraint_id: x.status for x in r.constraint_results}
    assert got == {
        "resource:cpu": Status.VIOLATED, "resource:gpu": Status.UNRESOLVED,
        "capability:python3": Status.SATISFIED, "capability:rust": Status.VIOLATED,
        "time:deadline": Status.VIOLATED, "time:not_before": Status.UNRESOLVED,
    }
    s2 = base_state(capabilities_complete=False)
    r2 = evaluate(base_contract(capabilities=["rust"]), s2, [], checkpoint="PLAN")
    assert r2.verdict is Verdict.UNKNOWN and "CAPABILITY_UNKNOWN" in r2.reason_codes


def test_ownership_predicate():
    c = base_contract(outputs=[{"path": "o.txt"}])
    assert evaluate(c, base_state(file_owners={"o.txt": TASK}), [], checkpoint="DISPATCH").verdict is Verdict.TRUE
    assert evaluate(c, base_state(file_owners={"o.txt": "x"}), [], checkpoint="DISPATCH").verdict is Verdict.FALSE
    assert evaluate(c, base_state(), [], checkpoint="DISPATCH").verdict is Verdict.UNKNOWN


# --------------------------------------------------------------------------- evidence handling


def test_evidence_verifier_allowlist(ws):
    (ws / "a").write_text("x")
    c = base_contract(inputs=[{"path": "a"}])
    item = file_ev("e", "input:a:exists", "a")
    assert evaluate(c, base_state(), [item], checkpoint="DISPATCH", workspace=ws).verdict is Verdict.TRUE
    c2 = base_contract(constraints=[{"constraint_id": "x", "kind": "hard",
                                     "predicate": {"type": "input_exists", "params": {"path": "a"}},
                                     "evidence": {"verifiers": ["hmac_attestation"]}}])
    r = evaluate(c2, base_state(), [file_ev("e", "x", "a")], checkpoint="DISPATCH", workspace=ws)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_VERIFIER_NOT_ALLOWED" in r.reason_codes


def test_subject_mismatch_is_not_used(ws):
    (ws / "a").write_text("x")
    (ws / "b").write_text("y")
    c = base_contract(inputs=[{"path": "a"}])
    r = evaluate(c, base_state(), [file_ev("e", "input:a:exists", "b")], checkpoint="DISPATCH", workspace=ws)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_SUBJECT_MISMATCH" in r.reason_codes


def test_min_items(trust):
    c = base_contract(constraints=[attested_constraint(min_items=2)])
    r = evaluate(c, base_state(), [attest("e1", "c-att", True)], checkpoint="DISPATCH", trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_INSUFFICIENT" in r.reason_codes
    r = evaluate(c, base_state(), [attest("e1", "c-att", True), attest("e2", "c-att", True)],
                 checkpoint="DISPATCH", trust_store=trust)
    assert r.verdict is Verdict.TRUE


def test_source_precedence_rule_is_explicit_and_reproducible(trust):
    policy = {"conflict_resolution": {"type": "source_precedence", "order": ["lab", "ci-runner"]}}
    c = base_contract(constraints=[attested_constraint()], evidence_policy=policy)
    evidence = [attest("e-ci", "c-att", True), attest("e-lab", "c-att", False, source="lab", key_id="k-lab",
                                                       secret=b"test-secret-0123456789abcdef-XYZ"[::-1])]
    r1 = evaluate(c, base_state(), evidence, checkpoint="DISPATCH", trust_store=trust)
    r2 = evaluate(c, base_state(), list(reversed(evidence)), checkpoint="DISPATCH", trust_store=trust)
    assert r1.verdict is Verdict.FALSE and "CONFLICT_RESOLVED_BY_SOURCE_PRECEDENCE" in ev_for(r1, "c-att").reason_codes
    assert r1.constraint_results == r2.constraint_results


def test_no_last_write_wins(trust):
    c = base_contract(constraints=[attested_constraint()])
    older_false = attest("e-old", "c-att", False, ts="2026-11-16T23:00:00Z")
    newer_true = attest("e-new", "c-att", True, ts="2026-11-16T23:59:59Z")
    r = evaluate(c, base_state(), [older_false, newer_true], checkpoint="DISPATCH", trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_CONFLICT" in r.reason_codes


def test_unmatched_evidence_reported(trust):
    r = evaluate(base_contract(), base_state(), [attest("e", "nope", True)], checkpoint="PLAN", trust_store=trust)
    assert r.verdict is Verdict.TRUE and r.unmatched_evidence == ("e",)


def test_missing_evidence_lists_constraints(trust):
    c = base_contract(constraints=[attested_constraint("a"), attested_constraint("b")])
    r = evaluate(c, base_state(), [attest("e", "a", True)], checkpoint="DISPATCH", trust_store=trust)
    assert r.missing_evidence == ("b",)
    assert r.action == "PAUSE_REQUEST_EVIDENCE"


# --------------------------------------------------------------------------- registry / predicates


def test_custom_registered_predicate():
    reg = default_predicate_registry()
    reg.register("queue_below", FunctionPredicate(
        lambda p, s: sat() if s["extensions"]["queue"] < p["limit"] else violated("QUEUE_FULL"),
        kind="state", required_params={"limit": (int,)}))
    engine = PhiEngine(predicates=reg)
    c = base_contract(constraints=[{"constraint_id": "q", "kind": "hard",
                                    "predicate": {"type": "queue_below", "params": {"limit": 5}}}])
    assert engine.evaluate(c, base_state(extensions={"queue": 1}), [], checkpoint="PLAN").verdict is Verdict.TRUE
    assert engine.evaluate(c, base_state(extensions={"queue": 9}), [], checkpoint="PLAN").verdict is Verdict.FALSE
    c_bad = copy.deepcopy(c)
    c_bad["constraints"][0]["predicate"]["params"] = {"limit": "five"}
    r = engine.evaluate(c_bad, base_state(extensions={"queue": 1}), [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "PREDICATE_PARAMS_INVALID" in r.reason_codes


def test_crashing_or_bogus_predicate_is_unresolved():
    reg = default_predicate_registry()
    reg.register("boom", FunctionPredicate(lambda p, s: 1 / 0))
    reg.register("bogus", FunctionPredicate(lambda p, s: "TRUE"))
    engine = PhiEngine(predicates=reg)
    for t in ("boom", "bogus"):
        c = base_contract(constraints=[{"constraint_id": "x", "kind": "hard", "predicate": {"type": t}}])
        r = engine.evaluate(c, base_state(), [], checkpoint="PLAN")
        assert r.verdict is Verdict.UNKNOWN


def test_predicate_cannot_mutate_state_seen_by_other_constraints():
    def sneaky(p, s):
        s["tasks"]["dep-a"]["status"] = "completed"
        return sat()

    reg = default_predicate_registry()
    reg.register("sneaky", FunctionPredicate(sneaky))
    s = base_state()
    s["tasks"]["dep-a"]["status"] = "failed"
    c = base_contract(dependencies=["dep-a"], constraints=[
        {"constraint_id": "a-sneaky", "kind": "hard", "predicate": {"type": "sneaky"}}])
    r = PhiEngine(predicates=reg).evaluate(c, s, [], checkpoint="DISPATCH")
    assert r.verdict is Verdict.FALSE
    assert ev_for(r, "a-sneaky").reason_codes == ("PREDICATE_ERROR",)
    assert s["tasks"]["dep-a"]["status"] == "failed"


def test_reserved_natural_language_types_cannot_be_registered():
    reg = default_predicate_registry()
    for name in ("natural_language", "llm", "llm_judgment"):
        with pytest.raises(ValueError):
            reg.register(name, FunctionPredicate(lambda p, s: sat()))


def test_registry_rejects_duplicates_and_non_predicates():
    reg = default_predicate_registry()
    with pytest.raises(ValueError):
        reg.register("deadline", FunctionPredicate(lambda p, s: sat()))
    with pytest.raises(TypeError):
        reg.register("x", lambda p, s: sat())


# --------------------------------------------------------------------------- determinism / purity


def test_engine_does_not_mutate_inputs(ws, trust):
    (ws / "a").write_text("x")
    c = base_contract(inputs=[{"path": "a", "sha256": sha(b"x")}], constraints=[attested_constraint()],
                      dependencies=["dep-a"])
    s = base_state()
    e = [file_ev("e1", "input:a:exists", "a"), file_ev("e2", "input:a:sha256", "a"), attest("e3", "c-att", True)]
    snap = json.dumps([c, s, e], sort_keys=True)
    r = evaluate(c, s, e, checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.TRUE
    assert json.dumps([c, s, e], sort_keys=True) == snap


def test_judge_is_pure_and_repeatable(trust):
    engine = PhiEngine()
    c = base_contract(constraints=[attested_constraint()], dependencies=["dep-a"])
    s = base_state()
    vres = engine.verify(s, [attest("e", "c-att", True)], trust_store=trust)
    results = [engine.judge(c, s, vres, checkpoint="DISPATCH").to_dict() for _ in range(20)]
    assert all(r == results[0] for r in results)


def test_verdict_bound_to_hashes():
    r1 = evaluate(base_contract(), base_state(), [], checkpoint="PLAN")
    r2 = evaluate(base_contract(), base_state(now="2026-11-17T00:00:01Z"), [], checkpoint="PLAN")
    assert r1.contract_hash == r2.contract_hash and r1.state_hash != r2.state_hash


def test_integrity_and_pin():
    sealed = seal_contract(base_contract())
    assert evaluate(sealed, base_state(), [], checkpoint="PLAN").verdict is Verdict.TRUE
    edited = copy.deepcopy(sealed)
    edited["objective"] = "changed"
    r = evaluate(edited, base_state(), [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "CONTRACT_INTEGRITY_MISMATCH" in r.reason_codes
    pinned = base_state(contract_pins={TASK: "0" * 64})
    r = evaluate(base_contract(), pinned, [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "CONTRACT_PIN_MISMATCH" in r.reason_codes


def test_result_serialises_with_full_references(trust):
    c = base_contract(constraints=[attested_constraint()])
    r = evaluate(c, base_state(), [attest("e", "c-att", True)], checkpoint="DISPATCH", trust_store=trust)
    d = json.loads(json.dumps(r.to_dict()))
    assert d["constraint_results"][0]["evidence_refs"] == ["e"]
    assert d["evidence_results"][0]["status"] == "VERIFIED"
    assert d["evaluator_version"] == "phi-core/1.0.0"


# --------------------------------------------------------------------------- plan level


def plan_contract(tid, **kw):
    c = base_contract(**kw)
    c["task_id"] = tid
    return c


def plan_state(*tids):
    return base_state(tasks={t: {"status": "pending"} for t in tids})


def test_plan_true_for_consistent_tree():
    parent = plan_contract("p", subtasks=["a", "b"])
    a = plan_contract("a", parent_task_id="p", outputs=[{"path": "a.out"}])
    b = plan_contract("b", parent_task_id="p", dependencies=["a"], outputs=[{"path": "b.out"}])
    r = PhiEngine().evaluate_plan([parent, a, b], plan_state("p", "a", "b"), [])
    assert r.verdict is Verdict.TRUE, r.to_dict()


@pytest.mark.parametrize("contracts, code, verdict", [
    ([plan_contract("a", dependencies=["b"]), plan_contract("b", dependencies=["a"])], "DEPENDENCY_CYCLE", Verdict.FALSE),
    ([plan_contract("a", outputs=[{"path": "x"}]), plan_contract("b", outputs=[{"path": "x"}])],
     "OUTPUT_OWNERSHIP_CONFLICT", Verdict.FALSE),
    ([plan_contract("a"), plan_contract("a")], "DUPLICATE_TASK_ID", Verdict.FALSE),
    ([plan_contract("a", dependencies=["ghost"])], "DEPENDENCY_UNDECLARED", Verdict.UNKNOWN),
    ([plan_contract("p", subtasks=["a"]), plan_contract("a")], "PARENT_CHILD_INCONSISTENT", Verdict.FALSE),
    ([plan_contract("a", parent_task_id="ghost")], "PARENT_UNDECLARED", Verdict.UNKNOWN),
    ([], "EMPTY_PLAN", Verdict.UNKNOWN),
    ([{"contract_version": "1.0"}], "CONTRACT_SCHEMA_INVALID", Verdict.UNKNOWN),
])
def test_plan_issues(contracts, code, verdict):
    r = PhiEngine().evaluate_plan(contracts, plan_state("a", "b", "p"), [])
    assert r.verdict is verdict
    assert code in r.reason_codes


def test_example_v1_files_true_with_trust():
    from phi_core import TrustStore

    load = lambda p: json.loads((ROOT / "examples" / p).read_text("utf-8"))  # noqa: E731
    trust = TrustStore.from_dict(load("trust.demo.json"))
    for cp in ("PLAN", "DISPATCH", "STEP", "COMMIT"):
        r = evaluate(load("v1/contract.json"), load("v1/state.json"), load("v1/evidence.json"), checkpoint=cp,
                     workspace=ROOT / "examples" / "v1" / "workspace", trust_store=trust)
        assert r.verdict is Verdict.TRUE, (cp, r.reason_codes)
