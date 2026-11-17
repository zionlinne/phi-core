"""Property-based, fuzz and replay tests (Hypothesis, derandomized for reproducibility)."""

import copy
import json
import random

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import EARLIER, NOW, OTHER_SECRET, SECRET, TASK, attest, base_contract, base_state
from phi_core import AuditLog, PhiEngine, PhiGate, Status, TrustStore, Verdict, evaluate, replay_log, validate_contract
from phi_core.cli import main as cli_main

PROFILE = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                   suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])

TRUST = TrustStore()
TRUST.add_key("k-ci", SECRET, ["ci-runner"])

DEP_STATUSES = ["completed", "failed", "cancelled", "running", "pending", "ready", "blocked", None]
EVIDENCE_KINDS = ["true", "false", "forged", "stale", "unknown_key", "unregistered", "future"]


def evidence_item(eid, cid, kind):
    if kind == "true":
        return attest(eid, cid, True)
    if kind == "false":
        return attest(eid, cid, False)
    if kind == "forged":
        return attest(eid, cid, True, secret=OTHER_SECRET)
    if kind == "stale":
        return attest(eid, cid, True, ts="2026-11-16T20:00:00Z")
    if kind == "unknown_key":
        return attest(eid, cid, True, key_id="k-nobody")
    if kind == "future":
        return attest(eid, cid, True, ts="2026-11-17T01:00:00Z")
    item = attest(eid, cid, True)
    item["verifier_id"] = "unregistered-verifier"
    return item


@st.composite
def scenarios(draw):
    n_deps = draw(st.integers(0, 4))
    deps = [f"d{i}" for i in range(n_deps)]
    # Weighted toward satisfiable inputs so that TRUE is generated often enough to matter.
    statuses = {d: draw(st.sampled_from(DEP_STATUSES + ["completed"] * 8)) for d in deps}
    n_att = draw(st.integers(0, 3))
    att_ids = [f"a{i}" for i in range(n_att)]
    kinds = st.sampled_from(EVIDENCE_KINDS + ["true"] * 10)
    evidence_plan = {a: draw(st.lists(kinds, min_size=1, max_size=3) | st.just([])) for a in att_ids}
    n_soft = draw(st.integers(0, 2))
    soft_plan = {f"s{i}": draw(st.lists(st.sampled_from(EVIDENCE_KINDS), max_size=2)) for i in range(n_soft)}
    complete = draw(st.sampled_from([True, True, True, False]))
    task_in_state = draw(st.sampled_from([True, True, True, False]))
    checkpoint = draw(st.sampled_from(["PLAN", "DISPATCH", "STEP", "COMMIT"]))
    constraints = [{"constraint_id": a, "kind": "hard", "evidence": {"max_age_seconds": 3600},
                    "predicate": {"type": "attested_value", "params": {"expected": True}}} for a in att_ids]
    constraints += [{"constraint_id": s, "kind": "soft",
                     "predicate": {"type": "attested_value", "params": {"expected": True}}} for s in soft_plan]
    contract = base_contract(dependencies=deps, constraints=constraints, constraint_scope={"complete": complete})
    tasks = {d: {"status": s} for d, s in statuses.items() if s is not None}
    if task_in_state:
        tasks[TASK] = {"status": "ready"}
    state = base_state(tasks=tasks)
    evidence = [evidence_item(f"{cid}-{i}", cid, kind)
                for cid, kinds in {**evidence_plan, **soft_plan}.items() for i, kind in enumerate(kinds)]
    return contract, state, evidence, checkpoint, statuses, evidence_plan, complete, task_in_state


def oracle_dep(status):
    if status == "completed":
        return "SATISFIED"
    if status in ("failed", "cancelled"):
        return "VIOLATED"
    return "UNRESOLVED"


def oracle_att(kinds):
    usable = [k for k in kinds if k in ("true", "false")]
    if not usable:
        return "UNRESOLVED"
    if len(set(usable)) > 1:
        return "UNRESOLVED"
    return "SATISFIED" if usable[0] == "true" else "VIOLATED"


@PROFILE
@given(scenarios())
def test_verdict_matches_independent_oracle(sc):
    contract, state, evidence, cp, statuses, evidence_plan, complete, task_in_state = sc
    r = evaluate(contract, state, evidence, checkpoint=cp, trust_store=TRUST)
    expected = {}
    if cp != "PLAN":
        expected.update({f"dep:{d}": oracle_dep(s) for d, s in statuses.items()})
    expected.update({a: oracle_att(k) for a, k in evidence_plan.items()})
    got = {c.constraint_id: c.status.value for c in r.constraint_results}
    assert got == expected
    values = set(expected.values())
    if "VIOLATED" in values:
        oracle = Verdict.FALSE
    elif "UNRESOLVED" in values or not complete or not task_in_state:
        oracle = Verdict.UNKNOWN
    else:
        oracle = Verdict.TRUE
    assert r.verdict is oracle
    assert r.release == (oracle is Verdict.TRUE)
    if r.verdict is Verdict.TRUE:
        assert all(c.status is Status.SATISFIED for c in r.constraint_results)
        assert complete and task_in_state


@PROFILE
@given(scenarios(), st.randoms(use_true_random=False))
def test_deterministic_order_invariant_and_non_mutating(sc, rnd):
    contract, state, evidence, cp, *_ = sc
    snap = json.dumps([contract, state, evidence], sort_keys=True)
    r1 = evaluate(contract, state, evidence, checkpoint=cp, trust_store=TRUST)
    r2 = evaluate(contract, state, evidence, checkpoint=cp, trust_store=TRUST)
    assert r1.to_dict() == r2.to_dict()
    shuffled = list(evidence)
    rnd.shuffle(shuffled)
    r3 = evaluate(contract, state, shuffled, checkpoint=cp, trust_store=TRUST)
    assert r3.verdict is r1.verdict
    assert r3.constraint_results == r1.constraint_results
    assert json.dumps([contract, state, evidence], sort_keys=True) == snap


@PROFILE
@given(scenarios(), st.lists(st.sampled_from(["forged", "unknown_key", "unregistered", "future", "stale"]), min_size=1, max_size=4))
def test_untrusted_evidence_never_changes_constraint_statuses(sc, junk):
    contract, state, evidence, cp, *_ = sc
    base = evaluate(contract, state, evidence, checkpoint=cp, trust_store=TRUST)
    targets = [c["constraint_id"] for c in contract.get("constraints", [])] or ["nothing"]
    extra = [evidence_item(f"junk-{i}", targets[i % len(targets)], k) for i, k in enumerate(junk)]
    r = evaluate(contract, state, evidence + extra, checkpoint=cp, trust_store=TRUST)
    assert r.verdict is base.verdict
    assert [(c.constraint_id, c.status) for c in r.constraint_results] == \
           [(c.constraint_id, c.status) for c in base.constraint_results]


@PROFILE
@given(scenarios())
def test_soft_constraints_never_influence_verdict(sc):
    contract, state, evidence, cp, *_ = sc
    hard_only = copy.deepcopy(contract)
    hard_only["constraints"] = [c for c in contract["constraints"] if c["kind"] == "hard"]
    a = evaluate(contract, state, evidence, checkpoint=cp, trust_store=TRUST)
    b = evaluate(hard_only, state, evidence, checkpoint=cp, trust_store=TRUST)
    assert a.verdict is b.verdict and a.constraint_results == b.constraint_results


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False) | st.text(max_size=8),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=20,
)


@PROFILE
@given(json_values, json_values, json_values, st.sampled_from(["PLAN", "DISPATCH", "STEP", "COMMIT"]))
def test_fuzz_arbitrary_json_never_crashes_never_true(c, s, e, cp):
    r = evaluate(c, s, e, checkpoint=cp, trust_store=TRUST)
    assert r.verdict in (Verdict.FALSE, Verdict.UNKNOWN)
    json.dumps(r.to_dict())


KEYS = ["contract_version", "task_id", "objective", "constraint_scope", "dependencies", "inputs", "outputs",
        "constraints", "capabilities", "resources", "time_bounds", "evidence_policy", "integrity"]


@PROFILE
@given(st.lists(st.tuples(st.sampled_from(KEYS), st.sampled_from(["delete", "replace"]), json_values), max_size=4),
       st.sampled_from(["PLAN", "DISPATCH", "STEP", "COMMIT"]))
def test_fuzz_mutated_valid_contract(mutations, cp):
    contract = base_contract(dependencies=["dep-a"], capabilities=["python3"])
    for key, op, value in mutations:
        if op == "delete":
            contract.pop(key, None)
        else:
            contract[key] = value
    r = evaluate(contract, base_state(), [], checkpoint=cp, trust_store=TRUST)
    if r.verdict is Verdict.TRUE:
        assert validate_contract(contract).valid
        assert contract["constraint_scope"]["complete"] is True


@settings(max_examples=60, deadline=None, derandomize=True, database=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(scenarios(), min_size=1, max_size=6))
def test_audit_replay_reproduces_every_recorded_verdict(tmp_path_factory, seq):
    log = AuditLog(tmp_path_factory.mktemp("audit") / "log.jsonl")
    gate = PhiGate(trust_store=TRUST, audit_log=log)
    for contract, state, evidence, cp, *_ in seq:
        gate.check(cp, contract, state, evidence)
    assert log.verify()["ok"]
    results = replay_log(log)
    assert len(results) == len(seq) and all(r["matches"] for r in results)


@settings(max_examples=80, deadline=None, derandomize=True, database=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.binary(max_size=200) | json_values.map(lambda v: json.dumps(v).encode()))
def test_cli_fuzz_request_file(tmp_path_factory, payload):
    p = tmp_path_factory.mktemp("cli") / "req.json"
    p.write_bytes(payload)
    code = cli_main(["evaluate", "--request", str(p)])
    assert code in (2, 10, 20)
