"""Adversarial scenarios A-T. Each test name starts with its scenario letter."""

import copy
import hashlib
import json
import subprocess
import sys
import threading

import pytest

from conftest import EARLIER, NOW, OTHER_SECRET, ROOT, SECRET, TASK, attest, base_contract, base_state, file_ev, sha
from phi_core import (
    AuditLog,
    Decision,
    DecisionInvalid,
    GateBlocked,
    GateDenied,
    GateNeedsEvidence,
    GateSession,
    PhiGate,
    Verdict,
    evaluate,
    make_anchor_entry,
    make_evidence,
    new_revision,
    observe_files,
    run_acceptance,
    seal_contract,
)
from phi_core.acceptance import baseline_hash

SCHEMA = {"type": "object", "required": ["n"], "properties": {"n": {"type": "integer"}}, "additionalProperties": False}


@pytest.fixture
def scenario(ws):
    data = b"payload\n"
    (ws / "in.txt").write_bytes(data)
    (ws / "schema.json").write_text(json.dumps(SCHEMA))
    (ws / "out.json").write_text('{"n": 1}')
    contract = base_contract(
        dependencies=["dep-a"],
        inputs=[{"path": "in.txt", "sha256": sha(data)}],
        outputs=[{"path": "out.json", "schema": "schema.json"}],
        constraints=[{"constraint_id": "tests", "kind": "hard",
                      "predicate": {"type": "attested_value", "params": {"expected": {"passed": True}}},
                      "checkpoints": ["COMMIT"], "evidence": {"max_age_seconds": 600}}],
    )
    state = base_state(file_owners={"out.json": TASK})
    return contract, state


def full_evidence(contract, ws, passed=True, ts=EARLIER):
    return observe_files(contract, ws, ts) + [attest("att-tests", "tests", {"passed": passed}, ts=ts)]


def ran_marker(tmp_path):
    marker = tmp_path / "side_effect.txt"

    def action():
        marker.write_text("executed")
        return "done"

    return marker, action


# --------------------------------------------------------------------------- A-I: core semantics


def test_A_all_required_satisfied_true(scenario, ws, trust):
    contract, state = scenario
    for cp in ("PLAN", "DISPATCH", "STEP", "COMMIT"):
        r = evaluate(contract, state, full_evidence(contract, ws), checkpoint=cp, workspace=ws, trust_store=trust)
        assert r.verdict is Verdict.TRUE, (cp, r.reason_codes)
        assert all(c.status.value == "SATISFIED" for c in r.constraint_results)
    assert r.release and r.action == "PROCEED"


def test_B_valid_hard_violation_false(scenario, ws, trust):
    contract, state = scenario
    r = evaluate(contract, state, full_evidence(contract, ws, passed=False), checkpoint="COMMIT",
                 workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.FALSE and r.action == "BLOCK"
    assert "ATTESTED_VALUE_MISMATCH" in r.reason_codes and "VERIFIED_HARD_VIOLATION" in r.reason_codes


def test_C_missing_evidence_unknown(scenario, ws, trust):
    contract, state = scenario
    ev = [e for e in full_evidence(contract, ws) if e["constraint_id"] != "tests"]
    r = evaluate(contract, state, ev, checkpoint="COMMIT", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and r.missing_evidence == ("tests",)
    assert "EVIDENCE_MISSING" in r.reason_codes
    r0 = evaluate(contract, state, [], checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert r0.verdict is Verdict.UNKNOWN


def test_D_conflicting_evidence_unknown(scenario, ws, trust):
    contract, state = scenario
    ev = full_evidence(contract, ws) + [attest("att-tests-2", "tests", {"passed": False})]
    r = evaluate(contract, state, ev, checkpoint="COMMIT", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN
    assert "EVIDENCE_CONFLICT" in r.reason_codes


def test_E_stale_evidence_unknown(scenario, ws, trust):
    contract, state = scenario
    ev = observe_files(contract, ws, EARLIER) + [attest("att-tests", "tests", {"passed": True}, ts="2026-11-16T23:49:59Z")]
    r = evaluate(contract, state, ev, checkpoint="COMMIT", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_STALE" in r.reason_codes
    old_files = observe_files(contract, ws, "2026-11-16T22:00:00Z")
    r2 = evaluate(contract, state, old_files, checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert r2.verdict is Verdict.UNKNOWN and "EVIDENCE_STALE" in r2.reason_codes


def test_F_unverifiable_source_unknown(scenario, ws, trust):
    contract, state = scenario
    files = observe_files(contract, ws, EARLIER)
    variants = [
        attest("att", "tests", {"passed": True}, key_id="k-unregistered"),
        make_evidence("att", "tests", source="ci-runner", verifier_id="hmac_attestation",
                      observed_value={"passed": True}, timestamp=EARLIER, verification_status="VERIFIED"),
        make_evidence("att", "tests", source="gpt-reviewer", verifier_id="llm_judgment",
                      observed_value={"passed": True}, timestamp=EARLIER, verification_status="VERIFIED"),
    ]
    for v in variants:
        r = evaluate(contract, state, files + [v], checkpoint="COMMIT", workspace=ws, trust_store=trust)
        assert r.verdict is Verdict.UNKNOWN, v
        assert "EVIDENCE_UNVERIFIABLE" in r.reason_codes


def test_G_non_executable_predicate_unknown_and_never_executed(tmp_path, trust):
    marker = tmp_path / "pwned"
    payload = f"__import__('pathlib').Path({str(marker)!r}).write_text('x')"
    for ptype, params in [("natural_language", {"text": "the build should probably be fine"}),
                          ("python_expression", {"expr": payload}),
                          ("llm_judgment", {"prompt": payload})]:
        c = base_contract(constraints=[{"constraint_id": "g", "kind": "hard",
                                        "predicate": {"type": ptype, "params": params}}])
        r = evaluate(c, base_state(), [], checkpoint="PLAN", trust_store=trust)
        assert r.verdict is Verdict.UNKNOWN
        assert "PREDICATE_NOT_EXECUTABLE" in r.reason_codes
    c = base_contract(constraints=[{"constraint_id": "g", "kind": "hard",
                                    "predicate": {"type": "attested_value", "params": {"expected": payload}}}])
    evaluate(c, base_state(), [attest("e", "g", payload)], checkpoint="PLAN", trust_store=trust)
    assert not marker.exists()


def test_H_empty_set_without_complete_declaration_is_not_true():
    c = base_contract(constraint_scope={"complete": False})
    r = evaluate(c, base_state(), [], checkpoint="DISPATCH")
    assert r.verdict is Verdict.UNKNOWN and "SCOPE_NOT_DECLARED_COMPLETE" in r.reason_codes
    no_scope = base_contract()
    del no_scope["constraint_scope"]
    assert evaluate(no_scope, base_state(), [], checkpoint="DISPATCH").verdict is Verdict.UNKNOWN


def test_I_explicit_complete_empty_set_true():
    r = evaluate(base_contract(constraint_scope={"complete": True, "declared_by": "host"}), base_state(), [],
                 checkpoint="DISPATCH")
    assert r.verdict is Verdict.TRUE
    assert "NO_APPLICABLE_HARD_CONSTRAINTS_SCOPE_DECLARED_COMPLETE" in r.reason_codes


# --------------------------------------------------------------------------- J-O: execution gate


def test_J_dependency_incomplete_blocks_execution(scenario, ws, trust, tmp_path):
    contract, state = scenario
    state["tasks"]["dep-a"]["status"] = "running"
    marker, action = ran_marker(tmp_path)
    gate = PhiGate(workspace=ws, trust_store=trust)
    with pytest.raises(GateNeedsEvidence) as exc:
        gate.guard("DISPATCH", contract, state, full_evidence(contract, ws), action)
    assert "DEPENDENCY_NOT_COMPLETED" in exc.value.decision.result.reason_codes
    assert not marker.exists()


def test_K_file_tampering(scenario, ws, trust, tmp_path):
    contract, state = scenario
    old_claims = full_evidence(contract, ws)
    (ws / "in.txt").write_bytes(b"tampered\n")
    stale_claim = evaluate(contract, state, old_claims, checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert stale_claim.verdict is Verdict.UNKNOWN and "ARTIFACT_HASH_MISMATCH" in stale_claim.reason_codes
    fresh = evaluate(contract, state, full_evidence(contract, ws), checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert fresh.verdict is Verdict.FALSE and "FILE_HASH_MISMATCH" in fresh.reason_codes
    marker, action = ran_marker(tmp_path)
    with pytest.raises(GateBlocked):
        PhiGate(workspace=ws, trust_store=trust).guard(
            "DISPATCH", contract, state, lambda: full_evidence(contract, ws), action)
    assert not marker.exists()


def test_L_forged_evidence_is_not_trusted(scenario, ws, trust):
    contract, state = scenario
    files = observe_files(contract, ws, EARLIER)
    forged_sig = attest("att", "tests", {"passed": True}, secret=OTHER_SECRET)
    flipped = attest("att", "tests", {"passed": False})
    flipped["observed_value"] = {"passed": True}
    fake_hash = file_ev("fake", "input:in.txt:sha256", "in.txt", artifact_hash="f" * 64)
    for forged in (forged_sig, flipped):
        r = evaluate(contract, state, files + [forged], checkpoint="COMMIT", workspace=ws, trust_store=trust)
        assert r.verdict is Verdict.UNKNOWN and "SIGNATURE_INVALID" in r.reason_codes
    only_fake = [e for e in files if e["constraint_id"] != "input:in.txt:sha256"] + [fake_hash]
    r = evaluate(contract, state, only_fake, checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "ARTIFACT_HASH_MISMATCH" in r.reason_codes
    # Forged positive evidence next to a verified violation cannot turn FALSE into TRUE.
    ev = files + [attest("att-real", "tests", {"passed": False}), forged_sig]
    r = evaluate(contract, state, ev, checkpoint="COMMIT", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.FALSE


def test_M_contract_modification(scenario, ws, trust, tmp_path):
    contract, state = scenario
    holder = {"c": copy.deepcopy(contract)}
    gate = PhiGate(workspace=ws, trust_store=trust)
    session = GateSession(gate, lambda: holder["c"])
    decision, _ = session.preflight(state, lambda: full_evidence(holder["c"], ws))
    assert decision.release
    holder["c"]["constraints"] = []  # agent drops the test requirement mid-run
    marker, action = ran_marker(tmp_path)
    with pytest.raises(GateNeedsEvidence) as exc:
        session.step(state, lambda: full_evidence(holder["c"], ws), action)
    assert "CONTRACT_PIN_MISMATCH" in exc.value.decision.result.reason_codes
    assert not marker.exists()
    sealed = seal_contract(contract)
    sealed["dependencies"] = []
    r = evaluate(sealed, state, full_evidence(contract, ws), checkpoint="DISPATCH", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "CONTRACT_INTEGRITY_MISMATCH" in r.reason_codes


def test_N_stale_verdict_cannot_be_reused(scenario, ws, trust, tmp_path):
    contract, state = scenario
    gate = PhiGate(workspace=ws, trust_store=trust)
    ev = full_evidence(contract, ws)
    decision = gate.check("DISPATCH", contract, state, ev)
    assert decision.release
    assert gate.authorize(decision, contract, state, ev).release
    changed = copy.deepcopy(state)
    changed["tasks"]["dep-a"]["status"] = "failed"
    with pytest.raises(DecisionInvalid, match="STALE_DECISION"):
        gate.authorize(decision, contract, changed, ev)
    later = copy.deepcopy(state)
    later["now"] = "2026-11-17T00:05:00Z"
    with pytest.raises(DecisionInvalid, match="STALE_DECISION"):
        gate.authorize(decision, contract, later, ev)
    # Same JSON inputs but the workspace changed underneath: re-verification catches it.
    (ws / "in.txt").write_bytes(b"swapped\n")
    with pytest.raises(DecisionInvalid):
        gate.authorize(decision, contract, state, ev)
    with pytest.raises(DecisionInvalid, match="DECISION_TOKEN_INVALID"):
        PhiGate(workspace=ws, trust_store=trust).authorize(decision, contract, state, ev)


def test_O_agent_bypass_attempts(scenario, ws, trust, tmp_path):
    contract, state = scenario
    state["tasks"]["dep-a"]["status"] = "pending"
    gate = PhiGate(workspace=ws, trust_store=trust)
    marker, action = ran_marker(tmp_path)
    ev = full_evidence(contract, ws)
    # 1. Supported entry: UNKNOWN never runs the action.
    with pytest.raises(GateDenied):
        gate.guard("DISPATCH", contract, state, ev, action)
    assert not marker.exists()
    # 2. Agent fabricates a TRUE decision object.
    real = gate.check("DISPATCH", contract, state, ev)
    fake_result = real.result.__class__(**{**real.result.__dict__, "verdict": Verdict.TRUE})
    for forged in (Decision(fake_result, real.token), Decision(fake_result, "0" * 64)):
        with pytest.raises(DecisionInvalid):
            gate.authorize(forged, contract, state, ev)
    # 3. Agent tries to skip preflight in a session.
    from phi_core import GateSequenceError

    with pytest.raises(GateSequenceError):
        GateSession(gate, contract).step(state, ev, action)
    with pytest.raises(GateSequenceError):
        GateSession(gate, contract).commit(state, ev, action)
    assert not marker.exists()


def test_O_boundary_direct_write_outside_library_is_not_prevented(scenario, ws, trust):
    """Honest boundary: code that never calls the gate is not stopped by an in-process library.
    What *is* guaranteed: the next supported checkpoint re-observes and catches an invalid result."""
    contract, state = scenario
    (ws / "out.json").write_text('{"n": "not-an-int"}')  # direct write, no gate involved
    assert (ws / "out.json").read_text() == '{"n": "not-an-int"}'
    r = evaluate(contract, state, full_evidence(contract, ws), checkpoint="COMMIT", workspace=ws, trust_store=trust)
    assert r.verdict is Verdict.FALSE and "SCHEMA_INCOMPATIBLE" in r.reason_codes


# --------------------------------------------------------------------------- P-R: acceptance


@pytest.fixture
def acceptance(ws, trust):
    design = b"design v1"
    (ws / "design.md").write_bytes(design)
    (ws / "schema.json").write_text(json.dumps(SCHEMA))
    (ws / "out.json").write_text('{"n": 1}')
    baseline = {
        "baseline_version": "1.0", "baseline_id": "B", "revision": 1, "previous_revision_hash": None,
        "frozen_at": "2026-11-01T00:00:00Z",
        "design": {"design_id": "D", "version": "1", "sha256": sha(design), "path": "design.md"},
        "requirements": [
            {"requirement_id": "R1", "text": "out.json exists", "verification": {"method": "file", "path": "out.json"}},
            {"requirement_id": "R2", "text": "out.json schema", "design_ref": "D.1",
             "verification": {"method": "json_schema", "path": "out.json", "schema_path": "schema.json"}},
            {"requirement_id": "R3", "text": "n is 1", "verification": {
                "method": "command", "argv": ["{python}", "-c", "import json,sys; sys.exit(0 if json.load(open('out.json'))['n']==1 else 1)"]}},
        ],
        "change_log": [{"revision": 1, "summary": "initial"}],
    }
    authority = b"authority-secret-0123456789abcdef"
    trust.add_key("k-auth", authority, ["acceptance-authority"])
    anchor = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [
        make_anchor_entry(baseline, anchored_by="authority", anchored_at="2026-11-01T00:00:00Z",
                          key_id="k-auth", secret=authority)]}
    delivery = {"delivery_version": "1.0", "baseline_id": "B", "baseline_revision": 1, "claimed_status": "ALL DONE",
                "trace": [{"requirement_id": r, "artifacts": ["out.json"]} for r in ("R1", "R2", "R3")]}
    return baseline, anchor, delivery, authority


def accept(baseline, anchor, delivery, ws, trust, **kw):
    return run_acceptance(baseline, anchor, delivery, workspace=ws, now=NOW, trust_store=trust,
                          require_signed_anchor=True, **kw)


def test_acceptance_fixture_passes(acceptance, ws, trust):
    b, a, d, _ = acceptance
    assert accept(b, a, d, ws, trust)["status"] == "PASS"


def test_P_agent_changes_acceptance_criteria(acceptance, ws, trust):
    b, a, d, _ = acceptance
    (ws / "out.json").write_text('{"n": 2}')
    assert accept(b, a, d, ws, trust)["status"] == "FAIL"
    relaxed = copy.deepcopy(b)
    relaxed["requirements"][2]["verification"]["argv"] = ["{python}", "-c", "pass"]
    rep = accept(relaxed, a, d, ws, trust)
    assert rep["status"] == "FAIL" and "BASELINE_HASH_MISMATCH" in rep["global_reason_codes"]
    forged_anchor = copy.deepcopy(a)
    forged_anchor["revisions"][0]["baseline_hash"] = baseline_hash(relaxed)
    rep = accept(relaxed, forged_anchor, d, ws, trust)
    assert rep["status"] == "FAIL" and "ANCHOR_SIGNATURE_INVALID" in rep["global_reason_codes"]
    self_signed = copy.deepcopy(a)
    self_signed["revisions"] = [make_anchor_entry(relaxed, anchored_by="agent", anchored_at=NOW,
                                                  key_id="k-agent", secret=OTHER_SECRET)]
    rep = accept(relaxed, self_signed, d, ws, trust)
    assert rep["status"] != "PASS" and "ANCHOR_KEY_UNKNOWN" in rep["global_reason_codes"]
    producer_criteria = {**d, "requirements": [], "acceptance_criteria": "anything goes"}
    rep = accept(b, a, producer_criteria, ws, trust)
    assert rep["status"] == "FAIL"
    assert set(rep["ignored_producer_fields"]) == {"acceptance_criteria", "requirements"}


def test_Q_deleting_original_requirement_and_claiming_pass(acceptance, ws, trust):
    b, a, d, authority = acceptance
    (ws / "out.json").unlink()
    trimmed = copy.deepcopy(b)
    trimmed["requirements"] = [r for r in b["requirements"] if r["requirement_id"] != "R1"]
    d2 = {**d, "trace": [t for t in d["trace"] if t["requirement_id"] != "R1"], "claimed_status": "PASS"}
    rep = accept(trimmed, a, d2, ws, trust)
    assert rep["status"] == "FAIL" and "BASELINE_HASH_MISMATCH" in rep["global_reason_codes"]
    rev2 = new_revision(b, requirements=trimmed["requirements"], summary="agent removed R1", frozen_at=NOW)
    rep = accept(rev2, a, {**d2, "baseline_revision": 2}, ws, trust)
    assert rep["status"] == "FAIL" and "BASELINE_REVISION_NOT_ANCHORED" in rep["global_reason_codes"]
    omitted = accept(b, a, d2, ws, trust)
    r1 = next(r for r in omitted["requirement_results"] if r["requirement_id"] == "R1")
    assert omitted["status"] == "FAIL" and "TRACE_MISSING_OMITTED_REQUIREMENT" in r1["reason_codes"]
    # A legitimate, authority-anchored change is recorded as a new revision and the old one is superseded.
    a2 = copy.deepcopy(a)
    a2["revisions"].append(make_anchor_entry(rev2, anchored_by="authority", anchored_at=NOW,
                                             key_id="k-auth", secret=authority))
    assert rev2["change_log"][-1]["removed"] == ["R1"]
    rep_old = accept(b, a2, d, ws, trust)
    assert rep_old["status"] == "FAIL" and "BASELINE_REVISION_SUPERSEDED" in rep_old["global_reason_codes"]


def test_R_self_reported_success_but_design_deviation(acceptance, ws, trust, scenario):
    b, a, d, _ = acceptance
    (ws / "out.json").write_text('{"n": 1, "extra": "deviates from frozen schema"}')
    rep = accept(b, a, {**d, "claimed_status": "SUCCESS, matches design"}, ws, trust)
    assert rep["status"] == "FAIL"
    assert rep["producer_claimed_status"] == "SUCCESS, matches design"
    assert rep["design_deviation"]["denominator"] == 3
    assert rep["design_deviation"]["deviated"] >= 1 and rep["design_deviation"]["rate_lower"] > 0
    (ws / "out.json").write_text('{"n": 1}')
    (ws / "design.md").write_bytes(b"design v1 (silently edited)")
    rep = accept(b, a, d, ws, trust)
    assert rep["status"] == "FAIL" and "DESIGN_DOCUMENT_MODIFIED" in rep["global_reason_codes"]


def test_R_phi_true_does_not_imply_acceptance_pass(acceptance, scenario, ws, trust):
    contract, state = scenario
    (ws / "in.txt").write_bytes(b"payload\n")
    b, a, d, _ = acceptance
    (ws / "out.json").write_text('{"n": 5}')
    phi = evaluate(contract, state, full_evidence(contract, ws), checkpoint="COMMIT", workspace=ws, trust_store=trust)
    rep = accept(b, a, d, ws, trust)
    assert phi.verdict is Verdict.TRUE
    assert rep["status"] == "FAIL" and rep["phi_verdict_consulted"] is False


def test_acceptance_llm_and_manual_cannot_pass(acceptance, ws, trust):
    b, a, d, authority = acceptance
    b2 = copy.deepcopy(b)
    b2["requirements"].append({"requirement_id": "R4", "text": "looks good", "verification": {"method": "llm_judgment"}})
    a2 = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [
        make_anchor_entry(b2, anchored_by="authority", anchored_at=NOW, key_id="k-auth", secret=authority)]}
    d2 = {**d, "trace": d["trace"] + [{"requirement_id": "R4"}]}
    rep = accept(b2, a2, d2, ws, trust)
    assert rep["status"] == "INCONCLUSIVE"
    assert rep["design_deviation"]["unknown"] == 1 and rep["design_deviation"]["rate_upper"] == 0.25


# --------------------------------------------------------------------------- S-T


def test_S_concurrent_subtasks_with_state_changes(ws, trust, tmp_path):
    """Three subtasks run concurrently against one host state store. Between DISPATCH and
    COMMIT, the host changes shared state (an ownership grab and a dependency failure).
    Every COMMIT re-evaluates against the latest state; only the unaffected subtask commits."""
    lock = threading.Lock()
    store = base_state(tasks={"p": {"status": "running"}, "s1": {"status": "ready"},
                              "s2": {"status": "ready"}, "s3": {"status": "ready"}, "dep-a": {"status": "completed"}},
                       file_owners={"s1.out": "s1", "s2.out": "s2", "s3.out": "s3"})
    contracts = {}
    for t in ("s1", "s2", "s3"):
        c = base_contract(parent_task_id="p", outputs=[{"path": f"{t}.out"}],
                          dependencies=["dep-a"] if t == "s3" else [])
        c["task_id"] = t
        contracts[t] = c

    def latest_state():
        with lock:
            return copy.deepcopy(store)

    log = AuditLog(tmp_path / "audit.jsonl")
    gate = PhiGate(workspace=ws, trust_store=trust, audit_log=log)
    dispatched = threading.Barrier(4, timeout=30)
    mutated = threading.Event()
    outcome = {}

    def run(t):
        session = GateSession(gate, contracts[t])
        decision, _ = session.preflight(latest_state, lambda: observe_files(contracts[t], ws, EARLIER))
        assert decision.release, decision.result.reason_codes
        (ws / f"{t}.out").write_text(t)
        dispatched.wait()
        assert mutated.wait(30)
        try:
            session.commit(latest_state, lambda: observe_files(contracts[t], ws, EARLIER),
                           action=lambda: outcome.__setitem__(t, "COMMITTED"))
        except GateDenied as denied:
            outcome[t] = denied.decision.result.verdict.value

    threads = [threading.Thread(target=run, args=(t,)) for t in contracts]
    for th in threads:
        th.start()
    dispatched.wait()
    with lock:
        store["file_owners"]["s2.out"] = "intruder"
        store["tasks"]["dep-a"]["status"] = "failed"
    mutated.set()
    for th in threads:
        th.join(10)
    assert outcome == {"s1": "COMMITTED", "s2": "FALSE", "s3": "FALSE"}
    chain = log.verify()
    assert chain["ok"] and chain["records"] == 9  # 3 x (PLAN, DISPATCH, COMMIT)


def test_T_unknown_is_never_released(scenario, ws, trust, tmp_path):
    contract, state = scenario
    marker, action = ran_marker(tmp_path)
    gate = PhiGate(workspace=ws, trust_store=trust)
    unknown_cases = [
        (contract, state, []),
        (contract, base_state(tasks={TASK: {"status": "ready"}}), full_evidence(contract, ws)),
        ({**contract, "constraint_scope": {"complete": False}}, state, full_evidence(contract, ws)),
        (contract, state, full_evidence(contract, ws) + [attest("x", "tests", {"passed": False})]),
    ]
    for c, s, e in unknown_cases:
        decision = gate.check("COMMIT", c, s, e)
        assert decision.result.verdict is Verdict.UNKNOWN
        assert decision.release is False and decision.action == "PAUSE_REQUEST_EVIDENCE"
        with pytest.raises(GateNeedsEvidence):
            gate.guard("COMMIT", c, s, e, action)
        with pytest.raises(DecisionInvalid):
            gate.authorize(decision, c, s, e)
    assert not marker.exists()
    req = tmp_path / "req.json"
    req.write_text(json.dumps({"contract": contract, "state": state, "evidence": [], "checkpoint": "COMMIT"}))
    run = subprocess.run([sys.executable, "-m", "phi_core.cli", "gate-exec", "--request", str(req),
                          "--workspace", str(ws), "--", sys.executable, "-c",
                          f"open({str(marker)!r},'w').write('x')"], capture_output=True, text=True)
    assert run.returncode == 20 and not marker.exists()


def test_T_harness_blocked_actions_never_run_and_completion_not_committed(tmp_path):
    script = ROOT / "examples" / "minimal_harness" / "harness.py"
    expected = {"ok": (0, "completed"), "dependency_pending": (20, "ready"), "tampered_input": (10, "ready"),
                "bad_output": (10, "ready"), "ownership_conflict": (10, "ready"), "contract_edit_midrun": (20, "ready")}
    for name, (code, task_status) in expected.items():
        ws = tmp_path / name
        run = subprocess.run([sys.executable, str(script), "--workspace", str(ws), "--scenario", name],
                             capture_output=True, text=True)
        assert run.returncode == code, (name, run.stdout, run.stderr)
        out = json.loads(run.stdout)
        assert out["task_status"] == task_status
        outputs = [f for f in out["files"] if f.startswith("output/")]
        if name in ("dependency_pending", "tampered_input", "ownership_conflict"):
            assert outputs == [] and out["executed_steps"] == []
        if name == "contract_edit_midrun":
            assert out["executed_steps"] == ["uppercase"] and outputs == ["output/upper.txt"]
        if name == "bad_output":
            # Not rolled back: steps released at STEP keep their files; COMMIT blocks completion only.
            assert out["executed_steps"] == ["uppercase", "count"] and len(outputs) == 2
        if name == "ok":
            assert out["executed_steps"] == ["uppercase", "count"]
        log = AuditLog(out["audit_log"])
        assert log.verify()["ok"]
