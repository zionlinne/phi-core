import json

import pytest

from conftest import EARLIER, TASK, attest, base_contract, base_state, file_ev
from phi_core import (
    AuditLog,
    PhiEngine,
    PhiGate,
    Verdict,
    compare_versions,
    reconstruct_state_history,
    replay_log,
    replay_record,
    trace_evidence,
)
from phi_core.audit import AuditError, EVALUATION_FIELDS
from phi_core.predicates import FunctionPredicate, default_predicate_registry, unresolved


def populate(log, trust, ws=None):
    gate = PhiGate(trust_store=trust, audit_log=log, workspace=ws)
    c = base_contract(dependencies=["dep-a"], constraints=[
        {"constraint_id": "tests", "kind": "hard", "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    s1 = base_state()
    s2 = base_state(now="2026-11-17T00:01:00Z")
    s2["tasks"]["dep-a"]["status"] = "failed"
    ev = [attest("ev-1", "tests", True)]
    gate.check("PLAN", c, s1, ev)
    gate.check("DISPATCH", c, s1, ev)
    gate.check("DISPATCH", c, s2, ev)
    gate.check("DISPATCH", c, s1, [])
    return c


def test_records_have_required_fields_and_chain(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    recs = log.records()
    assert [r["verdict"] for r in recs] == ["TRUE", "TRUE", "FALSE", "UNKNOWN"]
    for i, r in enumerate(recs):
        assert all(f in r for f in EVALUATION_FIELDS)
        assert r["seq"] == i
        assert r["previous_record_hash"] == ("0" * 64 if i == 0 else recs[i - 1]["record_hash"])
        assert r["snapshot"]["contract"]["task_id"] == TASK
    assert log.verify()["ok"]


@pytest.mark.parametrize("tamper, code", [
    (lambda lines: lines.__setitem__(1, lines[1].replace('"TRUE"', '"FALSE"', 1)), "RECORD_HASH_MISMATCH"),
    (lambda lines: lines.pop(1), "CHAIN_LINK_BROKEN"),
    (lambda lines: lines.insert(1, lines[1]), "SEQUENCE_GAP_OR_REORDER"),
    (lambda lines: lines.reverse(), "SEQUENCE_GAP_OR_REORDER"),
    (lambda lines: lines.__setitem__(2, "{not json"), "MALFORMED_LINE"),
])
def test_tamper_detection(tmp_path, trust, tamper, code):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    lines = log.path.read_text().splitlines()
    tamper(lines)
    log.path.write_text("\n".join(lines) + "\n")
    report = log.verify()
    assert not report["ok"]
    assert code in {e["code"] for e in report["errors"]}


def test_error_line_numbers_are_one_based_file_lines(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    lines = log.path.read_text().splitlines()
    lines[1] = lines[1].replace('"verdict": "', '"verdict": "X', 1)
    log.path.write_text("\n".join(lines) + "\n")
    errors = log.verify()["errors"]
    assert {"line": 2, "code": "RECORD_HASH_MISMATCH"} in errors


def test_snapshot_tamper_with_recomputed_record_hash_detected(tmp_path, trust):
    from phi_core.audit import record_hash_of

    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    recs = log.records()
    recs[0]["snapshot"]["state"]["tasks"]["dep-a"]["status"] = "failed"
    recs[0]["record_hash"] = record_hash_of(recs[0])
    log.path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    codes = {e["code"] for e in log.verify()["errors"]}
    assert "SNAPSHOT_STATE_HASH_MISMATCH" in codes and "CHAIN_LINK_BROKEN" in codes


def test_full_rewrite_needs_external_anchor(tmp_path, trust):
    """Boundary: rewriting every record consistently passes the internal check;
    only a head hash held elsewhere reveals it."""
    from phi_core.audit import record_hash_of

    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    anchor = log.head()
    recs = log.records()
    recs[2]["verdict"] = "TRUE"
    prev = "0" * 64
    for r in recs:
        r["previous_record_hash"] = prev
        r["record_hash"] = record_hash_of(r)
        prev = r["record_hash"]
    log.path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    assert log.verify()["ok"] is True
    anchored = log.verify(anchor=anchor)
    assert anchored["ok"] is False and anchored["externally_anchored"] is False


def test_append_refuses_corrupt_tail(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    with open(log.path, "a") as fh:
        fh.write("garbage\n")
    with pytest.raises(AuditError):
        log.append({"record_type": "note"})


def test_replay_matches_history(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    results = replay_log(log)
    assert len(results) == 4 and all(r["matches"] for r in results)
    # Replay uses recorded verification results: no trust store needed to reproduce history.
    assert all(r["mode"] == "recorded-verification" for r in results)


def test_replay_reverify_detects_changed_artifacts(tmp_path, ws, trust):
    (ws / "in.txt").write_text("v1")
    log = AuditLog(tmp_path / "a.jsonl")
    c = base_contract(inputs=[{"path": "in.txt"}])
    PhiGate(audit_log=log, workspace=ws).check("DISPATCH", c, base_state(),
                                               [file_ev("e", "input:in.txt:exists", "in.txt")])
    rec = log.records()[0]
    assert replay_record(rec, reverify=True, workspace=ws)["matches"]
    (ws / "in.txt").unlink()
    rr = replay_record(rec, reverify=True, workspace=ws)
    assert not rr["matches"] and rr["replayed_verdict"] == "FALSE"
    assert replay_record(rec)["matches"]


def test_compare_versions(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    strict = default_predicate_registry()
    strict.register("attested_value", FunctionPredicate(lambda p, o: unresolved("POLICY_V2"), kind="evidence"),
                    replace=True)
    v2 = PhiEngine(predicates=strict, evaluator_version="phi-core/2.0.0-test")
    cmp = compare_versions(log.records()[0], PhiEngine(), v2)
    assert cmp["a"]["replayed_verdict"] == "TRUE" and cmp["b"]["replayed_verdict"] == "UNKNOWN"
    assert cmp["same_verdict"] is False


def test_trace_evidence_and_state_history(tmp_path, trust):
    log = AuditLog(tmp_path / "a.jsonl")
    populate(log, trust)
    trace = trace_evidence(log.records(), "ev-1")
    assert [t["seq"] for t in trace] == [0, 1, 2]
    assert trace[0]["claims"][0]["provenance"]["key_id"] == "k-ci"
    assert trace[0]["verification"][0]["status"] == "VERIFIED"
    assert trace[0]["referenced_by_constraints"] == ["tests"]
    hist = reconstruct_state_history(log.records(), TASK)
    assert len(hist) == 4
    changes = {c["path"]: (c["before"], c["after"]) for c in hist[2]["changes"]}
    assert changes["tasks/dep-a/status"] == ("completed", "failed")
    assert changes["now"] == ("2026-11-17T00:00:00Z", "2026-11-17T00:01:00Z")


def test_acceptance_records_in_separate_log(tmp_path):
    log = AuditLog(tmp_path / "acc.jsonl")
    log.append_acceptance({"status": "PASS", "baseline_hash": "a" * 64}, timestamp="2026-11-17T00:00:00Z")
    assert log.verify()["ok"] and log.records()[0]["record_type"] == "acceptance"
