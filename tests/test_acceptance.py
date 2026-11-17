import ast
import copy
import json

import pytest

from conftest import NOW, ROOT, attest, sha
from phi_core import TrustStore, make_anchor_entry, run_acceptance

ACC = ROOT / "examples" / "acceptance"
WS = ROOT / "examples" / "v1" / "workspace"


def load(name):
    return json.loads((ACC / name).read_text("utf-8"))


@pytest.fixture
def demo_trust():
    return TrustStore.from_dict(json.loads((ROOT / "examples" / "trust.demo.json").read_text("utf-8")))


def run(b=None, a=None, d=None, trust=None, **kw):
    return run_acceptance(b or load("baseline.json"), a if a is not None else load("anchor.json"),
                          d or load("delivery.json"), workspace=WS, now=NOW, trust_store=trust, **kw)


def test_example_passes(demo_trust):
    rep = run(trust=demo_trust, require_signed_anchor=True)
    assert rep["status"] == "PASS", rep
    assert rep["independent_of_phi"] is True and rep["phi_verdict_consulted"] is False
    assert rep["design_deviation"]["rate_lower"] == 0.0
    assert [r["requirement_id"] for r in rep["requirement_results"]] == ["R1", "R2", "R3", "R4"]


def test_acceptance_module_does_not_import_phi_engine():
    tree = ast.parse((ROOT / "src" / "phi_core" / "acceptance.py").read_text("utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"evaluator", "gate", "predicates", "audit"}


def test_no_anchor_inconclusive(demo_trust):
    rep = run_acceptance(load("baseline.json"), None, load("delivery.json"), workspace=WS, now=NOW, trust_store=demo_trust)
    assert rep["status"] == "INCONCLUSIVE" and "NO_TRUSTED_ANCHOR" in rep["global_reason_codes"]


def test_unsigned_anchor_when_signature_required(demo_trust):
    b = load("baseline.json")
    a = {"anchor_version": "1.0", "baseline_id": b["baseline_id"],
         "revisions": [make_anchor_entry(b, anchored_by="x", anchored_at=NOW)]}
    assert run(a=a, trust=demo_trust)["status"] == "PASS"
    rep = run(a=a, trust=demo_trust, require_signed_anchor=True)
    assert rep["status"] == "INCONCLUSIVE" and "ANCHOR_UNSIGNED" in rep["global_reason_codes"]


def test_signed_anchor_without_any_trust_store_is_inconclusive():
    rep = run()
    assert rep["status"] == "INCONCLUSIVE" and "ANCHOR_KEY_UNKNOWN" in rep["global_reason_codes"]
    assert rep["requirement_results"] == []


def test_evidence_requirement_without_ci_key_is_inconclusive():
    keys = json.loads((ROOT / "examples" / "trust.demo.json").read_text())["keys"]
    authority_only = TrustStore.from_dict({"keys": {"acceptance-authority-demo": keys["acceptance-authority-demo"]}})
    rep = run(trust=authority_only)
    r4 = next(r for r in rep["requirement_results"] if r["requirement_id"] == "R4")
    assert rep["status"] == "INCONCLUSIVE"
    assert r4["status"] == "INCONCLUSIVE" and "UNKNOWN_SIGNING_KEY" in r4["reason_codes"]


def test_evidence_value_mismatch_and_conflict(demo_trust):
    secret = bytes.fromhex(json.loads((ROOT / "examples" / "trust.demo.json").read_text())["keys"]["ci-demo-key"]["secret_hex"])
    d = load("delivery.json")
    d["evidence"] = [attest("x", "acceptance:tests", {"passed": False}, key_id="ci-demo-key", secret=secret)]
    rep = run(d=d, trust=demo_trust)
    assert rep["status"] == "FAIL"
    d["evidence"].append(attest("y", "acceptance:tests", {"passed": True}, key_id="ci-demo-key", secret=secret))
    rep = run(d=d, trust=demo_trust)
    r4 = next(r for r in rep["requirement_results"] if r["requirement_id"] == "R4")
    assert r4["status"] == "INCONCLUSIVE" and "EVIDENCE_CONFLICT" in r4["reason_codes"]


def test_delivery_targeting_other_revision_fails(demo_trust):
    d = load("delivery.json")
    d["baseline_revision"] = 7
    rep = run(d=d, trust=demo_trust)
    assert rep["status"] == "FAIL" and "DELIVERY_BASELINE_MISMATCH" in rep["global_reason_codes"]


def test_invalid_inputs(demo_trust):
    assert run_acceptance({"x": 1}, load("anchor.json"), load("delivery.json"), workspace=WS, now=NOW)["status"] == "INCONCLUSIVE"
    rep = run(d={"nonsense": True}, trust=demo_trust)
    assert rep["status"] == "FAIL"  # every requirement untraced => omitted
    assert "DELIVERY_SCHEMA_INVALID" in rep["global_reason_codes"]


def test_empty_requirement_set_is_not_pass(demo_trust, tmp_path):
    b = load("baseline.json")
    b["requirements"] = []
    a = {"anchor_version": "1.0", "baseline_id": b["baseline_id"],
         "revisions": [make_anchor_entry(b, anchored_by="x", anchored_at=NOW)]}
    rep = run(b=b, a=a, trust=demo_trust)
    assert rep["status"] == "INCONCLUSIVE" and rep["design_deviation"]["rate_lower"] is None


def test_command_timeout_inconclusive(demo_trust):
    b = load("baseline.json")
    b["requirements"][2]["verification"] = {"method": "command", "argv": ["{python}", "-c", "import time; time.sleep(5)"],
                                            "timeout_seconds": 0.5}
    a = {"anchor_version": "1.0", "baseline_id": b["baseline_id"],
         "revisions": [make_anchor_entry(b, anchored_by="x", anchored_at=NOW)]}
    rep = run(b=b, a=a, trust=demo_trust)
    r3 = next(r for r in rep["requirement_results"] if r["requirement_id"] == "R3")
    assert r3["status"] == "INCONCLUSIVE" and "COMMAND_TIMEOUT" in r3["reason_codes"]


def test_anchor_chain_must_be_consistent(demo_trust):
    a = load("anchor.json")
    a["revisions"].append({**a["revisions"][0], "revision": 2, "previous_revision_hash": "f" * 64})
    rep = run(a=a, trust=demo_trust)
    assert rep["status"] == "INCONCLUSIVE" and "ANCHOR_CHAIN_INVALID" in rep["global_reason_codes"]


def test_untraced_extras_reported(demo_trust):
    d = load("delivery.json")
    d["trace"].append({"requirement_id": "R99", "artifacts": ["bonus.txt"]})
    rep = run(d=d, trust=demo_trust)
    assert rep["status"] == "PASS" and rep["untraced_delivery_entries"] == ["R99"]


def test_does_not_mutate_inputs(demo_trust):
    b, a, d = load("baseline.json"), load("anchor.json"), load("delivery.json")
    snap = json.dumps([b, a, d], sort_keys=True)
    run(b=b, a=a, d=d, trust=demo_trust)
    assert json.dumps([b, a, d], sort_keys=True) == snap
