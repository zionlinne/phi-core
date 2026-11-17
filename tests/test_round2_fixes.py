"""Regression, legal-control, boundary, property, integration, replay and
concurrency tests for the six defects reported by the independent test of
963d12b (SCHEMA-CRITERION-MUTABLE, SCHEMA-REF-FETCH,
ACCEPT-COMMAND-UNPINNED-SCRIPT, ANCHOR-KEY-SOURCES-IGNORED,
RUNNER-PLAN-USES-DISPATCH-EVIDENCE, EVIDENCE-NOT-BOUND-TO-TASK)."""

import copy
import http.server
import json
import socket
import threading

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import EARLIER, NOW, ROOT, SECRET, TASK, attest, base_contract, base_state, sha
from phi_core import (
    AuditLog,
    GateBlocked,
    GatedRunner,
    GateSession,
    HarnessAdapter,
    PhiEngine,
    PhiGate,
    Step,
    TrustStore,
    Verdict,
    check_document,
    contract_hash,
    evaluate,
    make_anchor_entry,
    make_evidence,
    new_revision,
    observe_files,
    replay_log,
    run_acceptance,
    sign_evidence,
)

SCHEMA = {"type": "object", "required": ["n"], "properties": {"n": {"type": "integer"}},
          "additionalProperties": False}
SCHEMA_BYTES = json.dumps(SCHEMA).encode()
AUTH_SECRET = b"authority-secret-0123456789abcdef"


# --------------------------------------------------------------------------- helpers


@pytest.fixture
def http_hits():
    """A local HTTP server that serves a permissive schema and counts requests."""
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hits
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def no_network(monkeypatch):
    attempts = []
    real_connect = socket.socket.connect

    def guarded(self, address):
        attempts.append(address)
        raise OSError("network disabled in test")

    monkeypatch.setattr(socket.socket, "connect", guarded)
    yield attempts
    monkeypatch.setattr(socket.socket, "connect", real_connect)


def schema_contract(schema_sha256=None, schema_refs=None, **kw):
    out = {"path": "out.json", "schema": "schema.json"}
    if schema_sha256 is not None:
        out["schema_sha256"] = schema_sha256
    if schema_refs is not None:
        out["schema_refs"] = schema_refs
    return base_contract(outputs=[out], **kw)


def phi(contract, ws, checkpoint="COMMIT", state=None, evidence=None, trust=None):
    ev = observe_files(contract, ws, EARLIER) if evidence is None else evidence
    return evaluate(contract, state or base_state(file_owners={"out.json": TASK}), ev,
                    checkpoint=checkpoint, workspace=ws, trust_store=trust)


def write_schema_ws(ws, schema=SCHEMA, out='{"n": 1}'):
    (ws / "schema.json").write_text(json.dumps(schema))
    (ws / "out.json").write_text(out)
    return sha(json.dumps(schema).encode())


def authority_trust(trust=None):
    t = trust or TrustStore()
    t.add_key("k-ci", SECRET, ["ci-runner"])
    t.add_key("k-auth", AUTH_SECRET, ["acceptance-authority"], purposes=["baseline-anchor"])
    return t


def baseline_with(requirements, design_bytes=b"design v1"):
    return {"baseline_version": "1.0", "baseline_id": "B", "revision": 1, "previous_revision_hash": None,
            "frozen_at": "2026-11-01T00:00:00Z",
            "design": {"design_id": "D", "version": "1", "sha256": sha(design_bytes), "path": "design.md"},
            "requirements": requirements, "change_log": [{"revision": 1, "summary": "initial"}]}


def accept(ws, requirements, delivery_evidence=(), trust=None, **kw):
    if not (ws / "design.md").exists():
        (ws / "design.md").write_bytes(b"design v1")
    b = baseline_with(requirements)
    trust = trust or authority_trust()
    anchor = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [
        make_anchor_entry(b, anchored_by="authority", anchored_at="2026-11-01T00:00:00Z",
                          key_id="k-auth", secret=AUTH_SECRET)]}
    delivery = {"delivery_version": "1.0", "baseline_id": "B", "baseline_revision": 1,
                "trace": [{"requirement_id": r["requirement_id"]} for r in requirements],
                "evidence": list(delivery_evidence)}
    return run_acceptance(b, anchor, delivery, workspace=ws, now=NOW, trust_store=trust,
                          require_signed_anchor=True, **kw)


def req_status(rep, rid):
    r = next(x for x in rep["requirement_results"] if x["requirement_id"] == rid)
    return r["status"], r["reason_codes"]


# =========================================================================== 1. schema criterion frozen


def test_1_regression_step_rewrites_schema_phi_not_true(ws):
    """Probe input: pinned output schema, a released step replaces it with {} and
    writes a non-conforming output. 963d12b returned TRUE at COMMIT."""
    digest = write_schema_ws(ws)
    c = schema_contract(digest)
    assert phi(c, ws).verdict is Verdict.TRUE
    (ws / "schema.json").write_text("{}")
    (ws / "out.json").write_text('{"n": "not-an-int"}')
    r = phi(c, ws)
    assert r.verdict is Verdict.FALSE and "SCHEMA_CRITERION_MODIFIED" in r.reason_codes


def test_1_unpinned_schema_is_not_a_criterion(ws):
    write_schema_ws(ws)
    r = phi(schema_contract(), ws)
    assert r.verdict is Verdict.UNKNOWN and "SCHEMA_CRITERION_NOT_PINNED" in r.reason_codes
    (ws / "schema.json").write_text("{}")
    (ws / "out.json").write_text('{"n": "x"}')
    assert phi(schema_contract(), ws).verdict is not Verdict.TRUE


def test_1_legal_controls_phi(ws):
    digest = write_schema_ws(ws)
    c = schema_contract(digest)
    assert phi(c, ws).verdict is Verdict.TRUE
    (ws / "out.json").write_text('{"n": "x"}')
    r = phi(c, ws)
    assert r.verdict is Verdict.FALSE and "SCHEMA_INCOMPATIBLE" in r.reason_codes
    (ws / "out.json").unlink()
    r = phi(c, ws)
    assert r.verdict is Verdict.FALSE


def test_1_schema_pin_without_schema_is_semantically_invalid(ws):
    c = base_contract(outputs=[{"path": "out.json", "schema_sha256": "0" * 64}])
    r = evaluate(c, base_state(), [], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "CONTRACT_SEMANTIC_INVALID" in r.reason_codes


def test_1_regression_acceptance_schema_rewrite_not_pass(ws):
    digest = write_schema_ws(ws)
    reqs = [{"requirement_id": "R1", "text": "schema", "verification": {
        "method": "json_schema", "path": "out.json", "schema_path": "schema.json", "schema_sha256": digest}}]
    assert accept(ws, reqs)["status"] == "PASS"
    (ws / "schema.json").write_text("{}")
    (ws / "out.json").write_text('{"n": "x"}')
    rep = accept(ws, reqs)
    assert rep["status"] == "FAIL" and req_status(rep, "R1") == ("FAIL", ["SCHEMA_CRITERION_MODIFIED"])


def test_1_acceptance_unpinned_and_legal_controls(ws):
    write_schema_ws(ws)
    unpinned = [{"requirement_id": "R1", "text": "schema", "verification": {
        "method": "json_schema", "path": "out.json", "schema_path": "schema.json"}}]
    rep = accept(ws, unpinned)
    assert rep["status"] == "INCONCLUSIVE" and req_status(rep, "R1")[1] == ["SCHEMA_CRITERION_NOT_PINNED"]
    pinned = copy.deepcopy(unpinned)
    pinned[0]["verification"]["schema_sha256"] = sha(SCHEMA_BYTES)
    (ws / "out.json").write_text('{"n": "x"}')
    rep = accept(ws, pinned)
    assert rep["status"] == "FAIL" and req_status(rep, "R1")[1] == ["SCHEMA_INCOMPATIBLE"]
    (ws / "out.json").write_text("not json")
    assert req_status(accept(ws, pinned), "R1") == ("FAIL", ["OUTPUT_NOT_JSON"])


def test_1_examples_pin_their_schemas():
    contract = json.loads((ROOT / "examples" / "v1" / "contract.json").read_text())
    baseline = json.loads((ROOT / "examples" / "acceptance" / "baseline.json").read_text())
    schema_file = ROOT / "examples" / "v1" / "workspace" / "schemas" / "summary.schema.json"
    digest = sha(schema_file.read_bytes())
    assert contract["outputs"][0]["schema_sha256"] == digest
    r2 = next(r for r in baseline["requirements"] if r["requirement_id"] == "R2")
    assert r2["verification"]["schema_sha256"] == digest


# =========================================================================== 2. no implicit ref fetch


@pytest.mark.parametrize("ref_kind", ["http", "https_bad", "file_abs", "urn", "escape", "foreign_id"])
def test_2_regression_external_refs_fail_closed_without_fetch(ws, tmp_path, http_hits, ref_kind):
    base, hits = http_hits
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    refs = {"http": f"{base}/schema.json", "https_bad": "https://phi-core-test.invalid/s.json",
            "file_abs": outside.as_uri(), "urn": "urn:example:thing", "escape": "../outside.json"}
    schema = {"$ref": refs.get(ref_kind, "other.json")}
    if ref_kind == "foreign_id":
        schema = {"$id": f"{base}/root.json", "$ref": "other.json"}
        (ws / "other.json").write_text("{}")
    digest = write_schema_ws(ws, schema, '{"n": "anything"}')
    r = phi(schema_contract(digest), ws)
    assert r.verdict is Verdict.UNKNOWN and "SCHEMA_REF_UNRESOLVABLE" in r.reason_codes
    reqs = [{"requirement_id": "R1", "text": "s", "verification": {
        "method": "json_schema", "path": "out.json", "schema_path": "schema.json", "schema_sha256": digest}}]
    rep = accept(ws, reqs)
    assert rep["status"] == "INCONCLUSIVE" and req_status(rep, "R1")[1] == ["SCHEMA_REF_UNRESOLVABLE"]
    assert hits == []


def test_2_fragment_ref_is_supported(ws):
    schema = {"$defs": {"n": {"type": "integer"}}, "type": "object", "required": ["n"],
              "properties": {"n": {"$ref": "#/$defs/n"}}}
    digest = write_schema_ws(ws, schema)
    assert phi(schema_contract(digest), ws).verdict is Verdict.TRUE
    (ws / "out.json").write_text('{"n": "x"}')
    assert phi(schema_contract(digest), ws).verdict is Verdict.FALSE


def test_2_relative_ref_requires_pin_and_detects_change(ws):
    (ws / "sub").mkdir()
    defs = {"$defs": {"n": {"type": "integer"}}}
    (ws / "defs.json").write_text(json.dumps(defs))
    schema = {"type": "object", "properties": {"n": {"$ref": "defs.json#/$defs/n"}}, "required": ["n"]}
    digest = write_schema_ws(ws, schema)
    r = phi(schema_contract(digest), ws)
    assert r.verdict is Verdict.UNKNOWN and "SCHEMA_REF_NOT_PINNED" in r.reason_codes
    pins = {"defs.json": sha(json.dumps(defs).encode())}
    assert phi(schema_contract(digest, pins), ws).verdict is Verdict.TRUE
    (ws / "out.json").write_text('{"n": "x"}')
    assert phi(schema_contract(digest, pins), ws).verdict is Verdict.FALSE
    (ws / "out.json").write_text('{"n": "x"}')
    (ws / "defs.json").write_text(json.dumps({"$defs": {"n": {}}}))
    r = phi(schema_contract(digest, pins), ws)
    assert r.verdict is Verdict.FALSE and "SCHEMA_CRITERION_MODIFIED" in r.reason_codes


def test_2_nested_relative_ref_and_metaschema_resolve_offline(ws, no_network):
    (ws / "sub").mkdir()
    (ws / "defs.json").write_text('{"$defs": {"n": {"type": "integer"}}}')
    (ws / "sub" / "rel.json").write_text('{"$ref": "../defs.json#/$defs/n"}')
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
              "type": "object", "properties": {"n": {"$ref": "sub/rel.json"}}}
    write_schema_ws(ws, schema)
    check = check_document(ws, "schema.json", {"n": 3})
    assert check.code is None and check.valid is True
    assert set(check.closure) == {"schema.json", "sub/rel.json", "defs.json"}
    assert no_network == []


def test_2_loader_errors_are_structured(ws):
    assert check_document(ws, "missing.json", {}).code == "SCHEMA_FILE_MISSING"
    assert check_document(ws, "../x.json", {}).code == "SCHEMA_PATH_OUTSIDE_WORKSPACE"
    (ws / "bad.json").write_text("{not json")
    assert check_document(ws, "bad.json", {}).code == "SCHEMA_FILE_INVALID"
    (ws / "meta.json").write_text('{"type": 12}')
    assert check_document(ws, "meta.json", {}).code == "SCHEMA_FILE_INVALID"


_REF = st.one_of(
    st.sampled_from(["http://127.0.0.1:9/x", "https://example.com/s.json", "file:///etc/passwd",
                     "//evil.example/x", "urn:x", "../../x.json", "/abs.json", "#", "#/nope",
                     "tag:x", "ftp://h/x", "\\\\host\\x", "%2e%2e/x.json"]),
    st.text(min_size=0, max_size=30),
)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(ref=_REF, doc=st.one_of(st.none(), st.integers(), st.text(max_size=5), st.dictionaries(st.text(max_size=3), st.integers(), max_size=2)))
def test_2_property_random_refs_never_raise_never_connect(ws, no_network, ref, doc):
    (ws / "schema.json").write_text(json.dumps({"$ref": ref}))
    check = check_document(ws, "schema.json", doc)
    assert check.code in (None, "SCHEMA_REF_UNRESOLVABLE", "SCHEMA_FILE_INVALID", "SCHEMA_VALIDATION_ERROR")
    assert no_network == []


# =========================================================================== 3. command criteria frozen


CHECK_OK = b"import sys\nsys.exit(0 if open('out.txt').read() == 'ok' else 1)\n"


def cmd_req(argv, **extra):
    return [{"requirement_id": "R1", "text": "cmd", "verification": {"method": "command", "argv": argv, **extra}}]


def test_3_regression_agent_rewritten_script_cannot_pass(ws):
    """Probe input: baseline runs a workspace script; the agent rewrites it to exit 0."""
    (ws / "out.txt").write_text("bad")
    (ws / "check.py").write_bytes(b"import sys; sys.exit(0)\n")
    rep = accept(ws, cmd_req(["{python}", "check.py"]))
    assert rep["status"] == "INCONCLUSIVE"
    assert req_status(rep, "R1")[1] == ["COMMAND_WORKSPACE_FILE_NOT_PINNED"]


def test_3_pinned_script_legal_controls(ws):
    (ws / "check.py").write_bytes(CHECK_OK)
    pins = {"pinned_files": [{"path": "check.py", "sha256": sha(CHECK_OK)}], "artifacts": ["out.txt"]}
    (ws / "out.txt").write_text("ok")
    rep = accept(ws, cmd_req(["{python}", "-I", "check.py"], **pins))
    assert rep["status"] == "PASS"
    r = rep["requirement_results"][0]
    assert r["detail"]["pinned_files_verified"] == ["check.py"]
    (ws / "out.txt").write_text("bad")
    assert req_status(accept(ws, cmd_req(["{python}", "-I", "check.py"], **pins)), "R1") == \
        ("FAIL", ["COMMAND_EXIT_CODE_UNEXPECTED"])


def test_3_modified_or_missing_pinned_file_fails_before_running(ws, tmp_path):
    marker = tmp_path / "ran"
    script = f"open({str(marker)!r}, 'w').write('x')\n".encode()
    (ws / "check.py").write_bytes(script)
    pins = {"pinned_files": [{"path": "check.py", "sha256": sha(CHECK_OK)}]}
    rep = accept(ws, cmd_req(["{python}", "check.py"], **pins))
    assert req_status(rep, "R1") == ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED"]) and not marker.exists()
    (ws / "check.py").unlink()
    assert req_status(accept(ws, cmd_req(["{python}", "check.py"], **pins)), "R1") == \
        ("FAIL", ["COMMAND_PINNED_FILE_MISSING"])


def test_3_pinned_config_read_by_name_inside_program(ws):
    script = b"import json,sys\nsys.exit(0 if json.load(open('cfg.json'))['strict'] else 1)\n"
    (ws / "check.py").write_bytes(script)
    (ws / "cfg.json").write_text('{"strict": true}')
    pins = {"pinned_files": [{"path": "check.py", "sha256": sha(script)},
                             {"path": "cfg.json", "sha256": sha(b'{"strict": true}')}]}
    assert accept(ws, cmd_req(["{python}", "check.py"], **pins))["status"] == "PASS"
    (ws / "cfg.json").write_text('{"strict": false}')
    assert req_status(accept(ws, cmd_req(["{python}", "check.py"], **pins)), "R1") == \
        ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED"])


def test_3_file_modified_during_run_fails(ws):
    script = b"open('check.py', 'a').write('# changed\\n')\n"
    (ws / "check.py").write_bytes(script)
    pins = {"pinned_files": [{"path": "check.py", "sha256": sha(script)}]}
    assert req_status(accept(ws, cmd_req(["{python}", "check.py"], **pins)), "R1") == \
        ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED_DURING_RUN"])


@pytest.mark.parametrize("argv,setup", [
    (["{python}", "-m", "checks.run"], {"checks/run.py": "pass\n"}),
    (["{python}", "-m", "checks"], {"checks/__main__.py": "pass\n"}),
    (["{python}", "tool", "--config=conf.ini"], {"conf.ini": "x"}),
    (["{python}", "-c", "pass", "checks"], {"checks/a.py": "pass\n"}),
])
def test_3_boundary_unpinned_argv_files_detected(ws, argv, setup):
    for rel, text in setup.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text)
    rep = accept(ws, cmd_req(argv))
    assert req_status(rep, "R1")[1] == ["COMMAND_WORKSPACE_FILE_NOT_PINNED"]


def test_3_artifacts_are_exempt_and_inline_commands_still_supported(ws):
    (ws / "report").mkdir()
    (ws / "report" / "r.json").write_text('{"n": 1}')
    code = "import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))['n']==1 else 1)"
    rep = accept(ws, cmd_req(["{python}", "-c", code, "report/r.json"], artifacts=["report"]))
    assert rep["status"] == "PASS"
    rep = accept(ws, cmd_req(["{python}", "-c", code, "report/r.json"]))
    assert req_status(rep, "R1")[1] == ["COMMAND_WORKSPACE_FILE_NOT_PINNED"]


# =========================================================================== 4. anchor authority domain


def _anchored(ws, trust, signer_key, signer_secret):
    (ws / "design.md").write_bytes(b"design v1")
    (ws / "out.json").write_text('{"n": 9}')
    reqs = [{"requirement_id": "R1", "text": "exists", "verification": {"method": "file", "path": "out.json"}},
            {"requirement_id": "R2", "text": "n is 1", "verification": {"method": "command", "argv": [
                "{python}", "-c", "import json,sys; sys.exit(0 if json.load(open('out.json'))['n']==1 else 1)"]}}]
    b1 = baseline_with(reqs)
    anchor = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [
        make_anchor_entry(b1, anchored_by="authority", anchored_at="2026-11-01T00:00:00Z",
                          key_id="k-auth", secret=AUTH_SECRET)]}
    b2 = new_revision(b1, requirements=reqs[:1], summary="drop command requirement", frozen_at=NOW)
    anchor["revisions"].append(make_anchor_entry(b2, anchored_by="ci-runner", anchored_at=NOW,
                                                 key_id=signer_key, secret=signer_secret))
    delivery = {"delivery_version": "1.0", "baseline_id": "B", "baseline_revision": 2,
                "trace": [{"requirement_id": "R1"}]}
    return run_acceptance(b2, anchor, delivery, workspace=ws, now=NOW, trust_store=trust, require_signed_anchor=True)


def test_4_regression_evidence_key_cannot_rewrite_requirements(ws):
    rep = _anchored(ws, authority_trust(), "k-ci", SECRET)
    assert rep["status"] == "FAIL" and "ANCHOR_KEY_NOT_AUTHORIZED_FOR_BASELINE" in rep["global_reason_codes"]


def test_4_legal_control_authority_key_can_issue_new_revision(ws):
    rep = _anchored(ws, authority_trust(), "k-auth", AUTH_SECRET)
    assert rep["status"] == "PASS" and rep["global_reason_codes"] == []


def test_4_default_purpose_is_evidence_only(ws):
    t = TrustStore()
    t.add_key("k-auth", AUTH_SECRET, ["acceptance-authority"])
    t.add_key("k-ci", SECRET, ["ci-runner"])
    rep = _anchored(ws, t, "k-auth", AUTH_SECRET)
    assert rep["status"] == "FAIL" and "ANCHOR_KEY_NOT_AUTHORIZED_FOR_BASELINE" in rep["global_reason_codes"]


def test_4_anchor_key_cannot_sign_evidence():
    t = TrustStore()
    t.add_key("k-auth", AUTH_SECRET, ["ci-runner"], purposes=["baseline-anchor"])
    c = base_contract(constraints=[{"constraint_id": "c", "kind": "hard",
                                    "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    r = evaluate(c, base_state(), [attest("e", "c", True, key_id="k-auth", secret=AUTH_SECRET)],
                 checkpoint="PLAN", trust_store=t)
    assert r.verdict is Verdict.UNKNOWN and "KEY_NOT_AUTHORIZED_FOR_EVIDENCE" in r.reason_codes


def test_4_unsigned_revision_after_signed_is_rejected(ws):
    (ws / "design.md").write_bytes(b"design v1")
    (ws / "out.json").write_text("{}")
    reqs = [{"requirement_id": "R1", "text": "x", "verification": {"method": "file", "path": "out.json"}}]
    b1 = baseline_with(reqs)
    b2 = new_revision(b1, requirements=reqs, summary="noop", frozen_at=NOW)
    anchor = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [
        make_anchor_entry(b1, anchored_by="authority", anchored_at="2026-11-01T00:00:00Z",
                          key_id="k-auth", secret=AUTH_SECRET),
        make_anchor_entry(b2, anchored_by="agent", anchored_at=NOW)]}
    delivery = {"delivery_version": "1.0", "baseline_id": "B", "baseline_revision": 2,
                "trace": [{"requirement_id": "R1"}]}
    rep = run_acceptance(b2, anchor, delivery, workspace=ws, now=NOW, trust_store=authority_trust())
    assert rep["status"] == "FAIL" and "ANCHOR_UNSIGNED_REVISION_AFTER_SIGNED" in rep["global_reason_codes"]


def test_4_trust_store_rejects_unknown_purpose():
    with pytest.raises(ValueError):
        TrustStore().add_key("k", SECRET, ["x"], purposes=["admin"])
    with pytest.raises(ValueError):
        TrustStore.from_dict({"keys": {"k": {"secret_hex": SECRET.hex(), "purposes": []}}})


def test_4_demo_trust_store_separates_domains():
    t = TrustStore.load(ROOT / "examples" / "trust.demo.json")
    assert t.keys["ci-demo-key"].purposes == frozenset({"evidence"})
    assert t.keys["acceptance-authority-demo"].purposes == frozenset({"baseline-anchor"})


# =========================================================================== 5. per-checkpoint evidence


def plan_contract():
    return base_contract(constraints=[{"constraint_id": "pre:ok", "kind": "hard", "checkpoints": ["PLAN"],
                                       "predicate": {"type": "attested_value", "params": {"expected": True}}}])


class CheckpointAdapter(HarnessAdapter):
    def __init__(self, contract, by_cp, side):
        self.contract, self.by_cp, self.side, self.asked = contract, by_cp, side, []

    def load_contract(self):
        return self.contract

    def observe_state(self):
        return base_state()

    def collect_evidence(self, checkpoint):
        self.asked.append(checkpoint)
        return self.by_cp.get(checkpoint, [])

    def plan_steps(self):
        return [Step("one", lambda: self.side.append("one"))]

    def commit(self):
        self.side.append("commit")


def test_5_regression_plan_false_dispatch_true_does_not_run(trust):
    side = []
    a = CheckpointAdapter(plan_contract(), {"PLAN": [attest("p", "pre:ok", False)],
                                            "DISPATCH": [attest("d", "pre:ok", True)]}, side)
    rep = GatedRunner(PhiGate(trust_store=trust), a).run()
    assert rep.status == "BLOCKED" and rep.stopped_at == "preflight" and side == []
    assert rep.decisions[0]["checkpoint"] == "PLAN" and rep.decisions[0]["verdict"] == "FALSE"
    assert a.asked[0] == "PLAN"


def test_5_each_checkpoint_gets_its_own_evidence(trust):
    side = []
    a = CheckpointAdapter(plan_contract(), {"PLAN": [attest("p", "pre:ok", True)]}, side)
    rep = GatedRunner(PhiGate(trust_store=trust), a).run()
    assert rep.status == "COMPLETED" and side == ["one", "commit"]
    assert a.asked == ["PLAN", "DISPATCH", "STEP", "COMMIT"]


def test_5_session_provider_receives_checkpoint_zero_arg_still_supported(trust):
    asked = []

    def provider(checkpoint):
        asked.append(checkpoint)
        return [attest("p", "pre:ok", checkpoint == "PLAN")]

    s = GateSession(PhiGate(trust_store=trust), plan_contract())
    d, _ = s.preflight(base_state(), provider)
    assert d.release and asked == ["PLAN", "DISPATCH"]
    s2 = GateSession(PhiGate(trust_store=trust), plan_contract())
    with pytest.raises(GateBlocked):
        s2.preflight(base_state(), lambda: [attest("p", "pre:ok", False)], action=lambda: None)


def test_5_checkpoint_bound_evidence_only_counts_there(trust):
    c = base_contract(constraints=[{"constraint_id": "c", "kind": "hard", "checkpoints": ["PLAN", "COMMIT"],
                                    "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    ev = [attest("e", "c", True, binding={"task_id": TASK, "checkpoints": ["COMMIT"]})]
    plan = evaluate(c, base_state(), ev, checkpoint="PLAN", trust_store=trust)
    assert plan.verdict is Verdict.UNKNOWN and "EVIDENCE_NOT_BOUND_TO_CHECKPOINT" in plan.reason_codes
    assert evaluate(c, base_state(), ev, checkpoint="COMMIT", trust_store=trust).verdict is Verdict.TRUE


# =========================================================================== 6. evidence bound to task


def two_tasks():
    cons = [{"constraint_id": "tests:unit", "kind": "hard",
             "predicate": {"type": "attested_value", "params": {"expected": {"passed": True}}}}]
    a = base_contract(task_id="task-A", constraints=cons)
    b = base_contract(task_id="task-B", constraints=cons)
    state = base_state(tasks={"task-A": {"status": "ready"}, "task-B": {"status": "ready"}})
    return a, b, state


def test_6_regression_cross_task_reuse_rejected(trust):
    """Probe input: one HMAC attestation with provenance.task_id=task-A given to two tasks."""
    a, b, state = two_tasks()
    legacy = attest("e", "tests:unit", {"passed": True}, binding=None, provenance={"task_id": "task-A"})
    assert "binding" not in legacy
    for c in (a, b):
        r = evaluate(c, state, [legacy], checkpoint="COMMIT", trust_store=trust)
        assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_NOT_BOUND_TO_TASK" in r.reason_codes
    bound_a = attest("e", "tests:unit", {"passed": True}, binding={"task_id": "task-A"})
    assert evaluate(a, state, [bound_a], checkpoint="COMMIT", trust_store=trust).verdict is Verdict.TRUE
    rb = evaluate(b, state, [bound_a], checkpoint="COMMIT", trust_store=trust)
    assert rb.verdict is Verdict.UNKNOWN and "EVIDENCE_BOUND_TO_OTHER_TASK" in rb.reason_codes
    plan = PhiEngine().evaluate_plan([a, b], state, [bound_a], trust_store=trust)
    assert {k: v.verdict for k, v in plan.task_results.items()} == {"task-A": Verdict.TRUE, "task-B": Verdict.UNKNOWN}
    assert plan.verdict is not Verdict.TRUE


def test_6_binding_is_signed(trust):
    a, b, state = two_tasks()
    bound_a = attest("e", "tests:unit", {"passed": True}, binding={"task_id": "task-A"})
    moved = copy.deepcopy(bound_a)
    moved["binding"]["task_id"] = "task-B"
    r = evaluate(b, state, [moved], checkpoint="COMMIT", trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "SIGNATURE_INVALID" in r.reason_codes


def test_6_contract_hash_binding(trust):
    a, _, state = two_tasks()
    good = attest("e", "tests:unit", {"passed": True}, binding={"task_id": "task-A", "contract_hash": contract_hash(a)})
    assert evaluate(a, state, [good], checkpoint="COMMIT", trust_store=trust).verdict is Verdict.TRUE
    changed = copy.deepcopy(a)
    changed["objective"] = "something else"
    r = evaluate(changed, state, [good], checkpoint="COMMIT", trust_store=trust)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_BOUND_TO_OTHER_CONTRACT" in r.reason_codes


def test_6_reobserved_file_evidence_may_be_unbound_but_not_bound_elsewhere(ws):
    (ws / "in.txt").write_text("x")
    c = base_contract(inputs=[{"path": "in.txt", "sha256": sha(b"x")}])
    unbound = [make_evidence("f", "input:in.txt:sha256", source="o", verifier_id="file_sha256",
                             observed_value={"path": "in.txt"}, timestamp=EARLIER),
               make_evidence("g", "input:in.txt:exists", source="o", verifier_id="file_sha256",
                             observed_value={"path": "in.txt"}, timestamp=EARLIER)]
    assert evaluate(c, base_state(), unbound, checkpoint="DISPATCH", workspace=ws).verdict is Verdict.TRUE
    other = [dict(e, binding={"task_id": "other"}) for e in unbound]
    r = evaluate(c, base_state(), other, checkpoint="DISPATCH", workspace=ws)
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_BOUND_TO_OTHER_TASK" in r.reason_codes


def test_6_custom_verifier_claims_require_binding(trust):
    class Echo:
        verifier_id = "echo"

        def verify(self, item, ctx):
            from phi_core.evidence import VStatus, _result
            return _result(item, VStatus.VERIFIED, observed=item.observed_value)

    engine = PhiEngine()
    engine.verifiers.register(Echo())
    c = base_contract(constraints=[{"constraint_id": "c", "kind": "hard", "evidence": {"verifiers": ["echo"]},
                                    "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    ev = make_evidence("e", "c", source="s", verifier_id="echo", observed_value=True, timestamp=EARLIER)
    r = engine.evaluate(c, base_state(), [ev], checkpoint="PLAN")
    assert r.verdict is Verdict.UNKNOWN and "EVIDENCE_NOT_BOUND_TO_TASK" in r.reason_codes
    ev["binding"] = {"task_id": TASK}
    assert engine.evaluate(c, base_state(), [ev], checkpoint="PLAN").verdict is Verdict.TRUE


def test_6_acceptance_evidence_bound_to_baseline(ws):
    reqs = [{"requirement_id": "R1", "text": "tests", "verification": {
        "method": "evidence", "evidence_constraint_id": "acc:tests", "expected": {"passed": True}}}]
    mk = lambda b: attest("x", "acc:tests", {"passed": True}, binding=b)  # noqa: E731
    cases = [(None, "EVIDENCE_NOT_BOUND_TO_BASELINE"),
             ({"task_id": TASK}, "EVIDENCE_NOT_BOUND_TO_BASELINE"),
             ({"baseline_id": "other"}, "EVIDENCE_BOUND_TO_OTHER_BASELINE"),
             ({"baseline_id": "B", "baseline_revision": 7}, "EVIDENCE_BOUND_TO_OTHER_REVISION"),
             ({"baseline_id": "B", "requirement_id": "R9"}, "EVIDENCE_BOUND_TO_OTHER_REQUIREMENT")]
    for binding, code in cases:
        status, codes = req_status(accept(ws, reqs, [mk(binding)]), "R1")
        assert status == "INCONCLUSIVE" and code in codes, (binding, codes)
    good = mk({"baseline_id": "B", "baseline_revision": 1, "requirement_id": "R1"})
    assert accept(ws, reqs, [good])["status"] == "PASS"


@settings(max_examples=200, deadline=None)
@given(task=st.sampled_from(["t-main", "task-A", "task-B", "", "T-MAIN"]),
       cps=st.one_of(st.none(), st.lists(st.sampled_from(["PLAN", "DISPATCH", "STEP", "COMMIT"]), min_size=1, unique=True)),
       chash=st.one_of(st.none(), st.sampled_from(["0" * 64, "own"])),
       checkpoint=st.sampled_from(["PLAN", "DISPATCH", "STEP", "COMMIT"]))
def test_6_property_binding_never_crosses_tasks(task, cps, chash, checkpoint):
    trust = TrustStore()
    trust.add_key("k-ci", SECRET, ["ci-runner"])
    c = base_contract(constraints=[{"constraint_id": "c", "kind": "hard",
                                    "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    binding = {"task_id": task}
    if cps is not None:
        binding["checkpoints"] = cps
    if chash is not None:
        binding["contract_hash"] = contract_hash(c) if chash == "own" else chash
    r = evaluate(c, base_state(), [attest("e", "c", True, binding=binding)], checkpoint=checkpoint, trust_store=trust)
    expect_true = task == TASK and (cps is None or checkpoint in cps) and chash in (None, "own")
    assert (r.verdict is Verdict.TRUE) is expect_true


# =========================================================================== integration, replay, concurrency


def test_integration_cli_observe_binds_checkpoint(tmp_path, ws):
    import subprocess
    import sys
    (ws / "in.txt").write_text("x")
    c = base_contract(inputs=[{"path": "in.txt", "sha256": sha(b"x")}])
    cp = tmp_path / "c.json"
    cp.write_text(json.dumps(c))
    out = subprocess.run([sys.executable, "-m", "phi_core.cli", "evidence", "observe", "--contract", str(cp),
                          "--workspace", str(ws), "--now", EARLIER, "--checkpoint", "DISPATCH"],
                         capture_output=True, text=True, check=True)
    items = json.loads(out.stdout)
    assert items and all(i["binding"] == {"task_id": TASK, "checkpoints": ["DISPATCH"]} for i in items)


def test_replay_reproduces_binding_and_schema_decisions(tmp_path, ws, trust):
    digest = write_schema_ws(ws)
    c = schema_contract(digest, constraints=[{"constraint_id": "c", "kind": "hard", "checkpoints": ["COMMIT"],
                                               "predicate": {"type": "attested_value", "params": {"expected": True}}}])
    state = base_state(file_owners={"out.json": TASK})
    log = AuditLog(tmp_path / "audit.jsonl")
    gate = PhiGate(workspace=ws, trust_store=trust, audit_log=log)
    good = observe_files(c, ws, EARLIER) + [attest("e", "c", True)]
    cross = observe_files(c, ws, EARLIER) + [attest("e", "c", True, binding={"task_id": "elsewhere"})]
    assert gate.check("COMMIT", c, state, good).result.verdict is Verdict.TRUE
    assert gate.check("COMMIT", c, state, cross).result.verdict is Verdict.UNKNOWN
    (ws / "schema.json").write_text("{}")
    assert gate.check("COMMIT", c, state, observe_files(c, ws, EARLIER) + [attest("e", "c", True)]).result.verdict \
        is Verdict.FALSE
    assert log.verify()["ok"] is True
    replay = replay_log(log)
    assert [r["replayed_verdict"] for r in replay] == ["TRUE", "UNKNOWN", "FALSE"]
    assert all(r["matches"] for r in replay)
    records = log.records()
    assert records[1]["evidence_results"][-1]["binding"] == {"task_id": "elsewhere"}


def test_concurrent_tasks_never_share_attestations(trust):
    tasks = [f"task-{i}" for i in range(8)]
    state = base_state(tasks={t: {"status": "ready"} for t in tasks})
    cons = [{"constraint_id": "tests", "kind": "hard",
             "predicate": {"type": "attested_value", "params": {"expected": True}}}]
    contracts = {t: base_contract(task_id=t, constraints=cons) for t in tasks}
    pool = [attest(f"e-{t}", "tests", True, binding={"task_id": t}) for t in tasks[::2]]
    results, errors = {}, []

    def worker(t):
        try:
            for _ in range(10):
                r = evaluate(contracts[t], state, pool, checkpoint="COMMIT", trust_store=trust)
                results.setdefault(t, set()).add(r.verdict)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in tasks]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    for i, t in enumerate(tasks):
        assert results[t] == ({Verdict.TRUE} if i % 2 == 0 else {Verdict.UNKNOWN})


def test_concurrent_acceptance_runs_do_not_fetch_or_cross_baselines(ws, http_hits):
    base, hits = http_hits
    (ws / "design.md").write_bytes(b"design v1")
    (ws / "remote.json").write_text(json.dumps({"$ref": f"{base}/x.json"}))
    (ws / "out.json").write_text('{"n": 1}')
    (ws / "schema.json").write_text(json.dumps(SCHEMA))
    reqs_ok = [{"requirement_id": "R1", "text": "s", "verification": {
        "method": "json_schema", "path": "out.json", "schema_path": "schema.json", "schema_sha256": sha(SCHEMA_BYTES)}}]
    reqs_remote = [{"requirement_id": "R1", "text": "s", "verification": {
        "method": "json_schema", "path": "out.json", "schema_path": "remote.json",
        "schema_sha256": sha((ws / "remote.json").read_bytes())}}]
    out, errors = [], []

    def worker(reqs):
        try:
            rep = accept(ws, reqs)
            out.append((reqs is reqs_ok, rep["status"], rep["global_reason_codes"]))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(r,)) for r in [reqs_ok, reqs_remote] * 6]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == [] and hits == []
    assert {s for ok, s, _ in out if ok} == {"PASS"}, out
    assert {s for ok, s, _ in out if not ok} == {"INCONCLUSIVE"}, out
