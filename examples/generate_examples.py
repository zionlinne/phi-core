import json, hashlib, pathlib
from phi_core import seal_contract, sign_evidence, make_evidence, make_anchor_entry, baseline_hash
root = pathlib.Path("examples")
v1 = root / "v1"; ws = v1 / "workspace"
(ws / "data").mkdir(parents=True, exist_ok=True); (ws / "report").mkdir(exist_ok=True); (ws / "schemas").mkdir(exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()
csv = b"region,amount\nnorth,10\nsouth,32\n"
(ws / "data" / "input.csv").write_bytes(csv)
schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
          "required": ["total", "rows"], "additionalProperties": False,
          "properties": {"total": {"type": "number"}, "rows": {"type": "integer", "minimum": 0}}}
schema_bytes = (json.dumps(schema, indent=2) + "\n").encode()
(ws / "schemas" / "summary.schema.json").write_bytes(schema_bytes)
(ws / "report" / "summary.json").write_text(json.dumps({"total": 42, "rows": 2}, indent=2) + "\n")
DEMO = {"keys": {
  "ci-demo-key": {"secret_hex": sha(b"phi-core PUBLIC DEMO key - not a secret - ci"), "sources": ["ci-runner"], "purposes": ["evidence"]},
  "acceptance-authority-demo": {"secret_hex": sha(b"phi-core PUBLIC DEMO key - not a secret - authority"), "sources": ["acceptance-authority"], "purposes": ["baseline-anchor"]}},
  "_comment": "PUBLIC DEMO KEYS ONLY. Real deployments must provision secrets out-of-band and never commit them. 'purposes' separates evidence signing from baseline anchoring."}
(root / "trust.demo.json").write_text(json.dumps(DEMO, indent=2) + "\n")
ci_secret = bytes.fromhex(DEMO["keys"]["ci-demo-key"]["secret_hex"])
auth_secret = bytes.fromhex(DEMO["keys"]["acceptance-authority-demo"]["secret_hex"])
TASK = "build-report"
contract = {
  "contract_version": "1.0", "task_id": TASK, "title": "Build summary report",
  "objective": "Aggregate data/input.csv into report/summary.json.",
  "parent_task_id": "monthly-close", "dependencies": ["fetch-data"],
  "inputs": [{"path": "data/input.csv", "sha256": sha(csv)}],
  "outputs": [{"path": "report/summary.json", "schema": "schemas/summary.schema.json", "schema_sha256": sha(schema_bytes)}],
  "capabilities": ["python3"], "resources": [{"name": "cpu", "amount": 1}],
  "time_bounds": {"not_before": "2026-11-01T00:00:00Z", "deadline": "2026-11-30T00:00:00Z"},
  "constraints": [
    {"constraint_id": "tests:unit", "kind": "hard", "category": "postcondition",
     "statement": "unit tests pass (signed CI attestation)",
     "predicate": {"type": "attested_value", "params": {"expected": {"passed": True}}},
     "checkpoints": ["COMMIT"], "evidence": {"verifiers": ["hmac_attestation"], "max_age_seconds": 3600}},
    {"constraint_id": "style:report-readable", "kind": "soft", "statement": "report is readable",
     "predicate": {"type": "natural_language", "params": {}}}],
  "constraint_scope": {"complete": True, "declared_by": "example-host"},
  "evidence_policy": {"default_max_age_seconds": 3600, "conflict_resolution": {"type": "none"}},
  "acceptance": {"baseline_id": "report-req", "baseline_revision": 1},
}
contract = seal_contract(contract)
(v1 / "contract.json").write_text(json.dumps(contract, indent=2) + "\n")
state = {"state_version": "1.0", "now": "2026-11-17T00:00:00Z",
  "tasks": {"fetch-data": {"status": "completed"}, "monthly-close": {"status": "running"}, TASK: {"status": "ready"}},
  "resources": {"cpu": 4}, "capabilities": ["python3"], "capabilities_complete": True,
  "file_owners": {"report/summary.json": TASK}}
(v1 / "state.json").write_text(json.dumps(state, indent=2) + "\n")
ts = "2026-11-16T23:55:00Z"
bind = {"task_id": TASK}
ev = []
for cid, path in [("input:data/input.csv:exists", "data/input.csv"), ("input:data/input.csv:sha256", "data/input.csv"), ("output:report/summary.json:exists", "report/summary.json")]:
    ev.append(make_evidence(f"ev-{cid}", cid, source="example-observer", verifier_id="file_sha256",
        observed_value={"path": path}, timestamp=ts, artifact_hash=sha((ws / path).read_bytes()), binding=bind))
ev.append(make_evidence("ev-schema", "output:report/summary.json:schema", source="example-observer", verifier_id="json_schema",
    observed_value={"path": "report/summary.json", "schema_path": "schemas/summary.schema.json"}, timestamp=ts, binding=bind))
ev.append(sign_evidence(make_evidence("ev-tests", "tests:unit", source="ci-runner", verifier_id="hmac_attestation",
    observed_value={"passed": True}, timestamp=ts, provenance={"run": "example-ci-1"},
    binding={"task_id": TASK, "checkpoints": ["COMMIT"]}), "ci-demo-key", ci_secret))
(v1 / "evidence.json").write_text(json.dumps(ev, indent=2) + "\n")
req = {"protocol": "phi-core/1.0", "checkpoint": "DISPATCH", "contract": contract, "state": state, "evidence": ev, "workspace": "examples/v1/workspace"}
(v1 / "request.json").write_text(json.dumps(req, indent=2) + "\n")
# acceptance
acc = root / "acceptance"; acc.mkdir(exist_ok=True)
design = b"# Report design v1\n\nreport/summary.json = {total: number, rows: integer}\n"
(ws / "design.md").write_bytes(design)
baseline = {"baseline_version": "1.0", "baseline_id": "report-req", "revision": 1, "previous_revision_hash": None,
  "frozen_at": "2026-11-01T00:00:00Z",
  "design": {"design_id": "report-design", "version": "1.0", "sha256": sha(design), "path": "design.md"},
  "requirements": [
    {"requirement_id": "R1", "text": "summary report file is delivered", "design_ref": "D1", "verification": {"method": "file", "path": "report/summary.json"}},
    {"requirement_id": "R2", "text": "summary matches the frozen schema", "design_ref": "D1", "verification": {"method": "json_schema", "path": "report/summary.json", "schema_path": "schemas/summary.schema.json", "schema_sha256": sha(schema_bytes)}},
    {"requirement_id": "R3", "text": "total equals sum of input amounts", "verification": {"method": "command", "argv": ["{python}", "-c", "import csv,json,sys; t=sum(float(r['amount']) for r in csv.DictReader(open('data/input.csv'))); sys.exit(0 if json.load(open('report/summary.json'))['total']==t else 1)"], "timeout_seconds": 60}},
    {"requirement_id": "R4", "text": "unit tests pass", "verification": {"method": "evidence", "evidence_constraint_id": "acceptance:tests", "expected": {"passed": True}}}],
  "change_log": [{"revision": 1, "summary": "initial frozen requirements"}]}
(acc / "baseline.json").write_text(json.dumps(baseline, indent=2) + "\n")
anchor = {"anchor_version": "1.0", "baseline_id": "report-req",
  "revisions": [make_anchor_entry(baseline, anchored_by="acceptance-authority", anchored_at="2026-11-01T00:00:00Z", key_id="acceptance-authority-demo", secret=auth_secret)]}
(acc / "anchor.json").write_text(json.dumps(anchor, indent=2) + "\n")
delivery = {"delivery_version": "1.0", "baseline_id": "report-req", "baseline_revision": 1, "produced_by": "example-agent",
  "claimed_status": "DONE",
  "trace": [{"requirement_id": r, "artifacts": ["report/summary.json"]} for r in ("R1", "R2", "R3", "R4")],
  "evidence": [sign_evidence(make_evidence("acc-tests", "acceptance:tests", source="ci-runner", verifier_id="hmac_attestation",
      observed_value={"passed": True}, timestamp=ts, binding={"baseline_id": "report-req", "baseline_revision": 1}),
      "ci-demo-key", ci_secret)]}
(acc / "delivery.json").write_text(json.dumps(delivery, indent=2) + "\n")
print("ok", baseline_hash(baseline))
