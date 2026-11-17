"""Minimal runnable harness gated by phi-core.

A tiny file pipeline: read input/data.txt, write output/upper.txt and
output/count.json, then mark the task completed in the host's state.json.
Every step runs only through GatedRunner, which re-evaluates Phi with the
latest state and evidence before each action. FALSE stops (BLOCKED), UNKNOWN
pauses (PAUSED); in both cases the action is not executed.

Usage:
  python examples/minimal_harness/harness.py --workspace /tmp/demo --scenario ok

Scenarios: ok, tampered_input, dependency_pending, bad_output,
ownership_conflict, contract_edit_midrun.
Exit code: 0 COMPLETED, 10 BLOCKED, 20 PAUSED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

from phi_core import AuditLog, GatedRunner, HarnessAdapter, PhiGate, Step, observe_files

TASK = "uppercase-report"
DEFAULT_NOW = "2026-11-17T00:00:00Z"
COUNT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["lines"],
    "properties": {"lines": {"type": "integer", "minimum": 0}},
    "additionalProperties": False,
}


def setup_workspace(ws: Path, scenario: str, now: str) -> None:
    if ws.exists():
        shutil.rmtree(ws)
    (ws / "input").mkdir(parents=True)
    (ws / "schemas").mkdir()
    data = b"alpha\nbeta\ngamma\n"
    (ws / "input" / "data.txt").write_bytes(data)
    (ws / "schemas" / "count.schema.json").write_text(json.dumps(COUNT_SCHEMA), encoding="utf-8")
    contract = {
        "contract_version": "1.0",
        "task_id": TASK,
        "objective": "Upper-case input/data.txt and report its line count.",
        "dependencies": ["fetch-data"],
        "inputs": [{"path": "input/data.txt", "sha256": hashlib.sha256(data).hexdigest()}],
        "outputs": [
            {"path": "output/upper.txt"},
            {"path": "output/count.json", "schema": "schemas/count.schema.json"},
        ],
        "capabilities": ["python3"],
        "time_bounds": {"deadline": "2026-12-31T00:00:00Z"},
        "constraints": [
            {"constraint_id": "style:short-lines", "kind": "soft", "statement": "lines are short",
             "predicate": {"type": "natural_language", "params": {}}},
        ],
        "constraint_scope": {"complete": True, "declared_by": "demo-host"},
    }
    state = {
        "state_version": "1.0",
        "now": now,
        "tasks": {"fetch-data": {"status": "completed"}, TASK: {"status": "ready"}},
        "capabilities": ["python3"],
        "capabilities_complete": True,
        "file_owners": {"output/upper.txt": TASK, "output/count.json": TASK},
    }
    if scenario == "tampered_input":
        (ws / "input" / "data.txt").write_bytes(b"alpha\nEVIL\n")
    if scenario == "dependency_pending":
        state["tasks"]["fetch-data"]["status"] = "running"
    if scenario == "ownership_conflict":
        state["file_owners"]["output/count.json"] = "other-task"
    (ws / "contract.json").write_text(json.dumps(contract, indent=2), encoding="utf-8")
    (ws / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


class FilePipelineAdapter(HarnessAdapter):
    def __init__(self, ws: Path, scenario: str):
        self.ws = ws
        self.scenario = scenario

    def load_contract(self) -> dict:
        return json.loads((self.ws / "contract.json").read_text(encoding="utf-8"))

    def observe_state(self) -> dict:
        return json.loads((self.ws / "state.json").read_text(encoding="utf-8"))

    def collect_evidence(self, checkpoint: str) -> list:
        return observe_files(self.load_contract(), self.ws, self.observe_state()["now"], source="demo-host")

    def plan_steps(self):
        return [Step("uppercase", self._uppercase), Step("count", self._count)]

    def _uppercase(self):
        text = (self.ws / "input" / "data.txt").read_text(encoding="utf-8")
        (self.ws / "output").mkdir(exist_ok=True)
        (self.ws / "output" / "upper.txt").write_text(text.upper(), encoding="utf-8")
        if self.scenario == "contract_edit_midrun":
            contract = self.load_contract()
            contract["constraint_scope"]["declared_by"] = "agent-edited"
            (self.ws / "contract.json").write_text(json.dumps(contract), encoding="utf-8")

    def _count(self):
        lines = (self.ws / "input" / "data.txt").read_text(encoding="utf-8").count("\n")
        payload = {"lines": "many"} if self.scenario == "bad_output" else {"lines": lines}
        (self.ws / "output" / "count.json").write_text(json.dumps(payload), encoding="utf-8")

    def commit(self):
        state = self.observe_state()
        state["tasks"][TASK]["status"] = "completed"
        (self.ws / "state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--scenario", default="ok", choices=[
        "ok", "tampered_input", "dependency_pending", "bad_output", "ownership_conflict", "contract_edit_midrun"])
    ap.add_argument("--now", default=DEFAULT_NOW)
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    setup_workspace(ws, args.scenario, args.now)
    audit_path = ws.parent / f"{ws.name}.audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    gate = PhiGate(workspace=ws, audit_log=AuditLog(audit_path))
    report = GatedRunner(gate, FilePipelineAdapter(ws, args.scenario)).run()
    out = report.to_dict()
    out["scenario"] = args.scenario
    out["files"] = sorted(str(p.relative_to(ws)) for p in ws.rglob("*") if p.is_file())
    out["task_status"] = json.loads((ws / "state.json").read_text())["tasks"][TASK]["status"]
    out["audit_log"] = str(audit_path)
    print(json.dumps(out, indent=2))
    return {"COMPLETED": 0, "BLOCKED": 10, "PAUSED": 20}[report.status]


if __name__ == "__main__":
    sys.exit(main())
