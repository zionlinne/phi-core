"""Micro-benchmarks for phi-core. Prints / writes machine-readable JSON.

Method: each case is run ``--repeats`` times after one warm-up run; wall time
is measured with time.perf_counter and min/median/max are reported. Numbers
describe this machine and this run only.

Usage: python benchmarks/bench_phi.py --output bench.json [--repeats 5] [--quick]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from phi_core import (
    AuditLog,
    PhiEngine,
    PhiGate,
    TrustStore,
    make_anchor_entry,
    make_evidence,
    observe_files,
    run_acceptance,
    sign_evidence,
)

NOW = "2026-11-17T00:00:00Z"
TS = "2026-11-16T23:59:00Z"
SECRET = b"benchmark-secret-0123456789abcdef"


def timeit(fn, repeats):
    fn()
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return {"min_s": min(samples), "median_s": statistics.median(samples), "max_s": max(samples), "repeats": repeats}


def contract(n_deps=0, inputs=(), constraints=()):
    return {"contract_version": "1.0", "task_id": "bench", "objective": "bench",
            "dependencies": [f"d{i}" for i in range(n_deps)], "inputs": list(inputs),
            "constraints": list(constraints), "constraint_scope": {"complete": True}}


def state(n_deps=0):
    tasks = {f"d{i}": {"status": "completed"} for i in range(n_deps)}
    tasks["bench"] = {"status": "ready"}
    return {"state_version": "1.0", "now": NOW, "tasks": tasks}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--output")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args(argv)
    r = args.repeats
    engine = PhiEngine()
    trust = TrustStore()
    trust.add_key("k", SECRET, ["ci"])
    cases = []

    dep_sizes = [10, 100, 1000] if args.quick else [10, 100, 1000, 5000]
    for n in dep_sizes:
        c, s = contract(n_deps=n), state(n)
        vres = engine.verify(s, [])
        res = engine.judge(c, s, vres, checkpoint="DISPATCH")
        assert res.verdict.value == "TRUE"
        cases.append({"case": "judge_state_dependency_constraints", "n": n,
                      **timeit(lambda: engine.judge(c, s, vres, checkpoint="DISPATCH"), r)})

    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        file_sizes = [10, 100] if args.quick else [10, 100, 500]
        for n in file_sizes:
            inputs = []
            for i in range(n):
                data = f"file {i}\n".encode() * 64
                (ws / f"f{i}.txt").write_bytes(data)
                inputs.append({"path": f"f{i}.txt", "sha256": hashlib.sha256(data).hexdigest()})
            c, s = contract(inputs=inputs), state()
            ev = observe_files(c, ws, TS)
            res = engine.evaluate(c, s, ev, checkpoint="DISPATCH", workspace=ws)
            assert res.verdict.value == "TRUE", res.reason_codes
            cases.append({"case": "evaluate_file_constraints_incl_hashing", "n": n, "evidence_items": len(ev),
                          "file_bytes_each": len(data),
                          **timeit(lambda: engine.evaluate(c, s, ev, checkpoint="DISPATCH", workspace=ws), r)})

    att_sizes = [10, 100, 1000]
    for n in att_sizes:
        cons = [{"constraint_id": f"a{i}", "kind": "hard",
                 "predicate": {"type": "attested_value", "params": {"expected": True}}} for i in range(n)]
        ev = [sign_evidence(make_evidence(f"e{i}", f"a{i}", source="ci", verifier_id="hmac_attestation",
                                          observed_value=True, timestamp=TS, binding={"task_id": "bench"}),
                            "k", SECRET) for i in range(n)]
        c, s = contract(constraints=cons), state()
        res = engine.evaluate(c, s, ev, checkpoint="DISPATCH", trust_store=trust)
        assert res.verdict.value == "TRUE"
        cases.append({"case": "evaluate_hmac_attestations", "n": n,
                      **timeit(lambda: engine.evaluate(c, s, ev, checkpoint="DISPATCH", trust_store=trust), r)})

    with tempfile.TemporaryDirectory() as tmp:
        for n in ([100] if args.quick else [100, 1000]):
            path = Path(tmp) / f"audit-{n}.jsonl"
            log = AuditLog(path)
            gate = PhiGate(audit_log=log)
            c, s = contract(n_deps=5), state(5)
            t0 = time.perf_counter()
            for _ in range(n):
                gate.check("DISPATCH", c, s, [])
            append_total = time.perf_counter() - t0
            cases.append({"case": "audit_append_with_fsync", "n": n, "total_s": append_total,
                          "per_record_s": append_total / n, "file_bytes": path.stat().st_size})
            cases.append({"case": "audit_verify_chain", "n": n, **timeit(lambda: log.verify(), r)})

    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp)
        (ws / "design.md").write_bytes(b"d")
        for n in [10, 100]:
            reqs = []
            for i in range(n):
                (ws / f"o{i}.txt").write_text(str(i))
                reqs.append({"requirement_id": f"R{i}", "text": "t", "verification": {"method": "file", "path": f"o{i}.txt"}})
            b = {"baseline_version": "1.0", "baseline_id": "B", "revision": 1, "previous_revision_hash": None,
                 "frozen_at": NOW, "design": {"design_id": "D", "version": "1",
                                              "sha256": hashlib.sha256(b"d").hexdigest(), "path": "design.md"},
                 "requirements": reqs, "change_log": [{"revision": 1, "summary": "s"}]}
            a = {"anchor_version": "1.0", "baseline_id": "B", "revisions": [make_anchor_entry(b, anchored_by="x", anchored_at=NOW)]}
            d = {"delivery_version": "1.0", "baseline_id": "B", "baseline_revision": 1,
                 "trace": [{"requirement_id": f"R{i}"} for i in range(n)]}
            assert run_acceptance(b, a, d, workspace=ws, now=NOW)["status"] == "PASS"
            cases.append({"case": "acceptance_file_requirements", "n": n,
                          **timeit(lambda: run_acceptance(b, a, d, workspace=ws, now=NOW), r)})

    out = {
        "tool": "benchmarks/bench_phi.py",
        "method": "time.perf_counter wall time; 1 warm-up + N repeats; min/median/max. "
                  "audit_append is a single timed loop including fsync per record.",
        "environment": {
            "python": sys.version, "implementation": platform.python_implementation(),
            "platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor(), "cpu_count": os.cpu_count(),
        },
        "cases": cases,
        "caveat": "Single-machine measurements; no claim about other environments or about causes of differences.",
    }
    text = json.dumps(out, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
