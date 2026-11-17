"""Performance smoke tests. Bounds are deliberately generous (catch pathological
regressions such as quadratic blow-ups, not to promise speed); the measured
numbers are printed so the pytest log records them."""

import json
import subprocess
import sys
import time

import pytest

from conftest import ROOT, TASK, attest, base_contract, base_state
from phi_core import PhiEngine

pytestmark = pytest.mark.performance


def test_judge_5000_state_constraints_within_bound():
    n = 5000
    c = base_contract(dependencies=[f"d{i}" for i in range(n)])
    s = base_state(tasks={**{f"d{i}": {"status": "completed"} for i in range(n)}, TASK: {"status": "ready"}})
    engine = PhiEngine()
    t0 = time.perf_counter()
    r = engine.judge(c, s, [], checkpoint="DISPATCH")
    elapsed = time.perf_counter() - t0
    print(f"\nPERF judge n={n} hard constraints: {elapsed:.3f}s verdict={r.verdict.value}")
    assert r.verdict.value == "TRUE" and len(r.constraint_results) == n
    assert elapsed < 10


def test_attestations_scale_roughly_linearly(trust):
    engine = PhiEngine()
    timings = {}
    for n in (100, 800):
        cons = [{"constraint_id": f"a{i}", "kind": "hard",
                 "predicate": {"type": "attested_value", "params": {"expected": True}}} for i in range(n)]
        ev = [attest(f"e{i}", f"a{i}", True) for i in range(n)]
        c = base_contract(constraints=cons)
        engine.evaluate(c, base_state(), ev, checkpoint="DISPATCH", trust_store=trust)
        t0 = time.perf_counter()
        r = engine.evaluate(c, base_state(), ev, checkpoint="DISPATCH", trust_store=trust)
        timings[n] = time.perf_counter() - t0
        assert r.verdict.value == "TRUE"
    print(f"\nPERF hmac attestations: {timings}")
    # 8x more items; allow up to 40x time before calling it a blow-up.
    assert timings[800] < 40 * max(timings[100], 1e-3)


def test_benchmark_script_quick_runs(tmp_path):
    out = tmp_path / "bench.json"
    run = subprocess.run([sys.executable, str(ROOT / "benchmarks" / "bench_phi.py"), "--quick", "--repeats", "2",
                          "--output", str(out)], capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stderr
    data = json.loads(out.read_text())
    assert data["environment"]["python"] and data["cases"]
