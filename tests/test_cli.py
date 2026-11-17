import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phi_core.cli import (
    EXIT_ACCEPT_FAIL,
    EXIT_FALSE,
    EXIT_INVALID,
    EXIT_UNKNOWN,
    EXIT_USAGE,
    EXIT_VALID,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_task.json"
REQUEST = ROOT / "examples" / "v1" / "request.json"
EVIDENCE = ROOT / "examples" / "v1" / "evidence.json"
TRUST = ROOT / "examples" / "trust.demo.json"
WORKSPACE = ROOT / "examples" / "v1" / "workspace"


@pytest.fixture(autouse=True)
def _run_from_repo_root(monkeypatch):
    # examples/v1/request.json names its workspace relative to the repository root.
    monkeypatch.chdir(ROOT)


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "validate" in out and "evaluate" in out


def test_no_command_prints_help_and_fails(capsys):
    assert main([]) == EXIT_USAGE
    assert "usage" in capsys.readouterr().out


def test_validate_sample_ok(capsys):
    assert main(["validate", str(SAMPLE)]) == EXIT_VALID
    out = capsys.readouterr().out
    assert "VALID" in out and "not a feasibility verdict" in out


def test_validate_invalid_contract(tmp_path, capsys):
    bad = json.loads(SAMPLE.read_text("utf-8"))
    del bad["constraints"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_INVALID
    out = capsys.readouterr().out
    assert "INVALID" in out and "constraints" in out


def test_validate_malformed_json(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["validate", str(path)]) == EXIT_USAGE
    assert "not valid JSON" in capsys.readouterr().err


def test_validate_missing_file(tmp_path):
    assert main(["validate", str(tmp_path / "missing.json")]) == EXIT_USAGE


def test_evaluate_request_true_at_every_checkpoint(capsys):
    # Upgraded from the bootstrap NOT_IMPLEMENTED placeholder test.
    for cp in ("PLAN", "DISPATCH", "STEP", "COMMIT"):
        code = main(["evaluate", "--request", str(REQUEST), "--checkpoint", cp, "--trust", str(TRUST)])
        out = json.loads(capsys.readouterr().out)
        assert code == 0, out["reason_codes"]
        assert out["protocol"] == "phi-core/1.0"
        assert out["verdict"] == "TRUE" and out["release"] is True and out["action"] == "PROCEED"
        assert out["checkpoint"] == cp
        assert out["constraint_results"]


def test_evaluate_legacy_sample_is_unknown_not_success(capsys):
    state = ROOT / "examples" / "v1" / "state.json"
    code = main(["evaluate", "--contract", str(SAMPLE), "--state", str(state), "--evidence", str(EVIDENCE),
                 "--checkpoint", "DISPATCH"])
    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_UNKNOWN
    assert out["verdict"] == "UNKNOWN" and "CONTRACT_VERSION_UNSUPPORTED" in out["reason_codes"]


def test_evaluate_without_trust_store_pauses_on_attestation(capsys):
    code = main(["evaluate", "--request", str(REQUEST), "--checkpoint", "COMMIT"])
    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_UNKNOWN
    tests_result = next(r for r in out["constraint_results"] if r["constraint_id"] == "tests:unit")
    assert tests_result["status"] == "UNRESOLVED"
    assert "UNKNOWN_SIGNING_KEY" in tests_result["reason_codes"]


def test_evaluate_false_exit_code(tmp_path, capsys):
    req = json.loads(REQUEST.read_text("utf-8"))
    req["state"]["tasks"]["fetch-data"]["status"] = "failed"
    p = tmp_path / "req.json"
    p.write_text(json.dumps(req), encoding="utf-8")
    code = main(["evaluate", "--request", str(p), "--workspace", str(WORKSPACE)])
    out = json.loads(capsys.readouterr().out)
    assert code == EXIT_FALSE and out["verdict"] == "FALSE" and out["action"] == "BLOCK"
    assert "DEPENDENCY_FAILED" in out["reason_codes"]


def test_evaluate_request_from_stdin():
    run = subprocess.run([sys.executable, "-m", "phi_core.cli", "evaluate", "--request", "-",
                          "--trust", str(TRUST)], input=REQUEST.read_text("utf-8"), capture_output=True,
                         text=True, cwd=ROOT)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["verdict"] == "TRUE"


def test_evaluate_usage_errors(tmp_path, capsys):
    assert main(["evaluate", "--contract", str(SAMPLE)]) == EXIT_USAGE
    p = tmp_path / "r.json"
    p.write_text("[]", encoding="utf-8")
    assert main(["evaluate", "--request", str(p)]) == EXIT_USAGE


def test_gate_exec_runs_only_on_true(tmp_path):
    marker = tmp_path / "ran.txt"
    cmd = [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"]
    ok = subprocess.run([sys.executable, "-m", "phi_core.cli", "gate-exec", "--request", str(REQUEST),
                         "--trust", str(TRUST), "--", *cmd], capture_output=True, text=True, cwd=ROOT)
    assert ok.returncode == 0, ok.stderr
    assert marker.exists()
    marker.unlink()
    req = json.loads(REQUEST.read_text("utf-8"))
    req["state"]["tasks"]["fetch-data"]["status"] = "running"
    p = tmp_path / "req.json"
    p.write_text(json.dumps(req), encoding="utf-8")
    blocked = subprocess.run([sys.executable, "-m", "phi_core.cli", "gate-exec", "--request", str(p),
                              "--workspace", str(WORKSPACE), "--", *cmd], capture_output=True, text=True)
    assert blocked.returncode == EXIT_UNKNOWN
    assert "NOT EXECUTED" in blocked.stderr
    assert not marker.exists()


def test_plan_command(tmp_path, capsys):
    contract = json.loads((ROOT / "examples" / "v1" / "contract.json").read_text("utf-8"))
    code = main(["plan", "--contracts", str(ROOT / "examples" / "v1" / "contract.json"),
                 "--state", str(ROOT / "examples" / "v1" / "state.json"), "--evidence", str(EVIDENCE),
                 "--workspace", str(WORKSPACE), "--trust", str(TRUST)])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["verdict"] == "TRUE"
    assert contract["task_id"] in out["task_results"]


def test_audit_cli_roundtrip(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    for cp in ("PLAN", "DISPATCH"):
        main(["evaluate", "--request", str(REQUEST), "--checkpoint", cp, "--trust", str(TRUST), "--audit", str(log)])
    capsys.readouterr()
    assert main(["audit", "verify", str(log)]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 2
    assert main(["audit", "replay", str(log)]) == 0
    assert json.loads(capsys.readouterr().out)["all_match"] is True
    assert main(["audit", "trace", str(log), "ev-tests"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2
    assert main(["audit", "states", str(log)]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2
    assert main(["audit", "head", str(log)]) == 0
    head = json.loads(capsys.readouterr().out)
    assert main(["audit", "verify", str(log), "--anchor-seq", str(head["seq"]), "--anchor-hash", head["head_hash"]]) == 0
    capsys.readouterr()
    lines = log.read_text("utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["verdict"] = "FALSE"
    lines[0] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["audit", "verify", str(log)]) == EXIT_INVALID
    assert main(["audit", "replay", str(log)]) == EXIT_INVALID


def test_accept_cli_pass_and_fail(tmp_path, capsys):
    acc = ROOT / "examples" / "acceptance"
    args = ["accept", "--baseline", str(acc / "baseline.json"), "--anchor", str(acc / "anchor.json"),
            "--delivery", str(acc / "delivery.json"), "--workspace", str(WORKSPACE),
            "--now", "2026-11-17T00:00:00Z", "--trust", str(TRUST), "--require-signed-anchor"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    baseline = json.loads((acc / "baseline.json").read_text("utf-8"))
    baseline["requirements"].pop()
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(baseline), encoding="utf-8")
    args[2] = str(p)
    assert main(args) == EXIT_ACCEPT_FAIL
    assert "BASELINE_HASH_MISMATCH" in json.loads(capsys.readouterr().out)["global_reason_codes"]


def test_evidence_observe_and_sign_cli(tmp_path, capsys):
    assert main(["evidence", "observe", "--contract", str(ROOT / "examples" / "v1" / "contract.json"),
                 "--workspace", str(WORKSPACE), "--now", "2026-11-17T00:00:00Z"]) == 0
    items = json.loads(capsys.readouterr().out)
    assert {i["verifier_id"] for i in items} == {"file_sha256", "json_schema"}
    p = tmp_path / "item.json"
    p.write_text(json.dumps(items[0]), encoding="utf-8")
    assert main(["evidence", "sign", str(p), "--trust", str(TRUST), "--key-id", "ci-demo-key"]) == 0
    signed = json.loads(capsys.readouterr().out)
    assert len(signed["provenance"]["signature"]) == 64


def test_validate_other_kinds(capsys):
    assert main(["validate", str(ROOT / "examples" / "v1" / "state.json"), "--kind", "state"]) == 0
    assert main(["validate", str(EVIDENCE), "--kind", "evidence"]) == 0
    assert main(["validate", str(ROOT / "examples" / "acceptance" / "baseline.json"), "--kind", "baseline"]) == 0
    assert main(["validate", str(ROOT / "examples" / "acceptance" / "anchor.json"), "--kind", "anchor"]) == 0
    assert main(["validate", str(ROOT / "examples" / "acceptance" / "delivery.json"), "--kind", "delivery"]) == 0
    assert main(["validate", str(ROOT / "examples" / "v1" / "contract.json")]) == 0
    assert main(["validate", str(SAMPLE), "--kind", "state"]) == EXIT_INVALID


@pytest.mark.skipif(shutil.which("phi") is None, reason="phi console script not installed")
def test_console_script_end_to_end():
    help_run = subprocess.run(["phi", "--help"], capture_output=True, text=True)
    assert help_run.returncode == 0
    val = subprocess.run(["phi", "validate", str(SAMPLE)], capture_output=True, text=True)
    assert val.returncode == 0, val.stderr
    ev = subprocess.run(["phi", "evaluate", "--request", str(REQUEST), "--trust", str(TRUST)],
                        capture_output=True, text=True, cwd=ROOT)
    assert ev.returncode == 0, ev.stderr
    assert json.loads(ev.stdout)["verdict"] == "TRUE"


def test_module_entrypoint():
    run = subprocess.run(
        [sys.executable, "-m", "phi_core.cli", "validate", str(SAMPLE)],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
