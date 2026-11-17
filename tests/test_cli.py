import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phi_core.cli import EXIT_INVALID, EXIT_NOT_IMPLEMENTED, EXIT_USAGE, EXIT_VALID, main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_task.json"


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


def test_evaluate_reports_not_implemented(capsys):
    code = main(["evaluate", str(SAMPLE)])
    assert code == EXIT_NOT_IMPLEMENTED
    assert code != 0
    captured = capsys.readouterr()
    assert "NOT_IMPLEMENTED" in captured.err
    for verdict in ("TRUE", "FALSE", "UNKNOWN"):
        assert verdict not in captured.out


@pytest.mark.skipif(shutil.which("phi") is None, reason="phi console script not installed")
def test_console_script_end_to_end():
    help_run = subprocess.run(["phi", "--help"], capture_output=True, text=True)
    assert help_run.returncode == 0
    val = subprocess.run(["phi", "validate", str(SAMPLE)], capture_output=True, text=True)
    assert val.returncode == 0, val.stderr
    ev = subprocess.run(["phi", "evaluate", str(SAMPLE)], capture_output=True, text=True)
    assert ev.returncode == EXIT_NOT_IMPLEMENTED
    assert "NOT_IMPLEMENTED" in ev.stderr


def test_module_entrypoint():
    run = subprocess.run(
        [sys.executable, "-m", "phi_core.cli", "validate", str(SAMPLE)],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
