"""Regression, legal-control, boundary, property and concurrency tests for the
four defects reported by the independent retest of 6bca32e:

* COMMAND-ARTIFACT-EXEMPTS-CRITERION
* COMMAND-SYMLINK-SKIPS-UNPINNED-GUARD
* RUNNER-DEFAULTED-CHECKPOINT-IGNORED
* COMMAND-PIN-RESTORE-DURING-RUN
"""

import functools
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import TASK, attest, base_contract, base_state, sha
from phi_core import GateBlocked, GatedRunner, GateSession, HarnessAdapter, PhiGate, Step, Verdict
from phi_core.gate import EvidenceProviderError
from test_round2_fixes import accept, cmd_req, req_status

EXIT0 = "import sys\nsys.exit(0)\n"
EXIT1 = "import sys\nsys.exit(1)\n"


def marking(marker: Path, code: int = 0) -> str:
    return f"import sys\nopen({str(marker)!r}, 'w').write('ran')\nsys.exit({code})\n"


def write(ws: Path, rel: str, text: str) -> Path:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def pin(ws: Path, *rels: str) -> list:
    return [{"path": r, "sha256": sha((ws / r).read_bytes())} for r in rels]


@pytest.fixture
def outside(tmp_path):
    d = tmp_path / "outside"
    d.mkdir()
    return d


# =========================================================================== N1 artifact role never exempts the program


ALIASES = [
    ("script-as-artifact", ["check.py"], ["{python}", "check.py"], {"check.py"}),
    ("dot-root", ["."], ["{python}", "check.py"], {"check.py"}),
    ("parent-dir", ["scripts"], ["{python}", "scripts/check.py"], {"scripts/check.py"}),
    ("parent-dir-slash", ["./scripts/"], ["{python}", "./scripts/check.py"], {"scripts/check.py"}),
    ("dotdot-inside", ["scripts"], ["{python}", "scripts/../scripts/check.py"], {"scripts/check.py"}),
    ("dot-relative", ["."], ["{python}", "./check.py"], {"check.py"}),
    ("options-before-script", ["."], ["{python}", "-I", "-W", "ignore", "-X", "utf8", "check.py"], {"check.py"}),
    ("double-dash", ["."], ["{python}", "--", "check.py"], {"check.py"}),
    ("module-file", ["helper.py"], ["{python}", "-m", "helper"], {"helper.py"}),
    ("module-grouped-flag", ["."], ["{python}", "-Bm", "helper"], {"helper.py"}),
    ("module-attached", ["."], ["{python}", "-mhelper"], {"helper.py"}),
    ("package-main", ["pkg"], ["{python}", "-m", "pkg"], {"pkg/__init__.py", "pkg/__main__.py"}),
    ("package-sub", ["pkg"], ["{python}", "-m", "pkg.run"], {"pkg/__init__.py", "pkg/run.py"}),
    ("dir-program", ["app"], ["{python}", "app"], {"app/__main__.py"}),
]


def _alias_ws(ws, marker):
    for rel in ("check.py", "scripts/check.py", "helper.py", "pkg/run.py", "pkg/__main__.py", "app/__main__.py"):
        write(ws, rel, marking(marker))
    write(ws, "pkg/__init__.py", "")


@pytest.mark.parametrize("name,artifacts,argv,program", ALIASES, ids=[a[0] for a in ALIASES])
def test_n1_regression_artifact_alias_cannot_exempt_program(ws, tmp_path, name, artifacts, argv, program):
    marker = tmp_path / "ran"
    _alias_ws(ws, marker)
    rep = accept(ws, cmd_req(argv, artifacts=artifacts))
    status, codes = req_status(rep, "R1")
    detail = rep["requirement_results"][0]["detail"]
    assert (status, codes) == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_FILE_NOT_PINNED"])
    assert program <= set(detail["program_not_pinned"])
    assert not marker.exists()


@pytest.mark.parametrize("name,artifacts,argv,program", ALIASES, ids=[a[0] for a in ALIASES])
def test_n1_control_same_alias_passes_once_program_pinned(ws, tmp_path, name, artifacts, argv, program):
    marker = tmp_path / "ran"
    _alias_ws(ws, marker)
    rep = accept(ws, cmd_req(argv, artifacts=artifacts, pinned_files=pin(ws, *sorted(program))))
    assert rep["status"] == "PASS", rep["requirement_results"]
    assert marker.exists()


def test_n1_regression_sourceless_and_extension_module_candidates(ws):
    write(ws, "helper.pyc", "not really bytecode")
    write(ws, "fast.cpython-312-x86_64-linux-gnu.so", "x")
    for argv in (["{python}", "-m", "helper"], ["{python}", "-m", "fast"]):
        rep = accept(ws, cmd_req(argv, artifacts=["."]))
        assert req_status(rep, "R1") == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_FILE_NOT_PINNED"])


def test_n1_regression_original_fail_rewritten_cannot_pass(ws, tmp_path):
    marker = tmp_path / "ran"
    write(ws, "check.py", marking(marker, 1))
    pins = pin(ws, "check.py")
    rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pins, artifacts=["."]))
    assert req_status(rep, "R1") == ("FAIL", ["COMMAND_EXIT_CODE_UNEXPECTED"]) and marker.exists()
    marker.unlink()
    write(ws, "check.py", marking(marker, 0))
    for artifacts in (["."], ["check.py"], ["./"]):
        rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pins, artifacts=artifacts))
        assert req_status(rep, "R1") == ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED"])
        assert not marker.exists()


def test_n1_regression_unparsed_program_cannot_use_artifacts(ws, tmp_path):
    if shutil.which("sh") is None:
        pytest.skip("no sh on this host")
    marker = tmp_path / "ran"
    write(ws, "check.sh", f"echo ran > {marker}\nexit 0\n")
    rep = accept(ws, cmd_req(["sh", "check.sh"], artifacts=["check.sh"]))
    r = rep["requirement_results"][0]
    assert (r["status"], r["reason_codes"]) == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_FILE_NOT_PINNED"])
    assert r["detail"]["argv_roles"] == "unparsed-program-all-pinned" and not marker.exists()
    rep = accept(ws, cmd_req(["sh", "check.sh"], pinned_files=pin(ws, "check.sh")))
    assert rep["status"] == "PASS" and marker.exists()


def test_n1_control_data_arguments_are_not_programs(ws):
    """A ``.py`` data file passed to a pinned checker is data, not code."""
    check = "import sys\nsys.exit(0 if open(sys.argv[1]).read().startswith('x =') else 1)\n"
    write(ws, "check.py", check)
    write(ws, "deliverable/model.py", "x = 1\n")
    rep = accept(ws, cmd_req(["{python}", "check.py", "deliverable/model.py"],
                             pinned_files=pin(ws, "check.py"), artifacts=["deliverable"]))
    assert rep["status"] == "PASS"
    rep = accept(ws, cmd_req(["{python}", "check.py", "--in=deliverable/model.py"],
                             pinned_files=pin(ws, "check.py")))
    r = rep["requirement_results"][0]
    assert r["status"] == "INCONCLUSIVE" and r["detail"]["data_not_pinned_or_declared"] == ["deliverable/model.py"]
    assert r["detail"]["program_not_pinned"] == []


def test_n1_control_installed_module_and_host_checker(ws, tmp_path):
    write(ws, "out.json", '{"n": 1}')
    rep = accept(ws, cmd_req(["{python}", "-m", "json.tool", "out.json"], artifacts=["out.json"]))
    assert rep["status"] == "PASS"
    host = tmp_path / "host-checker"
    host.mkdir()
    (host / "check.py").write_text("import json,sys\nsys.exit(0 if json.load(open('out.json'))['n']==1 else 1)\n")
    rep = accept(ws, cmd_req(["{python}", str(host / "check.py")]))
    assert rep["status"] == "PASS"
    assert rep["requirement_results"][0]["detail"]["execution"]["program"] == []


# =========================================================================== N2 paths fail closed


def _fifo(outside: Path) -> Path:
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs on this platform")
    p = outside / "secret.fifo"
    os.mkfifo(p)
    return p


def _accept_with_deadline(*args, **kw):
    """Run acceptance in a thread; a hang means some code opened the FIFO."""
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("rep", accept(*args, **kw)), daemon=True)
    t.start()
    t.join(30)
    assert not t.is_alive(), "acceptance blocked: an external link target was opened"
    return out["rep"]


def test_n2_regression_file_symlink_outside_is_refused_unread(ws, outside, tmp_path):
    marker = tmp_path / "ran"
    (outside / "evil.py").write_text(marking(marker))
    (ws / "check.py").symlink_to(outside / "evil.py")
    for extra in ({}, {"artifacts": ["check.py"]}, {"artifacts": ["."]}):
        rep = accept(ws, cmd_req(["{python}", "check.py"], **extra))
        r = rep["requirement_results"][0]
        assert (r["status"], r["reason_codes"]) == ("INCONCLUSIVE", ["COMMAND_PATH_ESCAPES_WORKSPACE"])
        assert r["detail"]["reason"] == "resolves-outside-workspace" and not marker.exists()
    (ws / "check.py").unlink()
    (ws / "check.py").symlink_to(_fifo(outside))
    rep = _accept_with_deadline(ws, cmd_req(["{python}", "check.py"]))
    assert req_status(rep, "R1") == ("INCONCLUSIVE", ["COMMAND_PATH_ESCAPES_WORKSPACE"])


ESCAPES = [
    ("dir-symlink", lambda ws, out: (ws / "scripts").symlink_to(out, target_is_directory=True),
     ["{python}", "scripts/evil.py"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("module-symlink", lambda ws, out: (ws / "helper.py").symlink_to(out / "evil.py"),
     ["{python}", "-m", "helper"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("package-dir-symlink", lambda ws, out: (ws / "pkg").symlink_to(out, target_is_directory=True),
     ["{python}", "-m", "pkg.evil"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("data-symlink", lambda ws, out: (ws / "in.txt").symlink_to(out / "evil.py"),
     ["{python}", "-c", "pass", "in.txt"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("opt-value-symlink", lambda ws, out: (ws / "in.txt").symlink_to(out / "evil.py"),
     ["{python}", "-c", "pass", "--input=in.txt"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("relative-dotdot", lambda ws, out: None, ["{python}", "../outside/evil.py"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("dangling", lambda ws, out: (ws / "check.py").symlink_to(out / "missing.py"),
     ["{python}", "check.py"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("loop", lambda ws, out: ((ws / "a").symlink_to(ws / "b"), (ws / "b").symlink_to(ws / "a")),
     ["{python}", "a"], "COMMAND_PATH_ESCAPES_WORKSPACE"),
    ("absolute-into-workspace", lambda ws, out: write(ws, "check.py", EXIT0),
     lambda ws, out: ["{python}", str(ws / "check.py")], "COMMAND_ABSOLUTE_WORKSPACE_PATH"),
    ("absolute-alias-into-workspace",
     lambda ws, out: (write(ws, "check.py", EXIT0), (out / "alias.py").symlink_to(ws / "check.py")),
     lambda ws, out: ["{python}", str(out / "alias.py")], "COMMAND_ABSOLUTE_WORKSPACE_PATH"),
    ("host-path-through-workspace-link",
     lambda ws, out: ((ws / "check.py").symlink_to(out / "evil.py"), (out / "alias.py").symlink_to(ws / "check.py")),
     lambda ws, out: ["{python}", str(out / "alias.py")], "COMMAND_ABSOLUTE_WORKSPACE_PATH"),
    ("host-dir-through-workspace-dir",
     lambda ws, out: ((ws / "sub").mkdir(), (out / "via").symlink_to(ws / "sub", target_is_directory=True)),
     lambda ws, out: ["{python}", str(out / "via" / ".." / ".." / "outside" / "evil.py")],
     "COMMAND_ABSOLUTE_WORKSPACE_PATH"),
]


@pytest.mark.parametrize("name,setup,argv,code", ESCAPES, ids=[e[0] for e in ESCAPES])
def test_n2_regression_escapes_and_aliases_fail_closed(tmp_path, name, setup, argv, code):
    ws = tmp_path / "ws"
    ws.mkdir()
    out = tmp_path / "outside"
    out.mkdir()
    marker = tmp_path / "ran"
    (out / "evil.py").write_text(marking(marker))
    setup(ws, out)
    argv = argv(ws, out) if callable(argv) else argv
    for extra in ({}, {"artifacts": ["."]}):
        rep = accept(ws, cmd_req(argv, **extra))
        assert req_status(rep, "R1") == ("INCONCLUSIVE", [code])
    assert not marker.exists()


def test_n2_regression_pinned_path_through_external_link_fails(ws, outside):
    (outside / "c.py").write_text(EXIT1)
    (ws / "check.py").symlink_to(outside / "c.py")
    rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=[{"path": "check.py", "sha256": sha(EXIT1.encode())}]))
    assert req_status(rep, "R1") == ("FAIL", ["COMMAND_PINNED_FILE_MISSING"])


def test_n2_regression_path_lookup_cannot_reach_workspace(ws, tmp_path):
    marker = tmp_path / "ran"
    prog = write(ws, "bin/phi-r3-checker", f"#!/bin/sh\necho x > {marker}\nexit 0\n")
    prog.chmod(0o755)
    host_path = os.environ.get("PATH", "")
    for path in (f".{os.pathsep}{host_path}", f"bin{os.pathsep}{host_path}", f"{ws / 'bin'}{os.pathsep}{host_path}",
                 f"{os.pathsep}{host_path}"):
        rep = accept(ws, cmd_req(["phi-r3-checker"]), command_env={"PATH": path})
        assert req_status(rep, "R1") == ("INCONCLUSIVE", ["COMMAND_NOT_RUNNABLE"])
    assert not marker.exists()


def test_n2_regression_interpreter_inside_workspace_refused(ws, monkeypatch):
    fake = write(ws, "venv/bin/python", "")
    monkeypatch.setattr(sys, "executable", str(fake))
    rep = accept(ws, cmd_req(["{python}", "-c", "pass"]))
    assert req_status(rep, "R1") == ("INCONCLUSIVE", ["COMMAND_INTERPRETER_IN_WORKSPACE"])


def test_n2_control_unrelated_external_link_is_omitted_not_followed(ws, outside):
    fifo = _fifo(outside)
    (ws / ".venv").mkdir()
    (ws / ".venv" / "python").symlink_to(fifo)
    (ws / "inner.txt").write_text("in")
    (ws / "alias.txt").symlink_to(ws / "inner.txt")
    code = ("import os,sys; sys.exit(0 if not os.path.lexists('.venv/python') "
            "and open('alias.txt').read()=='in' else 1)")
    rep = _accept_with_deadline(ws, cmd_req(["{python}", "-c", code]))
    r = rep["requirement_results"][0]
    assert r["status"] == "PASS", r
    assert r["detail"]["execution"]["omitted_links_leaving_workspace"] == [".venv/python"]


# =========================================================================== N3 checkpoint always reaches a provider that can take it


CHECKPOINTS = ["PLAN", "DISPATCH", "STEP", "COMMIT"]


def all_cp_contract():
    return base_contract(constraints=[{"constraint_id": "pre:ok", "kind": "hard", "checkpoints": CHECKPOINTS,
                                       "predicate": {"type": "attested_value", "params": {"expected": True}}}])


def evidence_for(cp, false_at):
    return [attest(f"e-{cp}", "pre:ok", cp != false_at, binding={"task_id": TASK})]


class _Callable:
    def __init__(self, false_at, seen):
        self.false_at, self.seen = false_at, seen

    def __call__(self, checkpoint="DISPATCH"):
        self.seen.append(checkpoint)
        return evidence_for(checkpoint, self.false_at)


def _providers():
    def make(kind, false_at, seen):
        def body(cp):
            seen.append(cp)
            return evidence_for(cp, false_at)
        if kind == "required":
            return lambda checkpoint: body(checkpoint)
        if kind == "defaulted":
            return lambda checkpoint="DISPATCH": body(checkpoint)
        if kind == "positional-only-defaulted":
            def f(cp="DISPATCH", /):
                return body(cp)
            return f
        if kind == "kw-only":
            def f(*, checkpoint):
                return body(checkpoint)
            return f
        if kind == "kw-only-defaulted":
            def f(*, checkpoint="DISPATCH"):
                return body(checkpoint)
            return f
        if kind == "var-positional":
            return lambda *a: body(a[0] if a else "DISPATCH")
        if kind == "var-keyword":
            return lambda **kw: body(kw.get("checkpoint", "DISPATCH"))
        if kind == "callable-object":
            return _Callable(false_at, seen)
        if kind == "partial":
            return functools.partial(lambda tag, checkpoint="DISPATCH": body(checkpoint), "t")
        raise AssertionError(kind)
    return make


KINDS = ["required", "defaulted", "positional-only-defaulted", "kw-only", "kw-only-defaulted", "var-positional",
         "var-keyword", "callable-object", "partial"]


class ProviderAdapter(HarnessAdapter):
    def __init__(self, provider, side):
        self.provider, self.side = provider, side
        self.collect_evidence = provider

    def load_contract(self):
        return all_cp_contract()

    def observe_state(self):
        return base_state()

    def collect_evidence(self, checkpoint):  # replaced per instance
        raise AssertionError

    def plan_steps(self):
        return [Step("side", lambda: self.side.append("step"))]

    def commit(self):
        self.side.append("commit")


@pytest.mark.parametrize("kind", KINDS)
def test_n3_every_stage_collects_its_own_evidence(trust, kind):
    seen, side = [], []
    rep = GatedRunner(PhiGate(trust_store=trust), ProviderAdapter(_providers()(kind, None, seen), side)).run()
    assert rep.status == "COMPLETED" and side == ["step", "commit"]
    assert seen == CHECKPOINTS


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("false_at,stopped,side_expected", [
    ("PLAN", "preflight", []), ("DISPATCH", "preflight", []),
    ("STEP", "step:side", []), ("COMMIT", "commit", ["step"])])
def test_n3_regression_false_at_one_checkpoint_blocks_there(trust, kind, false_at, stopped, side_expected):
    seen, side = [], []
    rep = GatedRunner(PhiGate(trust_store=trust), ProviderAdapter(_providers()(kind, false_at, seen), side)).run()
    assert rep.status == "BLOCKED" and rep.stopped_at == stopped and side == side_expected
    assert seen[-1] == false_at and rep.decisions[-1]["checkpoint"] == false_at
    assert rep.decisions[-1]["verdict"] == "FALSE"


def test_n3_regression_probe_defaulted_method_task_only_binding(trust):
    """Independent-probe input: ``collect_evidence(self, checkpoint="DISPATCH")``,
    PLAN value False, binding names only the task. 6bca32e: COMPLETED."""
    side = []

    class Defaulted(HarnessAdapter):
        seen = []

        def load_contract(self):
            return base_contract(constraints=[{"constraint_id": "pre:ok", "kind": "hard", "checkpoints": ["PLAN"],
                                               "predicate": {"type": "attested_value", "params": {"expected": True}}}])

        def observe_state(self):
            return base_state()

        def collect_evidence(self, checkpoint="DISPATCH"):
            self.seen.append(checkpoint)
            return [attest("e", "pre:ok", checkpoint != "PLAN", binding={"task_id": TASK})]

        def plan_steps(self):
            return [Step("side", lambda: side.append("step"))]

        def commit(self):
            side.append("commit")

    a = Defaulted()
    rep = GatedRunner(PhiGate(trust_store=trust), a).run()
    assert rep.status == "BLOCKED" and rep.stopped_at == "preflight" and side == []
    assert a.seen == ["PLAN"] and rep.decisions[0]["verdict"] == "FALSE"


def test_n3_zero_arg_provider_still_supported(trust):
    calls = []

    def provider():
        calls.append(1)
        return [attest("e", "pre:ok", True, binding={"task_id": TASK, "checkpoints": CHECKPOINTS})]

    side = []
    rep = GatedRunner(PhiGate(trust_store=trust), ProviderAdapter(provider, side)).run()
    assert rep.status == "COMPLETED" and len(calls) == 4 and side == ["step", "commit"]


class _NoSignature:
    __signature__ = "not a signature"

    def __call__(self, *a, **kw):
        raise AssertionError("must not be called")


@pytest.mark.parametrize("provider", [
    _NoSignature(),
    lambda *, other: [],
], ids=["uninspectable", "kw-only-other-name"])
def test_n3_unknown_provider_signature_fails_closed(trust, provider):
    side = []
    with pytest.raises(EvidenceProviderError):
        GatedRunner(PhiGate(trust_store=trust), ProviderAdapter(provider, side)).run()
    assert side == []


def test_n3_provider_exception_propagates_and_releases_nothing(trust):
    side = []

    def provider(checkpoint):
        if checkpoint == "STEP":
            raise RuntimeError("collector down")
        return evidence_for(checkpoint, None)

    with pytest.raises(RuntimeError):
        GatedRunner(PhiGate(trust_store=trust), ProviderAdapter(provider, side)).run()
    assert side == []


def test_n3_session_and_check_use_same_dispatch(trust):
    seen = []
    s = GateSession(PhiGate(trust_store=trust), all_cp_contract())
    with pytest.raises(GateBlocked):
        s.preflight(base_state(), lambda checkpoint="DISPATCH": seen.append(checkpoint) or evidence_for(checkpoint, "PLAN"),
                    action=lambda: None)
    assert seen == ["PLAN"]
    d = PhiGate(trust_store=trust).check("COMMIT", all_cp_contract(), base_state(),
                                         lambda *, checkpoint: evidence_for(checkpoint, "COMMIT"))
    assert d.result.verdict is Verdict.FALSE


# =========================================================================== N4 the command reads frozen criterion bytes


RACE_READER = (
    "import json,sys,pathlib,time\n"
    "sig, ack = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])\n"
    "sig.write_text('started')\n"
    "end = time.time() + 20\n"
    "while not ack.exists() and time.time() < end:\n"
    "    time.sleep(0.01)\n"
    "cfg = json.loads(pathlib.Path('limits.json').read_text())\n"
    "print('read', json.dumps(cfg))\n"
    "sig.write_text('read')\n"
    "end = time.time() + 20\n"
    "while sig.read_text() != 'restored' and time.time() < end:\n"
    "    time.sleep(0.01)\n"
    "sys.exit(0 if cfg['max'] == {want} else 1)\n"
)


def _race(ws, tmp_path, want):
    original = b'{"max": 1}\n'
    (ws / "limits.json").write_bytes(original)
    write(ws, "readcfg.py", RACE_READER.replace("{want}", str(want)))
    pins = pin(ws, "readcfg.py", "limits.json")
    sig, ack = tmp_path / "sig", tmp_path / "ack"
    swapped = {}

    def racer():
        end = time.time() + 30
        while not (sig.exists() and sig.read_text() == "started") and time.time() < end:
            time.sleep(0.005)
        (ws / "limits.json").write_text('{"max": 0}\n')
        swapped["during_run"] = json.loads((ws / "limits.json").read_text())
        ack.write_text("go")
        while sig.read_text() != "read" and time.time() < end:
            time.sleep(0.005)
        (ws / "limits.json").write_bytes(original)
        sig.write_text("restored")

    t = threading.Thread(target=racer, daemon=True)
    t.start()
    rep = accept(ws, cmd_req(["{python}", "readcfg.py", str(sig), str(ack)], pinned_files=pins, timeout_seconds=60))
    t.join(30)
    assert swapped == {"during_run": {"max": 0}}, "racer did not swap the workspace file during the run"
    assert (ws / "limits.json").read_bytes() == original
    return rep["requirement_results"][0]


def test_n4_regression_swap_and_restore_during_run_reads_frozen_bytes(ws, tmp_path):
    """Racer swaps limits.json to max=0 while the pinned reader runs and restores
    it afterwards. 6bca32e read the swapped bytes and returned PASS."""
    r = _race(ws, tmp_path, want=0)
    assert (r["status"], r["reason_codes"]) == ("FAIL", ["COMMAND_EXIT_CODE_UNEXPECTED"])
    assert 'read {"max": 1}' in r["detail"]["stdout_tail"]
    assert r["detail"]["execution"]["cwd"] == "frozen-snapshot"


def test_n4_control_correct_product_passes_despite_concurrent_writer(ws, tmp_path):
    r = _race(ws, tmp_path, want=1)
    assert (r["status"], r["reason_codes"]) == ("PASS", ["COMMAND_EXIT_CODE_AS_EXPECTED"])


def test_n4_workspace_criterion_left_changed_by_run_fails(ws, tmp_path):
    """The command (here acting for untrusted code it executes) rewrites the
    workspace copy of a criterion through an absolute host path."""
    write(ws, "limits.json", '{"max": 1}')
    code = f"open({str(ws / 'limits.json')!r}, 'w').write('{{}}')"
    rep = accept(ws, cmd_req(["{python}", "-c", code], pinned_files=pin(ws, "limits.json")))
    r = rep["requirement_results"][0]
    assert (r["status"], r["reason_codes"]) == ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED_DURING_RUN"])
    assert r["detail"]["where"] == "workspace"


def test_n4_snapshot_criterion_modified_by_command_fails_and_is_not_written_back(ws):
    script = "open('cfg.json', 'w').write('{}')\n"
    write(ws, "check.py", script)
    write(ws, "cfg.json", '{"a": 1}')
    rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pin(ws, "check.py", "cfg.json")))
    r = rep["requirement_results"][0]
    assert (r["status"], r["reason_codes"]) == ("FAIL", ["COMMAND_PINNED_FILE_MODIFIED_DURING_RUN"])
    assert r["detail"]["where"] == "snapshot" and (ws / "cfg.json").read_text() == '{"a": 1}'


def test_n4_outputs_written_back_without_following_links(ws, outside):
    (ws / "sub").mkdir()
    (ws / "sub" / "evil").symlink_to(outside / "target.txt")
    code = ("import os; open('report.txt','w').write('ok'); os.makedirs('deep', exist_ok=True); "
            "open('deep/r.txt','w').write('d'); os.unlink('sub/evil') if os.path.lexists('sub/evil') else None; "
            "open('sub/evil','w').write('pwn')")
    rep = accept(ws, cmd_req(["{python}", "-c", code]))
    r = rep["requirement_results"][0]
    assert r["status"] == "PASS"
    assert (ws / "report.txt").read_text() == "ok" and (ws / "deep" / "r.txt").read_text() == "d"
    assert not (outside / "target.txt").exists()
    assert r["detail"]["execution"]["outputs_not_written_back"] == ["sub/evil"]


def test_n4_pycache_never_enters_snapshot(ws):
    write(ws, "__pycache__/helper.cpython-312.pyc", "planted")
    write(ws, "pkg/__pycache__/x.pyc", "planted")
    code = "import os,sys; sys.exit(0 if not os.path.exists('__pycache__') and not os.path.exists('pkg/__pycache__') else 1)"
    rep = accept(ws, cmd_req(["{python}", "-c", code]))
    assert rep["status"] == "PASS"


def test_n4_snapshot_is_outside_workspace_and_removed(ws):
    code = f"import os,sys; sys.exit(0 if not os.getcwd().startswith({str(ws.resolve())!r}) else 1)"
    before = {p.name for p in Path(tempfile.gettempdir()).glob("phi-accept-*")}
    assert accept(ws, cmd_req(["{python}", "-c", code]))["status"] == "PASS"
    after = {p.name for p in Path(tempfile.gettempdir()).glob("phi-accept-*")}
    assert after <= before


SHADOW_CHECK = "import json,sys\nsys.exit(0 if json.loads('{\"n\": 1}')['n'] == 1 else 1)\n"
FAKE = "import sys\nloads = lambda s: {'n': 1}\n"


@pytest.mark.parametrize("layout", [
    {"json.py": FAKE},
    {"json/__init__.py": FAKE},
    {"jsonschema.py": FAKE},
], ids=["stdlib-module", "stdlib-package", "installed-module"])
def test_n1_regression_unpinned_workspace_module_shadowing_trusted_import(ws, layout):
    write(ws, "check.py", SHADOW_CHECK)
    for rel, text in layout.items():
        write(ws, rel, text)
    rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pin(ws, "check.py"), artifacts=["."]))
    r = rep["requirement_results"][0]
    assert (r["status"], r["reason_codes"]) == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_SHADOWS_MODULE"])
    assert set(layout) <= set(r["detail"]["shadowing_not_pinned"])
    rep = accept(ws, cmd_req(["{python}", "-c", "import json"], artifacts=["."]))
    assert req_status(rep, "R1") == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_SHADOWS_MODULE"])


def test_n1_control_shadowing_rules(ws):
    write(ws, "check.py", SHADOW_CHECK)
    write(ws, "json/readme.txt", "namespace dir, not a package")
    assert accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pin(ws, "check.py")))["status"] == "PASS"
    write(ws, "json.py", "import sys\nloads = lambda s: {'n': 1}\n")
    assert accept(ws, cmd_req(["{python}", "-I", "check.py"], pinned_files=pin(ws, "check.py")))["status"] == "PASS"
    rep = accept(ws, cmd_req(["{python}", "check.py"], pinned_files=pin(ws, "check.py", "json.py")))
    assert rep["status"] == "PASS"


def test_n1_regression_file_added_between_check_and_snapshot(ws, monkeypatch, tmp_path):
    """A producer creates an undeclared data file after the live-workspace role
    check and before the snapshot copy: the snapshot re-check refuses it."""
    from phi_core import command

    marker = tmp_path / "ran"
    write(ws, "check.py", marking(marker))
    real_copy = command._copy_workspace

    def racing_copy(paths, snap, copied):
        write(ws, "in.txt", "late")
        return real_copy(paths, snap, copied)

    monkeypatch.setattr(command, "_copy_workspace", racing_copy)
    rep = accept(ws, cmd_req(["{python}", "check.py", "in.txt"], pinned_files=pin(ws, "check.py")))
    r = rep["requirement_results"][0]
    assert (r["status"], r["reason_codes"]) == ("INCONCLUSIVE", ["COMMAND_WORKSPACE_FILE_NOT_PINNED"])
    assert r["detail"]["changed_while_snapshotting"] is True and not marker.exists()


# =========================================================================== property and concurrency


_TOKENS = st.sampled_from(["check.py", "./check.py", "scripts/check.py", "scripts/../check.py", "link.py",
                           "linkdir/evil.py", "../outside/evil.py", ".", "scripts", "-I", "-B", "data.txt",
                           "--x=check.py", "--x=link.py"])
_ARTS = st.lists(st.sampled_from([".", "./", "check.py", "scripts", "link.py", "linkdir", "data.txt"]),
                 max_size=4, unique=True)


@pytest.fixture(scope="module")
def prop_ws(tmp_path_factory):
    root = tmp_path_factory.mktemp("prop")
    ws, out = root / "ws", root / "outside"
    ws.mkdir()
    out.mkdir()
    (out / "evil.py").write_text(EXIT0)
    write(ws, "check.py", EXIT0)
    write(ws, "scripts/check.py", EXIT0)
    write(ws, "data.txt", "d")
    (ws / "link.py").symlink_to(out / "evil.py")
    (ws / "linkdir").symlink_to(out, target_is_directory=True)
    return ws


@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(script=_TOKENS, rest=st.lists(_TOKENS, max_size=3), artifacts=_ARTS)
def test_property_unpinned_or_escaping_program_never_passes(prop_ws, script, rest, artifacts):
    rep = accept(prop_ws, cmd_req(["{python}", script, *rest], artifacts=artifacts))
    assert rep["status"] != "PASS", (script, rest, artifacts, rep["requirement_results"])


def test_concurrent_command_acceptance_is_isolated(ws):
    write(ws, "check.py", "import sys,pathlib\npathlib.Path('out-' + sys.argv[1]).write_text(sys.argv[1])\n")
    pins = pin(ws, "check.py")

    def one(i):
        return accept(ws, cmd_req(["{python}", "check.py", str(i)], pinned_files=pins))["status"]

    with ThreadPoolExecutor(8) as pool:
        statuses = list(pool.map(one, range(16)))
    assert statuses == ["PASS"] * 16
    assert sorted(p.name for p in ws.glob("out-*")) == sorted(f"out-{i}" for i in range(16))
