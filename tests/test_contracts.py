import copy
import json
import tomllib
from pathlib import Path

import pytest

from phi_core import (
    ContractFormatError,
    EvidenceFormatError,
    EvidenceItem,
    TaskContract,
    Verdict,
    compile_constraints,
    contract_hash,
    evaluate,
    load_schema,
    seal_contract,
    validate_contract,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_task.json"
V1 = ROOT / "examples" / "v1" / "contract.json"


@pytest.fixture
def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def test_installed_schema_matches_repo_schema():
    repo_schema = json.loads((ROOT / "schemas" / "task_contract.schema.json").read_text("utf-8"))
    assert load_schema() == repo_schema


def test_sample_contract_is_structurally_valid(sample):
    result = validate_contract(sample)
    assert result.valid, result.errors
    assert result.errors == []


def test_from_dict_roundtrip(sample):
    contract = TaskContract.from_dict(sample)
    assert contract.task_id == "example-001"
    assert [c.kind for c in contract.constraints] == ["hard", "soft"]
    assert contract.to_dict() == sample


def _mutate(sample, fn):
    data = copy.deepcopy(sample)
    fn(data)
    return data


@pytest.mark.parametrize(
    "mutation, fragment",
    [
        (lambda d: d.pop("task_id"), "'task_id' is a required property"),
        (lambda d: d.pop("constraints"), "'constraints' is a required property"),
        (lambda d: d.__setitem__("contract_version", "9.9"), "contract_version"),
        (lambda d: d.__setitem__("constraints", []), "constraints"),
        (lambda d: d.__setitem__("objective", 42), "objective"),
        (lambda d: d.__setitem__("unexpected", True), "Additional properties"),
        (lambda d: d["constraints"][0].__setitem__("kind", "critical"), "constraints/0/kind"),
        (lambda d: d["constraints"][1].pop("statement"), "'statement' is a required property"),
        (lambda d: d.__setitem__("task_id", "has space"), "task_id"),
    ],
)
def test_invalid_contracts_are_rejected(sample, mutation, fragment):
    result = validate_contract(_mutate(sample, mutation))
    assert not result.valid
    assert any(fragment in e for e in result.errors), result.errors


def test_non_object_is_rejected():
    assert not validate_contract([]).valid
    assert not validate_contract("contract").valid


def test_from_dict_raises_on_invalid(sample):
    bad = _mutate(sample, lambda d: d.pop("objective"))
    with pytest.raises(ContractFormatError) as exc:
        TaskContract.from_dict(bad)
    assert exc.value.errors


def test_evidence_model_requires_all_v1_fields():
    full = {
        "evidence_id": "e1", "constraint_id": "c1", "source": "probe", "verifier_id": "file_sha256",
        "observed_value": {"path": "a"}, "verification_status": "VERIFIED", "timestamp": "2026-01-01T00:00:00Z",
        "artifact_hash": None, "provenance": {},
    }
    item = EvidenceItem.from_dict(full)
    assert item.constraint_id == "c1"
    assert item.to_dict() == full
    for key in full:
        broken = {k: v for k, v in full.items() if k != key}
        with pytest.raises(EvidenceFormatError):
            EvidenceItem.from_dict(broken)
    with pytest.raises(EvidenceFormatError):
        EvidenceItem.from_dict({**full, "timestamp": "yesterday"})


def test_legacy_draft_contract_is_not_evaluated_by_phi(sample):
    # Upgraded from the bootstrap NotImplementedError placeholder: Phi is now implemented,
    # but a 0.1-draft contract is outside its input language and must never yield TRUE.
    result = evaluate(sample, {"state_version": "1.0", "now": "2026-01-01T00:00:00Z", "tasks": {}}, [],
                      checkpoint="DISPATCH")
    assert result.verdict is Verdict.UNKNOWN
    assert "CONTRACT_VERSION_UNSUPPORTED" in result.reason_codes
    assert not result.release


def test_verdict_enum_only_declares_three_values():
    assert {v.value for v in Verdict} == {"TRUE", "FALSE", "UNKNOWN"}


def test_no_fbs_runtime_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    deps = " ".join(project["dependencies"]).lower()
    assert "feasibility" not in deps and "fbs" not in deps
    assert project["dependencies"] == ["jsonschema>=4.18"]


def test_no_fbs_llm_or_cloud_imports_in_package():
    import ast

    banned = {"feasibility_scheduler", "fbs", "openai", "anthropic", "requests", "httpx", "urllib3",
              "boto3", "google", "langchain", "transformers", "socket", "http", "urllib"}
    for path in (ROOT / "src" / "phi_core").glob("*.py"):
        tree = ast.parse(path.read_text("utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in banned, f"{path.name} imports {name}"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile"), f"{path.name} calls {node.func.id}"


# --------------------------------------------------------------------------- v1.0 contract


@pytest.fixture
def v1():
    return json.loads(V1.read_text(encoding="utf-8"))


def test_v1_example_is_valid_and_sealed(v1):
    assert validate_contract(v1).valid, validate_contract(v1).errors
    assert v1["integrity"]["contract_hash"] == contract_hash(v1)


def test_v1_schema_shipped_with_package_matches_repo():
    repo = json.loads((ROOT / "schemas" / "task_contract.v1.schema.json").read_text("utf-8"))
    assert load_schema("1.0") == repo


@pytest.mark.parametrize(
    "mutation, fragment",
    [
        (lambda d: d.pop("constraint_scope"), "constraint_scope"),
        (lambda d: d.__setitem__("inputs", [{"path": "/etc/passwd"}]), "inputs/0/path"),
        (lambda d: d.__setitem__("inputs", [{"path": "../outside"}]), "inputs/0/path"),
        (lambda d: d.__setitem__("dependencies", ["build-report"]), "depends on itself"),
        (lambda d: d["constraints"][0].__setitem__("kind", "critical"), "constraints/0/kind"),
        (lambda d: d["constraints"][0].__setitem__("checkpoints", ["LATER"]), "checkpoints"),
        (lambda d: d["constraints"].append(dict(d["constraints"][0])), "duplicate constraint_id"),
        (lambda d: d["time_bounds"].__setitem__("deadline", "tomorrow"), "deadline"),
        (lambda d: d.__setitem__("surprise", 1), "Additional properties"),
        (lambda d: d["outputs"].append({"path": "report/summary.json"}), "duplicate path"),
    ],
)
def test_v1_invalid_contracts_rejected(v1, mutation, fragment):
    bad = copy.deepcopy(v1)
    mutation(bad)
    res = validate_contract(bad)
    assert not res.valid
    assert any(fragment in e for e in res.errors), res.errors


def test_compile_constraints_expands_structured_fields(v1):
    ids = {c.constraint_id: c for c in compile_constraints(v1)}
    assert ids["dep:fetch-data"].predicate_type == "dependency_completed"
    assert ids["input:data/input.csv:sha256"].predicate_type == "file_hash"
    assert ids["output:report/summary.json:exists"].checkpoints == ("COMMIT",)
    assert ids["output:report/summary.json:ownership"].params["owner"] == "build-report"
    assert ids["capability:python3"].checkpoints == ("PLAN", "DISPATCH")
    assert ids["time:deadline"].predicate_type == "deadline"
    assert ids["tests:unit"].verifiers == ("hmac_attestation",)
    assert ids["style:report-readable"].kind == "soft"


def test_seal_and_hash_exclude_integrity_block(v1):
    resealed = seal_contract({k: v for k, v in v1.items() if k != "integrity"})
    assert resealed == v1
    edited = copy.deepcopy(v1)
    edited["objective"] = "something else"
    assert contract_hash(edited) != v1["integrity"]["contract_hash"]
