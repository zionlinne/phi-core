import copy
import json
import tomllib
from pathlib import Path

import pytest

from phi_core import (
    ContractFormatError,
    EvidenceItem,
    EvidenceSet,
    TaskContract,
    Verdict,
    evaluate,
    load_schema,
    validate_contract,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_task.json"


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
        (lambda d: d.__setitem__("contract_version", "1.0"), "contract_version"),
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


def test_evidence_model():
    ev = EvidenceSet.from_list(
        [{"evidence_id": "e1", "kind": "toolchain_probe", "source": "probe", "constraint_id": "c1"}]
    )
    assert len(ev) == 1
    assert ev.items[0].constraint_id == "c1"
    with pytest.raises(ValueError):
        EvidenceItem.from_dict({"evidence_id": "e1", "kind": "x"})


def test_evaluate_is_not_implemented(sample):
    contract = TaskContract.from_dict(sample)
    with pytest.raises(NotImplementedError):
        evaluate(contract, EvidenceSet())


def test_verdict_enum_only_declares_three_values():
    assert {v.value for v in Verdict} == {"TRUE", "FALSE", "UNKNOWN"}


def test_no_fbs_runtime_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    deps = " ".join(project["dependencies"]).lower()
    assert "feasibility" not in deps and "fbs" not in deps
