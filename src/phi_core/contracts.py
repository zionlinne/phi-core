"""Task contract models, structural validation, integrity hash and constraint compilation.

Two contract versions are understood:

* ``"1.0"``       -- the formal versioned Task Contract used by Phi(T, S, E).
* ``"0.1-draft"`` -- the bootstrap-phase draft, kept only for structural
  validation backwards compatibility. Phi does not evaluate it.

Structural validity only means a document matches the schema. It is not a
feasibility verdict and not an acceptance result.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .canonical import hash_obj
from .schemas import SCHEMA_FILES, load_schema_file, schema_errors

CONTRACT_VERSION = "1.0"
LEGACY_CONTRACT_VERSION = "0.1-draft"
SCHEMA_FILENAME = SCHEMA_FILES["contract-0.1-draft"]
CHECKPOINTS = ("PLAN", "DISPATCH", "STEP", "COMMIT")
_EXEC = ("DISPATCH", "STEP", "COMMIT")


class ContractFormatError(ValueError):
    """Raised when a document is not a structurally valid task contract."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) or "invalid task contract")


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of structural validation. ``valid`` is NOT a feasibility verdict."""

    valid: bool
    errors: list[str]


# --------------------------------------------------------------------------- legacy 0.1-draft


@dataclass(frozen=True)
class Constraint:
    constraint_id: str
    kind: str
    statement: str


@dataclass(frozen=True)
class TaskContract:
    """Typed view of a legacy ``0.1-draft`` contract (validation only)."""

    contract_version: str
    task_id: str
    objective: str
    constraints: tuple[Constraint, ...]
    required_evidence: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskContract":
        result = validate_contract(data)
        if not result.valid:
            raise ContractFormatError(result.errors)
        if data.get("contract_version") != LEGACY_CONTRACT_VERSION:
            raise ContractFormatError(["TaskContract.from_dict only builds 0.1-draft contracts"])
        return cls(
            contract_version=data["contract_version"],
            task_id=data["task_id"],
            objective=data["objective"],
            constraints=tuple(
                Constraint(constraint_id=c["constraint_id"], kind=c["kind"], statement=c["statement"])
                for c in data["constraints"]
            ),
            required_evidence=tuple(data.get("required_evidence", ())),
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "contract_version": self.contract_version,
            "task_id": self.task_id,
            "objective": self.objective,
            "constraints": [
                {"constraint_id": c.constraint_id, "kind": c.kind, "statement": c.statement}
                for c in self.constraints
            ],
        }
        if self.required_evidence:
            out["required_evidence"] = list(self.required_evidence)
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


def load_schema(version: str = LEGACY_CONTRACT_VERSION) -> dict[str, Any]:
    key = "contract" if version == CONTRACT_VERSION else "contract-0.1-draft"
    return load_schema_file(SCHEMA_FILES[key])


# --------------------------------------------------------------------------- v1.0


@dataclass(frozen=True)
class CompiledConstraint:
    """A machine-executable constraint, explicit or derived from structured contract fields."""

    constraint_id: str
    kind: str
    predicate_type: str
    params: Mapping[str, Any]
    checkpoints: tuple[str, ...]
    origin: str
    statement: str = ""
    verifiers: tuple[str, ...] | None = None
    max_age_seconds: int | None = None
    min_items: int = 1


def contract_hash(contract: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical contract without its ``integrity`` block."""
    return hash_obj({k: v for k, v in contract.items() if k != "integrity"})


def seal_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with ``integrity.contract_hash`` set. Self-hash detects accidental
    or naive edits only; whoever can edit the contract can also recompute this hash."""
    out = copy.deepcopy(dict(contract))
    out["integrity"] = {"contract_hash": contract_hash(out)}
    return out


def compile_constraints(contract: Mapping[str, Any]) -> list[CompiledConstraint]:
    """Expand structured contract fields into typed predicates. Assumes schema-valid input."""
    task_id = contract["task_id"]
    out: list[CompiledConstraint] = []

    def add(cid, ptype, params, cps, origin, statement=""):
        out.append(
            CompiledConstraint(
                constraint_id=cid, kind="hard", predicate_type=ptype, params=params,
                checkpoints=tuple(cps), origin=origin, statement=statement,
            )
        )

    for dep in contract.get("dependencies", []):
        add(f"dep:{dep}", "dependency_completed", {"task_id": dep}, _EXEC, "dependencies",
            f"dependency {dep} completed")
    for inp in contract.get("inputs", []):
        path = inp["path"]
        add(f"input:{path}:exists", "input_exists", {"path": path}, _EXEC, "inputs", f"input {path} exists")
        if "sha256" in inp:
            add(f"input:{path}:sha256", "file_hash", {"path": path, "sha256": inp["sha256"]}, _EXEC,
                "inputs", f"input {path} integrity")
    for outp in contract.get("outputs", []):
        path = outp["path"]
        owner = outp.get("owner", task_id)
        add(f"output:{path}:ownership", "ownership", {"path": path, "owner": owner}, _EXEC, "outputs",
            f"output {path} owned by {owner}")
        add(f"output:{path}:exists", "output_exists", {"path": path}, ("COMMIT",), "outputs",
            f"output {path} exists")
        if "sha256" in outp:
            add(f"output:{path}:sha256", "file_hash", {"path": path, "sha256": outp["sha256"]}, ("COMMIT",),
                "outputs", f"output {path} integrity")
        if "schema" in outp:
            add(f"output:{path}:schema", "schema_compatible", {"path": path, "schema_path": outp["schema"]},
                ("COMMIT",), "outputs", f"output {path} matches {outp['schema']}")
    for cap in contract.get("capabilities", []):
        add(f"capability:{cap}", "capability", {"name": cap}, ("PLAN", "DISPATCH"), "capabilities")
    for res in contract.get("resources", []):
        add(f"resource:{res['name']}", "resource_available", {"name": res["name"], "amount": res["amount"]},
            ("DISPATCH",), "resources")
    bounds = contract.get("time_bounds", {})
    if "deadline" in bounds:
        add("time:deadline", "deadline", {"deadline": bounds["deadline"]}, _EXEC, "time_bounds")
    if "not_before" in bounds:
        add("time:not_before", "not_before", {"not_before": bounds["not_before"]}, ("DISPATCH",), "time_bounds")

    for c in contract.get("constraints", []):
        ev = c.get("evidence", {})
        out.append(
            CompiledConstraint(
                constraint_id=c["constraint_id"],
                kind=c["kind"],
                predicate_type=c["predicate"]["type"],
                params=copy.deepcopy(c["predicate"].get("params", {})),
                checkpoints=tuple(c.get("checkpoints", CHECKPOINTS)),
                origin="constraints",
                statement=c.get("statement", ""),
                verifiers=tuple(ev["verifiers"]) if "verifiers" in ev else None,
                max_age_seconds=ev.get("max_age_seconds"),
                min_items=ev.get("min_items", 1),
            )
        )
    return out


def semantic_errors(contract: Mapping[str, Any]) -> list[str]:
    """Checks beyond JSON Schema. Assumes schema-valid input."""
    errors = []
    task_id = contract["task_id"]
    if task_id in contract.get("dependencies", []):
        errors.append("dependencies: task depends on itself")
    if task_id in contract.get("subtasks", []):
        errors.append("subtasks: task lists itself as subtask")
    if contract.get("parent_task_id") == task_id:
        errors.append("parent_task_id: task is its own parent")
    for key in ("inputs", "outputs"):
        paths = [x["path"] for x in contract.get(key, [])]
        if len(paths) != len(set(paths)):
            errors.append(f"{key}: duplicate path")
    names = [r["name"] for r in contract.get("resources", [])]
    if len(names) != len(set(names)):
        errors.append("resources: duplicate name")
    counts = Counter(c.constraint_id for c in compile_constraints(contract))
    dupes = sorted(i for i, n in counts.items() if n > 1)
    if dupes:
        errors.append(f"constraints: duplicate constraint_id {dupes}")
    return errors


def validate_contract(data: Any) -> ValidationResult:
    """Structural (+ semantic for v1.0) validation. Not a feasibility verdict."""
    if isinstance(data, dict) and data.get("contract_version") == CONTRACT_VERSION:
        errors = schema_errors("contract", data)
        if not errors:
            errors = semantic_errors(data)
        return ValidationResult(valid=not errors, errors=errors)
    errors = schema_errors("contract-0.1-draft", data)
    return ValidationResult(valid=not errors, errors=errors)


def load_contract_file(path: str | Path) -> Any:
    """Read a JSON file. Raises OSError or json.JSONDecodeError on failure."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


load_json_file = load_contract_file
