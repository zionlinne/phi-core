"""Task contract data model and structural validation.

The fields here are a DRAFT engineering protocol (``contract_version`` =
``"0.1-draft"``). They are not a frozen specification.

Structural validity only means a document matches the JSON Schema. It does not
mean the task is feasible and it does not mean final acceptance has passed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

CONTRACT_VERSION = "0.1-draft"
SCHEMA_FILENAME = "task_contract.schema.json"


class ContractFormatError(ValueError):
    """Raised when a document is not a structurally valid task contract."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) or "invalid task contract")


@dataclass(frozen=True)
class Constraint:
    constraint_id: str
    kind: str  # "hard" | "soft"; no priority/evaluation semantics yet
    statement: str


@dataclass(frozen=True)
class TaskContract:
    contract_version: str
    task_id: str
    objective: str
    constraints: tuple[Constraint, ...]
    required_evidence: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskContract":
        """Build a contract from a mapping, raising ContractFormatError if invalid."""
        result = validate_contract(data)
        if not result.valid:
            raise ContractFormatError(result.errors)
        return cls(
            contract_version=data["contract_version"],
            task_id=data["task_id"],
            objective=data["objective"],
            constraints=tuple(
                Constraint(
                    constraint_id=c["constraint_id"],
                    kind=c["kind"],
                    statement=c["statement"],
                )
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
                {
                    "constraint_id": c.constraint_id,
                    "kind": c.kind,
                    "statement": c.statement,
                }
                for c in self.constraints
            ],
        }
        if self.required_evidence:
            out["required_evidence"] = list(self.required_evidence)
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of structural validation. ``valid`` is NOT a feasibility verdict."""

    valid: bool
    errors: list[str]


def _repo_schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / SCHEMA_FILENAME


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load the task contract JSON Schema.

    Installed wheels carry a copy under ``phi_core/_schemas``; editable/source
    checkouts fall back to the repository-level ``schemas/`` directory.
    """
    packaged = resources.files("phi_core").joinpath("_schemas", SCHEMA_FILENAME)
    if packaged.is_file():
        return json.loads(packaged.read_text(encoding="utf-8"))
    repo_path = _repo_schema_path()
    if repo_path.is_file():
        return json.loads(repo_path.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"cannot locate {SCHEMA_FILENAME}")


def validate_contract(data: Any) -> ValidationResult:
    """Check that ``data`` is structurally a valid task contract."""
    validator = Draft202012Validator(load_schema())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    messages = []
    for err in errors:
        location = "/".join(str(p) for p in err.absolute_path) or "<root>"
        messages.append(f"{location}: {err.message}")
    return ValidationResult(valid=not messages, errors=messages)


def load_contract_file(path: str | Path) -> Any:
    """Read a JSON file. Raises OSError or json.JSONDecodeError on failure."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
