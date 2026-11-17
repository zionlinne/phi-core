"""Locate and cache the JSON Schemas shipped with phi-core."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_FILES = {
    "contract-0.1-draft": "task_contract.schema.json",
    "contract": "task_contract.v1.schema.json",
    "state": "state.v1.schema.json",
    "evidence": "evidence.v1.schema.json",
    "baseline": "requirements_baseline.v1.schema.json",
    "anchor": "baseline_anchor.v1.schema.json",
    "delivery": "delivery_report.v1.schema.json",
}


def _repo_schema_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas"


@lru_cache(maxsize=None)
def load_schema_file(filename: str) -> dict[str, Any]:
    """Installed wheels carry a copy under ``phi_core/_schemas``; editable/source
    checkouts fall back to the repository-level ``schemas/`` directory."""
    packaged = resources.files("phi_core").joinpath("_schemas", filename)
    if packaged.is_file():
        return json.loads(packaged.read_text(encoding="utf-8"))
    repo_path = _repo_schema_dir() / filename
    if repo_path.is_file():
        return json.loads(repo_path.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"cannot locate schema {filename}")


@lru_cache(maxsize=None)
def validator_for(kind: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema_file(SCHEMA_FILES[kind]))


def schema_errors(kind: str, data: Any) -> list[str]:
    errors = sorted(validator_for(kind).iter_errors(data), key=lambda e: [str(p) for p in e.absolute_path])
    out = []
    for err in errors:
        location = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"{location}: {err.message}")
    return out
