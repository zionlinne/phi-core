"""Typed, machine-executable predicates and the extensible Predicate Registry.

Every predicate is deterministic Python over explicit inputs (state S and
verified evidence observations). Nothing here evaluates strings as code, calls
``eval``/``exec``, or interprets natural language. A predicate type without a
registered implementation is UNRESOLVED (never guessed).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from .canonical import parse_time
from .safeschema import pin_issue


class Status(str, Enum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class Outcome:
    status: Status
    reason_codes: tuple[str, ...] = ()
    detail: str = ""


def sat(*codes: str, detail: str = "") -> Outcome:
    return Outcome(Status.SATISFIED, tuple(codes), detail)


def violated(*codes: str, detail: str = "") -> Outcome:
    return Outcome(Status.VIOLATED, tuple(codes), detail)


def unresolved(*codes: str, detail: str = "") -> Outcome:
    return Outcome(Status.UNRESOLVED, tuple(codes), detail)


RESERVED_NON_EXECUTABLE = frozenset({"natural_language", "llm", "llm_judgment", "free_text"})


class Predicate:
    """Base class. ``required_params`` maps name -> accepted Python types."""

    kind: str = "state"  # "state" or "evidence"
    required_params: Mapping[str, tuple[type, ...]] = {}

    def param_errors(self, params: Mapping[str, Any]) -> list[str]:
        errors = []
        for name, types in self.required_params.items():
            if name not in params:
                errors.append(f"missing param {name}")
            else:
                value = params[name]
                bool_as_number = isinstance(value, bool) and (int in types or float in types)
                if not isinstance(value, types) or bool_as_number:
                    errors.append(f"param {name} has wrong type")
        return errors


class StatePredicate(Predicate):
    kind = "state"

    def evaluate(self, params: Mapping[str, Any], state: Mapping[str, Any]) -> Outcome:
        raise NotImplementedError


class EvidencePredicate(Predicate):
    kind = "evidence"
    default_verifiers: tuple[str, ...] = ()

    def subject_matches(self, params: Mapping[str, Any], observed: Any) -> bool:
        return True

    def judge(self, params: Mapping[str, Any], observed: Any) -> Outcome:
        raise NotImplementedError


# --------------------------------------------------------------------------- state predicates


class DependencyCompleted(StatePredicate):
    required_params = {"task_id": (str,)}

    def evaluate(self, params, state):
        task = state.get("tasks", {}).get(params["task_id"])
        if task is None:
            return unresolved("DEPENDENCY_STATE_MISSING")
        status = task.get("status")
        if status == "completed":
            return sat()
        if status in ("failed", "cancelled"):
            return violated("DEPENDENCY_FAILED", detail=f"status={status}")
        return unresolved("DEPENDENCY_NOT_COMPLETED", detail=f"status={status}")


class Ownership(StatePredicate):
    required_params = {"path": (str,), "owner": (str,)}

    def evaluate(self, params, state):
        owners = state.get("file_owners", {})
        if params["path"] not in owners:
            return unresolved("OWNERSHIP_UNREGISTERED")
        actual = owners[params["path"]]
        if actual == params["owner"]:
            return sat()
        return violated("OWNERSHIP_CONFLICT", detail=f"owned by {actual}")


class ResourceAvailable(StatePredicate):
    required_params = {"name": (str,), "amount": (int, float)}

    def evaluate(self, params, state):
        resources = state.get("resources", {})
        if params["name"] not in resources:
            return unresolved("RESOURCE_STATE_MISSING")
        if resources[params["name"]] >= params["amount"]:
            return sat()
        return violated("RESOURCE_INSUFFICIENT", detail=f"available={resources[params['name']]}")


class Capability(StatePredicate):
    required_params = {"name": (str,)}

    def evaluate(self, params, state):
        caps = state.get("capabilities")
        if caps is not None and params["name"] in caps:
            return sat()
        if caps is not None and state.get("capabilities_complete") is True:
            return violated("CAPABILITY_MISSING")
        return unresolved("CAPABILITY_UNKNOWN")


class Deadline(StatePredicate):
    required_params = {"deadline": (str,)}

    def param_errors(self, params):
        errors = super().param_errors(params)
        if not errors:
            try:
                parse_time(params["deadline"])
            except ValueError:
                errors.append("param deadline is not a timestamp")
        return errors

    def evaluate(self, params, state):
        now = parse_time(state["now"])
        if now <= parse_time(params["deadline"]):
            return sat()
        return violated("DEADLINE_PASSED")


class NotBefore(StatePredicate):
    required_params = {"not_before": (str,)}

    def param_errors(self, params):
        errors = super().param_errors(params)
        if not errors:
            try:
                parse_time(params["not_before"])
            except ValueError:
                errors.append("param not_before is not a timestamp")
        return errors

    def evaluate(self, params, state):
        if parse_time(state["now"]) >= parse_time(params["not_before"]):
            return sat()
        return unresolved("NOT_BEFORE_NOT_REACHED")


# --------------------------------------------------------------------------- evidence predicates


class _PathSubject(EvidencePredicate):
    def subject_matches(self, params, observed):
        return isinstance(observed, Mapping) and observed.get("path") == params["path"]


class FileExists(_PathSubject):
    required_params = {"path": (str,)}
    default_verifiers = ("file_sha256",)

    def __init__(self, missing_code: str):
        self.missing_code = missing_code

    def judge(self, params, observed):
        exists = observed.get("exists")
        if exists is True:
            return sat()
        if exists is False:
            return violated(self.missing_code)
        return unresolved("OBSERVATION_INCOMPLETE")


class FileHash(_PathSubject):
    required_params = {"path": (str,), "sha256": (str,)}
    default_verifiers = ("file_sha256",)

    def judge(self, params, observed):
        if observed.get("exists") is False:
            return violated("FILE_MISSING")
        actual = observed.get("sha256")
        if not isinstance(actual, str):
            return unresolved("OBSERVATION_INCOMPLETE")
        if actual == params["sha256"]:
            return sat()
        return violated("FILE_HASH_MISMATCH", detail=f"actual={actual}")


class SchemaCompatible(_PathSubject):
    """The schema is a criterion and must be frozen: ``schema_sha256`` pins the
    root document and ``schema_refs`` ({relpath: sha256}) pins every document it
    may reference. The verifier reports the closure it actually loaded; an
    unpinned document is UNRESOLVED, a pinned one with different bytes is a
    verified violation (the frozen criterion was replaced)."""

    required_params = {"path": (str,), "schema_path": (str,)}
    default_verifiers = ("json_schema",)

    def param_errors(self, params):
        errors = super().param_errors(params)
        if "schema_sha256" in params and not isinstance(params["schema_sha256"], str):
            errors.append("param schema_sha256 has wrong type")
        refs = params.get("schema_refs", {})
        if not isinstance(refs, Mapping) or not all(isinstance(v, str) for v in refs.values()):
            errors.append("param schema_refs must map relpath -> sha256")
        return errors

    def subject_matches(self, params, observed):
        return super().subject_matches(params, observed) and observed.get("schema_path") == params["schema_path"]

    def judge(self, params, observed):
        if observed.get("exists") is False:
            return violated("FILE_MISSING")
        closure = observed.get("schema_closure")
        if not isinstance(closure, Mapping):
            return unresolved("SCHEMA_CLOSURE_NOT_OBSERVED")
        issue = pin_issue(closure, params["schema_path"], params.get("schema_sha256"), params.get("schema_refs"))
        if issue is not None:
            kind, code = issue
            return violated(code) if kind == "violated" else unresolved(code)
        valid = observed.get("valid")
        if valid is True:
            return sat()
        if valid is False:
            return violated("SCHEMA_INCOMPATIBLE")
        return unresolved("OBSERVATION_INCOMPLETE")


class AttestedValue(EvidencePredicate):
    """Exact structural equality between a verified attested value and ``expected``."""

    required_params = {"expected": (object,)}
    default_verifiers = ("hmac_attestation",)

    def judge(self, params, observed):
        if observed == params["expected"]:
            return sat()
        return violated("ATTESTED_VALUE_MISMATCH")


class FunctionPredicate(Predicate):
    """Adapter for registering a plain deterministic function.

    ``kind="state"``:    fn(params, state) -> Outcome
    ``kind="evidence"``: fn(params, observed) -> Outcome, with optional subject_fn.
    """

    def __init__(self, fn: Callable[..., Outcome], kind: str = "state",
                 required_params: Mapping[str, tuple[type, ...]] | None = None,
                 default_verifiers: tuple[str, ...] = (),
                 subject_fn: Callable[[Mapping[str, Any], Any], bool] | None = None):
        if kind not in ("state", "evidence"):
            raise ValueError("kind must be 'state' or 'evidence'")
        self.fn = fn
        self.kind = kind
        self.required_params = dict(required_params or {})
        self.default_verifiers = tuple(default_verifiers)
        self.subject_fn = subject_fn

    def evaluate(self, params, state):
        return self.fn(params, state)

    def judge(self, params, observed):
        return self.fn(params, observed)

    def subject_matches(self, params, observed):
        return True if self.subject_fn is None else bool(self.subject_fn(params, observed))


class PredicateRegistry:
    def __init__(self) -> None:
        self._preds: dict[str, Predicate] = {}

    def register(self, name: str, predicate: Predicate, *, replace: bool = False) -> None:
        if name in RESERVED_NON_EXECUTABLE:
            raise ValueError(f"predicate type {name!r} is reserved as non-executable")
        if not isinstance(predicate, Predicate):
            raise TypeError("predicate must be a phi_core.predicates.Predicate")
        if predicate.kind not in ("state", "evidence"):
            raise ValueError("predicate.kind must be 'state' or 'evidence'")
        if name in self._preds and not replace:
            raise ValueError(f"predicate type {name!r} already registered")
        self._preds[name] = predicate

    def get(self, name: str) -> Predicate | None:
        return self._preds.get(name)

    def names(self) -> list[str]:
        return sorted(self._preds)

    def copy(self) -> "PredicateRegistry":
        new = PredicateRegistry()
        new._preds = dict(self._preds)
        return new


def default_predicate_registry() -> PredicateRegistry:
    reg = PredicateRegistry()
    reg.register("dependency_completed", DependencyCompleted())
    reg.register("ownership", Ownership())
    reg.register("resource_available", ResourceAvailable())
    reg.register("capability", Capability())
    reg.register("deadline", Deadline())
    reg.register("not_before", NotBefore())
    reg.register("input_exists", FileExists("INPUT_MISSING"))
    reg.register("output_exists", FileExists("OUTPUT_MISSING"))
    reg.register("file_hash", FileHash())
    reg.register("schema_compatible", SchemaCompatible())
    reg.register("attested_value", AttestedValue())
    return reg
