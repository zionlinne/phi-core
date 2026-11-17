"""Evidence data model (DRAFT engineering protocol, not frozen).

Evidence items are opaque records in this phase. Nothing in this module
verifies evidence, resolves conflicts between items, or weighs them; those
semantics are undecided and belong to the future Phi implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    kind: str
    source: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    constraint_id: str | None = None
    collected_at: str | None = None  # ISO-8601 string; not parsed or checked

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceItem":
        missing = [k for k in ("evidence_id", "kind", "source") if k not in data]
        if missing:
            raise ValueError(f"evidence item missing required field(s): {', '.join(missing)}")
        for key in ("evidence_id", "kind", "source"):
            if not isinstance(data[key], str) or not data[key]:
                raise ValueError(f"evidence field '{key}' must be a non-empty string")
        payload = data.get("payload", {})
        if not isinstance(payload, Mapping):
            raise ValueError("evidence field 'payload' must be an object")
        return cls(
            evidence_id=data["evidence_id"],
            kind=data["kind"],
            source=data["source"],
            payload=dict(payload),
            constraint_id=data.get("constraint_id"),
            collected_at=data.get("collected_at"),
        )


@dataclass(frozen=True)
class EvidenceSet:
    """An unordered collection of evidence items E."""

    items: tuple[EvidenceItem, ...] = ()

    @classmethod
    def from_list(cls, data: list[Mapping[str, Any]]) -> "EvidenceSet":
        return cls(items=tuple(EvidenceItem.from_dict(d) for d in data))

    def __len__(self) -> int:
        return len(self.items)
