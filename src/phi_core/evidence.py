"""Evidence model and the independent Evidence Verifier.

Trust rules enforced here:

* The caller's ``verification_status`` is recorded as ``claimed_status`` and
  never used. Only a registered verifier decides VERIFIED / REJECTED /
  UNVERIFIABLE.
* Evidence whose ``verifier_id`` has no registered verifier is UNVERIFIABLE.
* ``file_sha256`` / ``json_schema`` re-observe the workspace themselves; the
  caller's hash or claimed result is only compared, never trusted.
* ``hmac_attestation`` accepts a claim only if it carries a valid HMAC-SHA256
  signature by a key held in the host's TrustStore and the key is authorised
  for the claimed ``source``. This proves possession of a shared secret, not
  human authorship, and cannot stop anyone who holds the key (or controls the
  host) from producing a valid-looking claim.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from jsonschema import Draft202012Validator

from .canonical import canonical_json, format_time, parse_time, sha256_file
from .schemas import schema_errors

EVIDENCE_FIELDS = (
    "evidence_id", "constraint_id", "source", "verifier_id", "observed_value",
    "verification_status", "timestamp", "artifact_hash", "provenance",
)


class EvidenceFormatError(ValueError):
    pass


class VStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    constraint_id: str
    source: str
    verifier_id: str
    observed_value: Any
    verification_status: str
    timestamp: str
    artifact_hash: str | None
    provenance: Mapping[str, Any]

    @classmethod
    def from_dict(cls, data: Any) -> "EvidenceItem":
        if not isinstance(data, Mapping):
            raise EvidenceFormatError("evidence item must be an object")
        missing = [k for k in EVIDENCE_FIELDS if k not in data]
        if missing:
            raise EvidenceFormatError(f"evidence item missing required field(s): {', '.join(missing)}")
        errors = schema_errors("evidence", dict(data))
        if errors:
            raise EvidenceFormatError("; ".join(errors))
        return cls(**{k: copy.deepcopy(data[k]) for k in EVIDENCE_FIELDS})

    def to_dict(self) -> dict[str, Any]:
        return {k: copy.deepcopy(getattr(self, k)) for k in EVIDENCE_FIELDS}


@dataclass(frozen=True)
class VerificationResult:
    evidence_id: str
    constraint_id: str | None
    source: str | None
    verifier_id: str | None
    status: VStatus
    reason_codes: tuple[str, ...]
    observed: Any
    timestamp: str | None
    claimed_status: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "constraint_id": self.constraint_id,
            "source": self.source,
            "verifier_id": self.verifier_id,
            "status": self.status.value,
            "reason_codes": list(self.reason_codes),
            "observed": copy.deepcopy(self.observed),
            "timestamp": self.timestamp,
            "claimed_status": copy.deepcopy(self.claimed_status),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "VerificationResult":
        return cls(
            evidence_id=d["evidence_id"], constraint_id=d.get("constraint_id"), source=d.get("source"),
            verifier_id=d.get("verifier_id"), status=VStatus(d["status"]),
            reason_codes=tuple(d.get("reason_codes", ())), observed=copy.deepcopy(d.get("observed")),
            timestamp=d.get("timestamp"), claimed_status=copy.deepcopy(d.get("claimed_status")),
        )


def _result(item: EvidenceItem, status: VStatus, *codes: str, observed: Any = None) -> VerificationResult:
    return VerificationResult(
        evidence_id=item.evidence_id, constraint_id=item.constraint_id, source=item.source,
        verifier_id=item.verifier_id, status=status, reason_codes=tuple(codes),
        observed=observed if status is VStatus.VERIFIED else None,
        timestamp=item.timestamp, claimed_status=item.verification_status,
    )


# --------------------------------------------------------------------------- trust store


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    secret: bytes
    sources: frozenset[str]


@dataclass
class TrustStore:
    """Host-provisioned HMAC keys. Keys must reach the host out-of-band, never via evidence."""

    keys: dict[str, TrustedKey] = field(default_factory=dict)

    def add_key(self, key_id: str, secret: bytes, sources: Iterable[str]) -> None:
        if len(secret) < 16:
            raise ValueError("HMAC secret must be at least 16 bytes")
        self.keys[key_id] = TrustedKey(key_id, bytes(secret), frozenset(sources))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TrustStore":
        store = cls()
        for key_id, spec in data.get("keys", {}).items():
            store.add_key(key_id, bytes.fromhex(spec["secret_hex"]), spec.get("sources", []))
        return store

    @classmethod
    def load(cls, path: str | Path) -> "TrustStore":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def signing_payload(item: Mapping[str, Any]) -> bytes:
    """Bytes covered by an evidence signature: every field except the caller's
    claimed ``verification_status`` and ``provenance.signature`` itself."""
    body = {k: v for k, v in item.items() if k != "verification_status"}
    prov = dict(body.get("provenance") or {})
    prov.pop("signature", None)
    body["provenance"] = prov
    return canonical_json(body).encode("utf-8")


def hmac_hex(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def sign_evidence(item: Mapping[str, Any], key_id: str, secret: bytes) -> dict[str, Any]:
    out = copy.deepcopy(dict(item))
    prov = dict(out.get("provenance") or {})
    prov["key_id"] = key_id
    prov.pop("signature", None)
    out["provenance"] = prov
    prov["signature"] = hmac_hex(secret, signing_payload(out))
    return out


# --------------------------------------------------------------------------- verifiers


@dataclass(frozen=True)
class VerificationContext:
    now: datetime | None
    workspace: Path | None = None
    trust_store: TrustStore = field(default_factory=TrustStore)


class Verifier(Protocol):
    verifier_id: str

    def verify(self, item: EvidenceItem, ctx: VerificationContext) -> VerificationResult: ...


def resolve_in_workspace(workspace: Path, rel: Any) -> Path | None:
    """Resolve ``rel`` under ``workspace``; None if it is not a safe relative path inside it."""
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or "\x00" in rel:
        return None
    root = workspace.resolve()
    target = (root / rel).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


class FileSha256Verifier:
    """Re-observes a workspace file. observed_value: {"path": str, optional "sha256"/"exists"}."""

    verifier_id = "file_sha256"

    def verify(self, item, ctx):
        ov = item.observed_value
        if not isinstance(ov, Mapping) or not isinstance(ov.get("path"), str):
            return _result(item, VStatus.REJECTED, "OBSERVED_VALUE_MALFORMED")
        if ctx.workspace is None:
            return _result(item, VStatus.UNVERIFIABLE, "NO_WORKSPACE")
        target = resolve_in_workspace(ctx.workspace, ov["path"])
        if target is None:
            return _result(item, VStatus.REJECTED, "PATH_OUTSIDE_WORKSPACE")
        claimed = [h for h in (item.artifact_hash, ov.get("sha256")) if h is not None]
        if not target.is_file():
            if claimed or ov.get("exists") is True:
                return _result(item, VStatus.REJECTED, "CLAIM_CONTRADICTS_OBSERVATION")
            return _result(item, VStatus.VERIFIED, observed={"path": ov["path"], "exists": False})
        actual = sha256_file(target)
        if any(h != actual for h in claimed):
            return _result(item, VStatus.REJECTED, "ARTIFACT_HASH_MISMATCH")
        if ov.get("exists") is False:
            return _result(item, VStatus.REJECTED, "CLAIM_CONTRADICTS_OBSERVATION")
        return _result(item, VStatus.VERIFIED, observed={"path": ov["path"], "exists": True, "sha256": actual})


class JsonSchemaVerifier:
    """Re-validates a workspace JSON file against a workspace JSON Schema.
    observed_value: {"path", "schema_path", optional claimed "valid"}."""

    verifier_id = "json_schema"

    def verify(self, item, ctx):
        ov = item.observed_value
        if not isinstance(ov, Mapping) or not isinstance(ov.get("path"), str) or not isinstance(ov.get("schema_path"), str):
            return _result(item, VStatus.REJECTED, "OBSERVED_VALUE_MALFORMED")
        if ctx.workspace is None:
            return _result(item, VStatus.UNVERIFIABLE, "NO_WORKSPACE")
        target = resolve_in_workspace(ctx.workspace, ov["path"])
        schema_path = resolve_in_workspace(ctx.workspace, ov["schema_path"])
        if target is None or schema_path is None:
            return _result(item, VStatus.REJECTED, "PATH_OUTSIDE_WORKSPACE")
        base = {"path": ov["path"], "schema_path": ov["schema_path"]}
        if not schema_path.is_file():
            return _result(item, VStatus.UNVERIFIABLE, "SCHEMA_FILE_MISSING")
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except (ValueError, Exception):  # noqa: BLE001 - any schema problem is unverifiable
            return _result(item, VStatus.UNVERIFIABLE, "SCHEMA_FILE_INVALID")
        if not target.is_file():
            if ov.get("valid") is True:
                return _result(item, VStatus.REJECTED, "CLAIM_CONTRADICTS_OBSERVATION")
            return _result(item, VStatus.VERIFIED, observed={**base, "exists": False, "valid": False})
        actual_hash = sha256_file(target)
        if item.artifact_hash is not None and item.artifact_hash != actual_hash:
            return _result(item, VStatus.REJECTED, "ARTIFACT_HASH_MISMATCH")
        try:
            doc = json.loads(target.read_text(encoding="utf-8"))
            valid = not any(True for _ in Draft202012Validator(schema).iter_errors(doc))
        except ValueError:
            valid = False
        if "valid" in ov and ov["valid"] is not valid:
            return _result(item, VStatus.REJECTED, "CLAIM_CONTRADICTS_OBSERVATION")
        return _result(item, VStatus.VERIFIED, observed={**base, "exists": True, "valid": valid, "sha256": actual_hash})


class HmacAttestationVerifier:
    """Accepts ``observed_value`` only with a valid signature from a trusted, source-authorised key.
    Optional provenance.artifact_path is re-hashed against artifact_hash."""

    verifier_id = "hmac_attestation"

    def verify(self, item, ctx):
        prov = item.provenance
        key_id, signature = prov.get("key_id"), prov.get("signature")
        if not isinstance(key_id, str) or not isinstance(signature, str):
            return _result(item, VStatus.UNVERIFIABLE, "SIGNATURE_MISSING")
        key = ctx.trust_store.keys.get(key_id)
        if key is None:
            return _result(item, VStatus.UNVERIFIABLE, "UNKNOWN_SIGNING_KEY")
        if item.source not in key.sources:
            return _result(item, VStatus.REJECTED, "SOURCE_NOT_AUTHORIZED_FOR_KEY")
        expected = hmac_hex(key.secret, signing_payload(item.to_dict()))
        if not hmac.compare_digest(expected, signature):
            return _result(item, VStatus.REJECTED, "SIGNATURE_INVALID")
        artifact_path = prov.get("artifact_path")
        if artifact_path is not None:
            if item.artifact_hash is None:
                return _result(item, VStatus.REJECTED, "ARTIFACT_HASH_MISSING")
            if ctx.workspace is None:
                return _result(item, VStatus.UNVERIFIABLE, "NO_WORKSPACE")
            target = resolve_in_workspace(ctx.workspace, artifact_path)
            if target is None:
                return _result(item, VStatus.REJECTED, "PATH_OUTSIDE_WORKSPACE")
            if not target.is_file() or sha256_file(target) != item.artifact_hash:
                return _result(item, VStatus.REJECTED, "ARTIFACT_HASH_MISMATCH")
        return _result(item, VStatus.VERIFIED, observed=copy.deepcopy(item.observed_value))


class VerifierRegistry:
    def __init__(self) -> None:
        self._verifiers: dict[str, Verifier] = {}

    def register(self, verifier: Verifier, *, replace: bool = False) -> None:
        vid = getattr(verifier, "verifier_id", None)
        if not isinstance(vid, str) or not vid:
            raise ValueError("verifier must define a non-empty verifier_id")
        if not callable(getattr(verifier, "verify", None)):
            raise TypeError("verifier must define verify(item, ctx)")
        if vid in self._verifiers and not replace:
            raise ValueError(f"verifier {vid!r} already registered")
        self._verifiers[vid] = verifier

    def get(self, verifier_id: str) -> Verifier | None:
        return self._verifiers.get(verifier_id)

    def names(self) -> list[str]:
        return sorted(self._verifiers)

    def copy(self) -> "VerifierRegistry":
        new = VerifierRegistry()
        new._verifiers = dict(self._verifiers)
        return new


def default_verifier_registry() -> VerifierRegistry:
    reg = VerifierRegistry()
    reg.register(FileSha256Verifier())
    reg.register(JsonSchemaVerifier())
    reg.register(HmacAttestationVerifier())
    return reg


def _raw_id(raw: Any, index: int) -> str:
    if isinstance(raw, Mapping) and isinstance(raw.get("evidence_id"), str) and raw["evidence_id"]:
        return raw["evidence_id"]
    return f"#{index}"


def _bare(raw: Any, index: int, status: VStatus, *codes: str) -> VerificationResult:
    m = raw if isinstance(raw, Mapping) else {}
    s = lambda k: m.get(k) if isinstance(m.get(k), str) else None  # noqa: E731
    return VerificationResult(
        evidence_id=_raw_id(raw, index), constraint_id=s("constraint_id"), source=s("source"),
        verifier_id=s("verifier_id"), status=status, reason_codes=tuple(codes), observed=None,
        timestamp=s("timestamp"), claimed_status=copy.deepcopy(m.get("verification_status")),
    )


def verify_evidence(raw_items: Any, ctx: VerificationContext,
                    registry: VerifierRegistry | None = None) -> list[VerificationResult]:
    """Verify every raw evidence claim independently. Never raises for bad input."""
    registry = registry or default_verifier_registry()
    if not isinstance(raw_items, list):
        return [_bare(raw_items, 0, VStatus.REJECTED, "EVIDENCE_PAYLOAD_NOT_A_LIST")]
    ids = [_raw_id(r, i) for i, r in enumerate(raw_items)]
    results = []
    for index, raw in enumerate(raw_items):
        if ids.count(ids[index]) > 1:
            results.append(_bare(raw, index, VStatus.REJECTED, "DUPLICATE_EVIDENCE_ID"))
            continue
        try:
            item = EvidenceItem.from_dict(raw)
        except EvidenceFormatError:
            results.append(_bare(raw, index, VStatus.REJECTED, "MALFORMED_EVIDENCE"))
            continue
        if ctx.now is None:
            results.append(_result(item, VStatus.UNVERIFIABLE, "NO_TRUSTED_TIME"))
            continue
        if parse_time(item.timestamp) > ctx.now:
            results.append(_result(item, VStatus.REJECTED, "TIMESTAMP_IN_FUTURE"))
            continue
        verifier = registry.get(item.verifier_id)
        if verifier is None:
            results.append(_result(item, VStatus.UNVERIFIABLE, "NO_REGISTERED_VERIFIER"))
            continue
        try:
            res = verifier.verify(item, ctx)
        except Exception:  # noqa: BLE001 - a crashing verifier must not yield trust
            results.append(_result(item, VStatus.UNVERIFIABLE, "VERIFIER_ERROR"))
            continue
        if not isinstance(res, VerificationResult) or res.evidence_id != item.evidence_id:
            results.append(_result(item, VStatus.UNVERIFIABLE, "VERIFIER_RESULT_INVALID"))
            continue
        results.append(res)
    return results


# --------------------------------------------------------------------------- collector


def observe_files(contract: Mapping[str, Any], workspace: str | Path, now: str,
                  source: str = "local-observer") -> list[dict[str, Any]]:
    """Host-side collector: produce file/schema evidence claims for a v1.0 contract's
    file constraints by observing ``workspace`` at time ``now``. The verifier will
    re-observe; these claims carry no trust of their own."""
    from .contracts import compile_constraints

    ws = Path(workspace)
    items = []
    for c in compile_constraints(contract):
        if c.predicate_type in ("input_exists", "output_exists", "file_hash"):
            path = c.params["path"]
            target = resolve_in_workspace(ws, path)
            digest = sha256_file(target) if target is not None and target.is_file() else None
            items.append({
                "evidence_id": f"obs:{c.constraint_id}@{now}",
                "constraint_id": c.constraint_id,
                "source": source,
                "verifier_id": "file_sha256",
                "observed_value": {"path": path},
                "verification_status": "CLAIMED",
                "timestamp": now,
                "artifact_hash": digest,
                "provenance": {"collector": "phi_core.evidence.observe_files"},
            })
        elif c.predicate_type == "schema_compatible":
            items.append({
                "evidence_id": f"obs:{c.constraint_id}@{now}",
                "constraint_id": c.constraint_id,
                "source": source,
                "verifier_id": "json_schema",
                "observed_value": {"path": c.params["path"], "schema_path": c.params["schema_path"]},
                "verification_status": "CLAIMED",
                "timestamp": now,
                "artifact_hash": None,
                "provenance": {"collector": "phi_core.evidence.observe_files"},
            })
    return items


def make_evidence(evidence_id: str, constraint_id: str, *, source: str, verifier_id: str,
                  observed_value: Any, timestamp: datetime | str, artifact_hash: str | None = None,
                  provenance: Mapping[str, Any] | None = None,
                  verification_status: str = "CLAIMED") -> dict[str, Any]:
    ts = timestamp if isinstance(timestamp, str) else format_time(timestamp)
    return {
        "evidence_id": evidence_id, "constraint_id": constraint_id, "source": source,
        "verifier_id": verifier_id, "observed_value": observed_value,
        "verification_status": verification_status, "timestamp": ts,
        "artifact_hash": artifact_hash, "provenance": dict(provenance or {}),
    }
