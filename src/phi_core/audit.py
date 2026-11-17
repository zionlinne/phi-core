"""Append-only JSONL audit log with a SHA-256 hash chain.

Each record stores the full input snapshot (T, S, raw E) plus the verifier
results, so a record can be replayed without the original files. The chain
detects edits, deletions, insertions and reordering *relative to a head hash
the verifier already trusts*. Without an external anchor (a head hash stored
somewhere the writer cannot modify), anyone able to rewrite the whole file can
recompute the entire chain; this log is tamper-evident, not tamper-proof.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import ZERO_HASH, hash_obj, safe_hash_obj
from .evidence import VerificationResult

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

EVALUATION_FIELDS = (
    "task_id", "contract_hash", "state_hash", "evidence_hash", "individual_constraint_results",
    "verdict", "reason_codes", "evaluator_version", "timestamp", "previous_record_hash", "record_hash",
)


class AuditError(RuntimeError):
    pass


def record_hash_of(record: Mapping[str, Any]) -> str:
    return hash_obj({k: v for k, v in record.items() if k != "record_hash"})


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        return [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(ln) for ln in self._read_lines()]

    def append(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Append ``body`` as a new chained record (seq/previous/record_hash are set here)."""
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a+", encoding="utf-8") as fh:
                if fcntl is not None:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.seek(0)
                    lines = [ln for ln in fh.read().splitlines() if ln.strip()]
                    if lines:
                        try:
                            last = json.loads(lines[-1])
                            prev, seq = last["record_hash"], last["seq"] + 1
                        except (ValueError, KeyError, TypeError) as exc:
                            raise AuditError("audit log tail is corrupt; refusing to extend") from exc
                    else:
                        prev, seq = ZERO_HASH, 0
                    record = copy.deepcopy(dict(body))
                    record["seq"] = seq
                    record["previous_record_hash"] = prev
                    record.pop("record_hash", None)
                    record["record_hash"] = record_hash_of(record)
                    fh.seek(0, os.SEEK_END)
                    fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                finally:
                    if fcntl is not None:
                        fcntl.flock(fh, fcntl.LOCK_UN)
        return record

    def append_evaluation(self, result, *, contract: Any, state: Any, evidence: Any, timestamp: str,
                          extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
        rd = result.to_dict()
        body = {
            "record_type": "phi_evaluation",
            "task_id": rd["task_id"],
            "checkpoint": rd["checkpoint"],
            "contract_hash": rd["contract_hash"],
            "state_hash": rd["state_hash"],
            "evidence_hash": rd["evidence_hash"],
            "individual_constraint_results": rd["constraint_results"],
            "soft_constraint_results": rd["soft_results"],
            "evidence_results": rd["evidence_results"],
            "verdict": rd["verdict"],
            "release": rd["release"],
            "reason_codes": rd["reason_codes"],
            "evaluator_version": rd["evaluator_version"],
            "timestamp": timestamp,
            "snapshot": {"contract": contract, "state": state, "evidence": evidence},
        }
        if extra:
            body["extra"] = dict(extra)
        return self.append(body)

    def append_acceptance(self, report: Mapping[str, Any], *, timestamp: str) -> dict[str, Any]:
        return self.append({"record_type": "acceptance", "timestamp": timestamp, "report": dict(report),
                            "status": report.get("status"), "baseline_hash": report.get("baseline_hash")})

    def verify(self, anchor: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return verify_chain(self._read_lines(), anchor=anchor)

    def head(self) -> dict[str, Any]:
        recs = self.records()
        if not recs:
            return {"seq": -1, "head_hash": ZERO_HASH}
        return {"seq": recs[-1]["seq"], "head_hash": recs[-1]["record_hash"]}


def verify_chain(lines: Iterable[str], anchor: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Check hashes, links, sequence and snapshot consistency. ``anchor`` =
    {"seq", "head_hash"} obtained out-of-band enables whole-chain-rewrite detection
    up to that point."""
    errors: list[dict[str, Any]] = []
    prev = ZERO_HASH
    count = 0
    hashes: dict[int, str] = {}
    for index, line in enumerate(lines):
        count += 1
        try:
            rec = json.loads(line)
        except ValueError:
            errors.append({"line": index, "code": "MALFORMED_LINE"})
            prev = None
            continue
        if not isinstance(rec, dict) or "record_hash" not in rec:
            errors.append({"line": index, "code": "MALFORMED_RECORD"})
            prev = None
            continue
        if record_hash_of(rec) != rec["record_hash"]:
            errors.append({"line": index, "code": "RECORD_HASH_MISMATCH"})
        if rec.get("seq") != index:
            errors.append({"line": index, "code": "SEQUENCE_GAP_OR_REORDER"})
        if prev is not None and rec.get("previous_record_hash") != prev:
            errors.append({"line": index, "code": "CHAIN_LINK_BROKEN"})
        if rec.get("record_type") == "phi_evaluation":
            missing = [f for f in EVALUATION_FIELDS if f not in rec]
            if missing:
                errors.append({"line": index, "code": "MISSING_FIELDS", "fields": missing})
            snap = rec.get("snapshot")
            if isinstance(snap, dict):
                c = snap.get("contract")
                c_hash = safe_hash_obj({k: v for k, v in c.items() if k != "integrity"} if isinstance(c, dict) else c)
                if c_hash != rec.get("contract_hash"):
                    errors.append({"line": index, "code": "SNAPSHOT_CONTRACT_HASH_MISMATCH"})
                if safe_hash_obj(snap.get("state")) != rec.get("state_hash"):
                    errors.append({"line": index, "code": "SNAPSHOT_STATE_HASH_MISMATCH"})
                if safe_hash_obj(snap.get("evidence")) != rec.get("evidence_hash"):
                    errors.append({"line": index, "code": "SNAPSHOT_EVIDENCE_HASH_MISMATCH"})
            else:
                errors.append({"line": index, "code": "SNAPSHOT_MISSING"})
        hashes[index] = rec["record_hash"]
        prev = rec["record_hash"]
    anchored = None
    if anchor is not None:
        anchored = hashes.get(anchor.get("seq")) == anchor.get("head_hash")
        if not anchored:
            errors.append({"line": anchor.get("seq"), "code": "EXTERNAL_ANCHOR_MISMATCH"})
    return {
        "ok": not errors,
        "records": count,
        "head_hash": prev if count else ZERO_HASH,
        "errors": errors,
        "externally_anchored": anchored,
        "note": "Without an external anchor a complete rewrite of the file cannot be detected.",
    }


def _compare(record: Mapping[str, Any], result) -> list[str]:
    rd = result.to_dict()
    diffs = []
    if rd["verdict"] != record.get("verdict"):
        diffs.append("verdict")
    if rd["reason_codes"] != record.get("reason_codes"):
        diffs.append("reason_codes")
    if rd["constraint_results"] != record.get("individual_constraint_results"):
        diffs.append("individual_constraint_results")
    for key in ("contract_hash", "state_hash", "evidence_hash"):
        if rd[key] != record.get(key):
            diffs.append(key)
    return diffs


def replay_record(record: Mapping[str, Any], engine=None, *, reverify: bool = False,
                  workspace: str | Path | None = None, trust_store=None) -> dict[str, Any]:
    """Re-run a recorded evaluation from its snapshot.

    Default: re-run the pure judgement on the recorded verifier results (exact
    historical replay). ``reverify=True``: re-run the Evidence Verifier against
    the current workspace too, which reveals artifacts changed since then."""
    from .evaluator import PhiEngine

    engine = engine or PhiEngine()
    snap = record["snapshot"]
    if reverify:
        result = engine.evaluate(snap["contract"], snap["state"], snap["evidence"],
                                 checkpoint=record["checkpoint"], workspace=workspace, trust_store=trust_store)
    else:
        vresults = [VerificationResult.from_dict(d) for d in record["evidence_results"]]
        result = engine.judge(snap["contract"], snap["state"], vresults, checkpoint=record["checkpoint"],
                              evidence_hash=record["evidence_hash"])
    diffs = _compare(record, result)
    return {
        "seq": record.get("seq"),
        "task_id": record.get("task_id"),
        "checkpoint": record.get("checkpoint"),
        "mode": "reverify" if reverify else "recorded-verification",
        "original_verdict": record.get("verdict"),
        "replayed_verdict": result.verdict.value,
        "original_evaluator_version": record.get("evaluator_version"),
        "replayed_evaluator_version": result.evaluator_version,
        "matches": not diffs,
        "differences": diffs,
    }


def replay_log(log: AuditLog, engine=None, **kw) -> list[dict[str, Any]]:
    return [replay_record(r, engine, **kw) for r in log.records() if r.get("record_type") == "phi_evaluation"]


def compare_versions(record: Mapping[str, Any], engine_a, engine_b) -> dict[str, Any]:
    a = replay_record(record, engine_a)
    b = replay_record(record, engine_b)
    return {"seq": record.get("seq"), "a": a, "b": b,
            "same_verdict": a["replayed_verdict"] == b["replayed_verdict"]}


def trace_evidence(records: Iterable[Mapping[str, Any]], evidence_id: str) -> list[dict[str, Any]]:
    out = []
    for rec in records:
        if rec.get("record_type") != "phi_evaluation":
            continue
        raw = rec.get("snapshot", {}).get("evidence")
        raw_items = [e for e in raw if isinstance(e, dict) and e.get("evidence_id") == evidence_id] if isinstance(raw, list) else []
        results = [r for r in rec.get("evidence_results", []) if r.get("evidence_id") == evidence_id]
        if not raw_items and not results:
            continue
        used_by = [c["constraint_id"] for c in rec.get("individual_constraint_results", [])
                   if evidence_id in c.get("evidence_refs", [])]
        out.append({
            "seq": rec.get("seq"), "task_id": rec.get("task_id"), "checkpoint": rec.get("checkpoint"),
            "timestamp": rec.get("timestamp"), "verdict": rec.get("verdict"),
            "claims": raw_items, "verification": results, "referenced_by_constraints": used_by,
        })
    return out


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict) and obj:
        out = {}
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}/{k}" if prefix else str(k)))
        return out
    return {prefix: obj}


def reconstruct_state_history(records: Iterable[Mapping[str, Any]], task_id: str | None = None) -> list[dict[str, Any]]:
    history = []
    previous: dict[str, Any] | None = None
    for rec in records:
        if rec.get("record_type") != "phi_evaluation":
            continue
        if task_id is not None and rec.get("task_id") != task_id:
            continue
        state = rec.get("snapshot", {}).get("state")
        flat = _flatten(state) if isinstance(state, dict) else {"": state}
        changes = []
        if previous is not None:
            for key in sorted(set(previous) | set(flat)):
                if previous.get(key, "<absent>") != flat.get(key, "<absent>"):
                    changes.append({"path": key, "before": previous.get(key, "<absent>"),
                                    "after": flat.get(key, "<absent>")})
        history.append({"seq": rec.get("seq"), "timestamp": rec.get("timestamp"),
                        "checkpoint": rec.get("checkpoint"), "task_id": rec.get("task_id"),
                        "state_hash": rec.get("state_hash"), "state": state, "changes": changes})
        previous = flat
    return history
