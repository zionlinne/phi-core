"""Independent final-delivery Acceptance gate: PASS / FAIL / INCONCLUSIVE.

Strictly separate from Phi: this module never imports or consults the
feasibility engine, and a Phi TRUE has no influence here.

Trust model:
* Requirements come only from the frozen baseline. Its canonical hash must
  equal the current revision in an *anchor* that the acceptance authority keeps
  where the producer cannot write (optionally HMAC-signed by an authority key).
  Recomputing the baseline hash does not help a producer: the anchor, not the
  baseline file, is the reference.
* Only keys provisioned with the ``baseline-anchor`` purpose can sign anchor
  entries; evidence keys cannot, whatever their ``sources``. Once a revision is
  signed, later unsigned revisions are rejected.
* Criteria that live in the workspace (JSON Schemas, scripts, configs) count
  only when their bytes are frozen in the baseline (``schema_sha256`` /
  ``schema_refs`` / ``pinned_files``). Schemas never trigger network or
  ``file://`` retrieval.
* Delivery evidence counts only when its signed ``binding`` names this
  baseline.
* Producer claims (``claimed_status``, extra criteria fields) are recorded and
  ignored.
* Anything that cannot be verified is INCONCLUSIVE, never PASS. ``manual`` and
  ``llm_judgment`` requirements cannot reach PASS on their own.
"""

from __future__ import annotations

import copy
import hmac
import json
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_json, hash_obj, parse_time, resolve_in_workspace, sha256_file
from .command import run_command
from .evidence import (
    PURPOSE_BASELINE_ANCHOR,
    TrustStore,
    VerificationContext,
    VerifierRegistry,
    VStatus,
    default_verifier_registry,
    hmac_hex,
    verify_evidence,
)
from .safeschema import check_document, pin_issue
from .schemas import schema_errors

ACCEPTANCE_VERSION = "phi-core-acceptance/1.0.2"
DEFAULT_EVIDENCE_MAX_AGE = 86400
_DELIVERY_KNOWN_FIELDS = {"delivery_version", "baseline_id", "baseline_revision", "produced_by",
                          "claimed_status", "trace", "evidence"}


class AStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


def baseline_hash(baseline: Mapping[str, Any]) -> str:
    return hash_obj(baseline)


def anchor_signing_payload(baseline_id: str, entry: Mapping[str, Any]) -> bytes:
    return canonical_json({
        "baseline_id": baseline_id,
        **{k: entry.get(k) for k in ("revision", "baseline_hash", "previous_revision_hash",
                                     "anchored_by", "anchored_at")},
    }).encode("utf-8")


def make_anchor_entry(baseline: Mapping[str, Any], *, anchored_by: str, anchored_at: str,
                      key_id: str | None = None, secret: bytes | None = None) -> dict[str, Any]:
    entry = {
        "revision": baseline["revision"],
        "baseline_hash": baseline_hash(baseline),
        "previous_revision_hash": baseline["previous_revision_hash"],
        "anchored_by": anchored_by,
        "anchored_at": anchored_at,
    }
    if key_id is not None and secret is not None:
        entry["key_id"] = key_id
        entry["signature"] = hmac_hex(secret, anchor_signing_payload(baseline["baseline_id"], entry))
    return entry


def new_revision(old: Mapping[str, Any], *, requirements: list, summary: str, frozen_at: str,
                 design: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Create the next baseline revision, recording added/removed/modified requirement ids."""
    old_reqs = {r["requirement_id"]: r for r in old["requirements"]}
    new_reqs = {r["requirement_id"]: r for r in requirements}
    entry = {
        "revision": old["revision"] + 1,
        "summary": summary,
        "added": sorted(set(new_reqs) - set(old_reqs)),
        "removed": sorted(set(old_reqs) - set(new_reqs)),
        "modified": sorted(k for k in set(old_reqs) & set(new_reqs) if old_reqs[k] != new_reqs[k]),
    }
    out = copy.deepcopy(dict(old))
    out.update({
        "revision": old["revision"] + 1,
        "previous_revision_hash": baseline_hash(old),
        "frozen_at": frozen_at,
        "requirements": copy.deepcopy(requirements),
        "change_log": list(copy.deepcopy(old["change_log"])) + [entry],
    })
    if design is not None:
        out["design"] = copy.deepcopy(dict(design))
    return out


class _Ctx:
    def __init__(self, workspace: Path, now, trust_store, verifiers, command_env, delivery_evidence,
                 baseline_id=None, baseline_revision=None):
        self.baseline_id = baseline_id
        self.baseline_revision = baseline_revision
        self.requirement_id = None
        self.workspace = workspace
        self.now = now
        self.trust_store = trust_store
        self.verifiers = verifiers
        self.command_env = command_env
        self._evidence_raw = delivery_evidence
        self._vresults = None

    def vresults(self):
        if self._vresults is None:
            ctx = VerificationContext(now=self.now, workspace=self.workspace, trust_store=self.trust_store)
            self._vresults = verify_evidence(copy.deepcopy(self._evidence_raw), ctx, self.verifiers)
        return self._vresults


def _check_file(spec, ctx):
    target = resolve_in_workspace(ctx.workspace, spec["path"])
    if target is None:
        return AStatus.FAIL, ["PATH_OUTSIDE_WORKSPACE"], {}
    if not target.is_file():
        return AStatus.FAIL, ["FILE_MISSING"], {}
    actual = sha256_file(target)
    if "sha256" in spec and spec["sha256"] != actual:
        return AStatus.FAIL, ["FILE_HASH_MISMATCH"], {"sha256": actual}
    return AStatus.PASS, ["FILE_VERIFIED"], {"sha256": actual}


def _check_command(spec, ctx):
    """Frozen-criterion command protocol (see :mod:`phi_core.command`): the argv
    text is frozen by the baseline hash, workspace programs and criteria must be
    pinned, and the command runs against a snapshot holding the verified bytes."""
    status, codes, detail = run_command(spec, ctx.workspace, ctx.command_env)
    return AStatus(status), codes, detail


def _check_json_schema(spec, ctx):
    target = resolve_in_workspace(ctx.workspace, spec["path"])
    if target is None or resolve_in_workspace(ctx.workspace, spec["schema_path"]) is None:
        return AStatus.FAIL, ["PATH_OUTSIDE_WORKSPACE"], {}
    if not target.is_file():
        return AStatus.FAIL, ["FILE_MISSING"], {}
    try:
        doc = json.loads(target.read_text(encoding="utf-8"))
    except ValueError:
        return AStatus.FAIL, ["OUTPUT_NOT_JSON"], {}
    check = check_document(ctx.workspace, spec["schema_path"], doc)
    detail = {"schema_closure": dict(check.closure)}
    if check.code is not None:
        return AStatus.INCONCLUSIVE, [check.code], detail
    issue = pin_issue(check.closure, spec["schema_path"], spec.get("schema_sha256"), spec.get("schema_refs"))
    if issue is not None:
        kind, code = issue
        return (AStatus.FAIL if kind == "violated" else AStatus.INCONCLUSIVE), [code], detail
    if not check.valid:
        return AStatus.FAIL, ["SCHEMA_INCOMPATIBLE"], {**detail, "errors": list(check.errors)}
    return AStatus.PASS, ["SCHEMA_COMPATIBLE"], detail


def _check_evidence(spec, ctx):
    allowed = spec.get("verifiers", ["hmac_attestation"])
    max_age = spec.get("max_age_seconds", DEFAULT_EVIDENCE_MAX_AGE)
    reasons, usable = set(), []
    for r in ctx.vresults():
        if r.constraint_id != spec["evidence_constraint_id"]:
            continue
        if r.status is not VStatus.VERIFIED:
            reasons.add(f"EVIDENCE_{r.status.value}")
            reasons.update(r.reason_codes)
            continue
        binding = r.binding if isinstance(r.binding, Mapping) else {}
        if "baseline_id" not in binding:
            reasons.add("EVIDENCE_NOT_BOUND_TO_BASELINE")
            continue
        if binding["baseline_id"] != ctx.baseline_id:
            reasons.add("EVIDENCE_BOUND_TO_OTHER_BASELINE")
            continue
        if "baseline_revision" in binding and binding["baseline_revision"] != ctx.baseline_revision:
            reasons.add("EVIDENCE_BOUND_TO_OTHER_REVISION")
            continue
        if "requirement_id" in binding and binding["requirement_id"] != ctx.requirement_id:
            reasons.add("EVIDENCE_BOUND_TO_OTHER_REQUIREMENT")
            continue
        if r.verifier_id not in allowed:
            reasons.add("EVIDENCE_VERIFIER_NOT_ALLOWED")
            continue
        if (ctx.now - parse_time(r.timestamp)).total_seconds() > max_age:
            reasons.add("EVIDENCE_STALE")
            continue
        usable.append(r)
    if not usable:
        return AStatus.INCONCLUSIVE, ["EVIDENCE_MISSING", *sorted(reasons)], {}
    values = {canonical_json(r.observed) for r in usable}
    refs = sorted(r.evidence_id for r in usable)
    if len(values) > 1:
        return AStatus.INCONCLUSIVE, ["EVIDENCE_CONFLICT"], {"evidence_refs": refs}
    if usable[0].observed == spec["expected"]:
        return AStatus.PASS, ["EVIDENCE_VALUE_AS_EXPECTED"], {"evidence_refs": refs}
    return AStatus.FAIL, ["EVIDENCE_VALUE_MISMATCH"], {"evidence_refs": refs}


_METHODS = {"file": _check_file, "command": _check_command, "json_schema": _check_json_schema,
            "evidence": _check_evidence}


def _verify_anchor(baseline, anchor, b_hash, trust_store, require_signed):
    """Return (fail_codes, inconclusive_codes, current_entry)."""
    fails, incs = [], []
    if anchor is None:
        return fails, ["NO_TRUSTED_ANCHOR"], None
    if schema_errors("anchor", anchor):
        return fails, ["ANCHOR_SCHEMA_INVALID"], None
    if anchor["baseline_id"] != baseline["baseline_id"]:
        return ["BASELINE_ID_MISMATCH"], incs, None
    revs = sorted(anchor["revisions"], key=lambda e: e["revision"])
    numbers = [e["revision"] for e in revs]
    if len(numbers) != len(set(numbers)):
        return fails, ["ANCHOR_CHAIN_INVALID"], None
    for prev, cur in zip(revs, revs[1:]):
        if cur["revision"] != prev["revision"] + 1 or cur["previous_revision_hash"] != prev["baseline_hash"]:
            return fails, ["ANCHOR_CHAIN_INVALID"], None
    signed_seen = False
    for e in revs:
        if "signature" not in e and "key_id" not in e:
            if signed_seen:
                fails.append("ANCHOR_UNSIGNED_REVISION_AFTER_SIGNED")
            continue
        signed_seen = True
        key = trust_store.keys.get(e.get("key_id")) if trust_store else None
        if key is None:
            incs.append("ANCHOR_KEY_UNKNOWN")
        elif not hmac.compare_digest(
                hmac_hex(key.secret, anchor_signing_payload(anchor["baseline_id"], e)), e.get("signature", "")):
            fails.append("ANCHOR_SIGNATURE_INVALID")
        elif PURPOSE_BASELINE_ANCHOR not in key.purposes:
            fails.append("ANCHOR_KEY_NOT_AUTHORIZED_FOR_BASELINE")
    current = revs[-1]
    if require_signed and "signature" not in current:
        incs.append("ANCHOR_UNSIGNED")
    if baseline["revision"] != current["revision"]:
        fails.append("BASELINE_REVISION_SUPERSEDED" if baseline["revision"] in numbers
                     else "BASELINE_REVISION_NOT_ANCHORED")
    elif b_hash != current["baseline_hash"]:
        fails.append("BASELINE_HASH_MISMATCH")
    return fails, incs, current


def run_acceptance(baseline: Any, anchor: Any, delivery: Any, *, workspace: str | Path, now: str,
                   trust_store: TrustStore | None = None, require_signed_anchor: bool = False,
                   verifiers: VerifierRegistry | None = None,
                   command_env: Mapping[str, str] | None = None) -> dict[str, Any]:
    ws = Path(workspace)
    now_dt = parse_time(now)
    trust_store = trust_store or TrustStore()
    baseline, anchor, delivery = copy.deepcopy(baseline), copy.deepcopy(anchor), copy.deepcopy(delivery)
    report: dict[str, Any] = {
        "report_version": "1.0",
        "gate": "ACCEPTANCE",
        "acceptance_version": ACCEPTANCE_VERSION,
        "independent_of_phi": True,
        "phi_verdict_consulted": False,
        "evaluated_at": now,
        "baseline_id": baseline.get("baseline_id") if isinstance(baseline, dict) else None,
        "baseline_revision": baseline.get("revision") if isinstance(baseline, dict) else None,
        "baseline_hash": None,
        "anchor_entry": None,
        "global_reason_codes": [],
        "requirement_results": [],
        "untraced_delivery_entries": [],
        "ignored_producer_fields": [],
        "producer_claimed_status": delivery.get("claimed_status") if isinstance(delivery, dict) else None,
        "design_deviation": None,
    }
    fails: list[str] = []
    incs: list[str] = []

    def finish():
        statuses = [r["status"] for r in report["requirement_results"]]
        if fails or "FAIL" in statuses:
            status = AStatus.FAIL
        elif incs or "INCONCLUSIVE" in statuses or not statuses:
            status = AStatus.INCONCLUSIVE
        else:
            status = AStatus.PASS
        if not statuses and not fails:
            incs.append("NO_REQUIREMENTS_EVALUATED")
        report["global_reason_codes"] = sorted(set(fails) | set(incs))
        report["status"] = status.value
        return report

    if not isinstance(baseline, dict) or schema_errors("baseline", baseline):
        incs.append("BASELINE_SCHEMA_INVALID")
        return finish()
    b_hash = baseline_hash(baseline)
    report["baseline_hash"] = b_hash
    a_fails, a_incs, current = _verify_anchor(baseline, anchor, b_hash, trust_store, require_signed_anchor)
    fails += a_fails
    incs += a_incs
    report["anchor_entry"] = current
    req_ids = [r["requirement_id"] for r in baseline["requirements"]]
    if len(req_ids) != len(set(req_ids)):
        incs.append("BASELINE_DUPLICATE_REQUIREMENT_ID")
    if fails or a_incs:
        report["design_deviation"] = {"note": "baseline not trusted; requirements not evaluated"}
        return finish()

    design = baseline["design"]
    dpath = resolve_in_workspace(ws, design["path"])
    if dpath is None or not dpath.is_file():
        incs.append("DESIGN_DOCUMENT_MISSING")
    elif sha256_file(dpath) != design["sha256"]:
        fails.append("DESIGN_DOCUMENT_MODIFIED")

    trace: dict[str, dict] = {}
    delivery_evidence: list = []
    if not isinstance(delivery, dict) or schema_errors("delivery", delivery):
        incs.append("DELIVERY_SCHEMA_INVALID")
    else:
        if delivery["baseline_id"] != baseline["baseline_id"] or delivery["baseline_revision"] != baseline["revision"]:
            fails.append("DELIVERY_BASELINE_MISMATCH")
        for entry in delivery["trace"]:
            trace.setdefault(entry["requirement_id"], entry)
        delivery_evidence = delivery.get("evidence", [])
        ignored = sorted(set(delivery) - _DELIVERY_KNOWN_FIELDS)
        report["ignored_producer_fields"] = ignored
        report["untraced_delivery_entries"] = sorted(set(trace) - set(req_ids))

    ctx = _Ctx(ws, now_dt, trust_store, verifiers or default_verifier_registry(), command_env, delivery_evidence,
               baseline["baseline_id"], baseline["revision"])
    for req in baseline["requirements"]:
        ctx.requirement_id = req["requirement_id"]
        spec = req["verification"]
        method = spec["method"]
        if method == "manual":
            status, codes, detail = AStatus.INCONCLUSIVE, ["MANUAL_VERIFICATION_NOT_AUTOMATABLE"], {}
        elif method == "llm_judgment":
            status, codes, detail = AStatus.INCONCLUSIVE, ["LLM_JUDGMENT_CANNOT_DECIDE_PASS"], {}
        else:
            try:
                status, codes, detail = _METHODS[method](spec, ctx)
            except Exception as exc:  # noqa: BLE001 - a crashing check is never PASS and never escapes
                status, codes, detail = AStatus.INCONCLUSIVE, ["VERIFICATION_ERROR"], {"error": type(exc).__name__}
        codes = list(codes)
        if req["requirement_id"] not in trace:
            status = AStatus.FAIL
            codes.append("TRACE_MISSING_OMITTED_REQUIREMENT")
        report["requirement_results"].append({
            "requirement_id": req["requirement_id"],
            "text": req["text"],
            "design_ref": req.get("design_ref"),
            "method": method,
            "delivered_artifacts": trace.get(req["requirement_id"], {}).get("artifacts", []),
            "status": status.value,
            "reason_codes": codes,
            "detail": detail,
        })

    n = len(baseline["requirements"])
    deviated = sum(1 for r in report["requirement_results"] if r["status"] == "FAIL")
    unknown = sum(1 for r in report["requirement_results"] if r["status"] == "INCONCLUSIVE")
    report["design_deviation"] = {
        "definition": "DDR = FAIL requirements / all requirements of the anchored baseline revision; "
                      "INCONCLUSIVE requirements are reported separately and bound the upper rate.",
        "denominator": n,
        "deviated": deviated,
        "unknown": unknown,
        "rate_lower": (deviated / n) if n else None,
        "rate_upper": ((deviated + unknown) / n) if n else None,
        "design_document_modified": "DESIGN_DOCUMENT_MODIFIED" in fails,
    }
    return finish()
