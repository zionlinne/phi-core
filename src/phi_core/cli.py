"""Command-line interface ``phi``.

Exit codes:
  0   validate: structurally valid | evaluate/plan: TRUE | accept: PASS | audit: ok
  1   validate: structurally invalid | audit verify/replay: problems found
  2   usage error / unreadable file / malformed JSON
  10  evaluate/plan/gate-exec: FALSE (blocked)
  20  evaluate/plan/gate-exec: UNKNOWN (paused, evidence required)
  30  accept: FAIL
  40  accept: INCONCLUSIVE
gate-exec returns the wrapped command's exit code when it was allowed to run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .acceptance import baseline_hash, run_acceptance
from .audit import AuditLog, reconstruct_state_history, replay_record, trace_evidence
from .canonical import hash_obj
from .contracts import CHECKPOINTS, contract_hash, load_json_file, seal_contract, validate_contract
from .evaluator import PhiEngine, Verdict
from .evidence import TrustStore, observe_files, sign_evidence
from .schemas import schema_errors

PROTOCOL = "phi-core/1.0"
EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2
EXIT_FALSE = 10
EXIT_UNKNOWN = 20
EXIT_ACCEPT_FAIL = 30
EXIT_ACCEPT_INCONCLUSIVE = 40
VERDICT_EXIT = {Verdict.TRUE: 0, Verdict.FALSE: EXIT_FALSE, Verdict.UNKNOWN: EXIT_UNKNOWN}
ACCEPT_EXIT = {"PASS": 0, "FAIL": EXIT_ACCEPT_FAIL, "INCONCLUSIVE": EXIT_ACCEPT_INCONCLUSIVE}


class InputError(Exception):
    pass


def _load(path: str) -> Any:
    try:
        if path == "-":
            return json.load(sys.stdin)
        return load_json_file(path)
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc


def _emit(obj: Any, output: str | None = None, stream=None) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
    print(text, file=stream or sys.stdout)


def _add_eval_inputs(p: argparse.ArgumentParser, checkpoint_required: bool = True) -> None:
    p.add_argument("--request", help="JSON request file ('-' for stdin) with contract/state/evidence/checkpoint")
    p.add_argument("--contract", help="task contract JSON")
    p.add_argument("--state", help="state JSON")
    p.add_argument("--evidence", help="evidence list JSON")
    p.add_argument("--checkpoint", choices=CHECKPOINTS)
    p.add_argument("--workspace", help="workspace root for file/schema verifiers")
    p.add_argument("--trust", help="trust store JSON (HMAC keys)")
    p.add_argument("--audit", help="append the evaluation to this JSONL audit log")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phi",
        description="phi-core: deterministic three-valued feasibility operator Phi(T, S, E) -> "
                    "TRUE|FALSE|UNKNOWN, plus an independent acceptance gate.",
    )
    parser.add_argument("--version", action="version", version=f"phi-core {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("validate", help="structurally validate a JSON document (not a feasibility verdict)")
    p.add_argument("file")
    p.add_argument("--kind", default="contract",
                   choices=["contract", "state", "evidence", "baseline", "anchor", "delivery"])

    p = sub.add_parser("hash", help="print the canonical SHA-256 of a contract / baseline / JSON file")
    p.add_argument("file")
    p.add_argument("--kind", default="contract", choices=["contract", "baseline", "json"])

    p = sub.add_parser("seal", help="write integrity.contract_hash into a contract")
    p.add_argument("file")
    p.add_argument("-o", "--output")

    p = sub.add_parser("evaluate", help="compute Phi(T, S, E) at a checkpoint; JSON verdict on stdout")
    _add_eval_inputs(p)
    p.add_argument("--output", help="also write the verdict JSON here")

    p = sub.add_parser("plan", help="plan-level check of several contracts (dependencies, ownership, cycles)")
    p.add_argument("--contracts", nargs="+", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--evidence", required=True)
    p.add_argument("--workspace")
    p.add_argument("--trust")

    p = sub.add_parser("gate-exec", help="run a command only if Phi is TRUE: phi gate-exec [inputs] -- CMD ...")
    _add_eval_inputs(p)
    p.add_argument("cmd", nargs=argparse.REMAINDER)

    p = sub.add_parser("audit", help="audit log tools")
    asub = p.add_subparsers(dest="audit_command", metavar="ACTION")
    a = asub.add_parser("verify", help="verify the hash chain")
    a.add_argument("log")
    a.add_argument("--anchor-seq", type=int)
    a.add_argument("--anchor-hash")
    a = asub.add_parser("replay", help="replay every recorded evaluation")
    a.add_argument("log")
    a.add_argument("--reverify", action="store_true", help="re-run evidence verification on the current workspace")
    a.add_argument("--workspace")
    a.add_argument("--trust")
    a = asub.add_parser("trace", help="trace an evidence_id through the log")
    a.add_argument("log")
    a.add_argument("evidence_id")
    a = asub.add_parser("states", help="reconstruct state history")
    a.add_argument("log")
    a.add_argument("--task-id")
    a = asub.add_parser("head", help="print head seq/hash for external anchoring")
    a.add_argument("log")

    p = sub.add_parser("accept", help="independent acceptance gate (PASS/FAIL/INCONCLUSIVE)")
    p.add_argument("--baseline", required=True)
    p.add_argument("--anchor", required=True)
    p.add_argument("--delivery", required=True)
    p.add_argument("--workspace", required=True)
    p.add_argument("--now", required=True, help="explicit evaluation time (RFC 3339)")
    p.add_argument("--trust")
    p.add_argument("--require-signed-anchor", action="store_true")
    p.add_argument("--audit")
    p.add_argument("--output")

    p = sub.add_parser("evidence", help="evidence helpers")
    esub = p.add_subparsers(dest="evidence_command", metavar="ACTION")
    e = esub.add_parser("observe", help="collect file/schema evidence claims for a contract")
    e.add_argument("--contract", required=True)
    e.add_argument("--workspace", required=True)
    e.add_argument("--now", required=True)
    e.add_argument("--source", default="local-observer")
    e.add_argument("--checkpoint", choices=CHECKPOINTS,
                   help="bind the observations to this checkpoint only (default: any checkpoint of the task)")
    e = esub.add_parser("sign", help="HMAC-sign evidence item(s) with a trust-store key")
    e.add_argument("file")
    e.add_argument("--trust", required=True)
    e.add_argument("--key-id", required=True)
    e.add_argument("-o", "--output")
    return parser


def _eval_inputs(args) -> dict[str, Any]:
    if args.request:
        req = _load(args.request)
        if not isinstance(req, dict):
            raise InputError("request must be a JSON object")
        missing = [k for k in ("contract", "state", "evidence", "checkpoint") if k not in req]
        if missing:
            raise InputError(f"request missing field(s): {', '.join(missing)}")
        inputs = {k: req[k] for k in ("contract", "state", "evidence", "checkpoint")}
        inputs["workspace"] = args.workspace or req.get("workspace")
    else:
        if not (args.contract and args.state and args.evidence and args.checkpoint):
            raise InputError("need --request, or all of --contract --state --evidence --checkpoint")
        inputs = {"contract": _load(args.contract), "state": _load(args.state),
                  "evidence": _load(args.evidence), "checkpoint": args.checkpoint,
                  "workspace": args.workspace}
    if args.checkpoint:
        inputs["checkpoint"] = args.checkpoint
    if inputs["checkpoint"] not in CHECKPOINTS:
        raise InputError(f"checkpoint must be one of {CHECKPOINTS}")
    inputs["trust_store"] = TrustStore.from_dict(_load(args.trust)) if args.trust else None
    return inputs


def _run_eval(args):
    i = _eval_inputs(args)
    result = PhiEngine().evaluate(i["contract"], i["state"], i["evidence"], checkpoint=i["checkpoint"],
                                  workspace=i["workspace"], trust_store=i["trust_store"])
    if args.audit:
        st = i["state"]
        ts = st.get("now") if isinstance(st, dict) and isinstance(st.get("now"), str) else "unknown"
        AuditLog(args.audit).append_evaluation(result, contract=i["contract"], state=i["state"],
                                               evidence=i["evidence"], timestamp=ts)
    return result


def _cmd_validate(args) -> int:
    data = _load(args.file)
    if args.kind == "contract":
        res = validate_contract(data)
        valid, errors = res.valid, res.errors
    elif args.kind == "evidence":
        if isinstance(data, list):
            errors = [f"[{i}] {e}" for i, item in enumerate(data) for e in schema_errors("evidence", item)]
        else:
            errors = schema_errors("evidence", data)
        valid = not errors
    else:
        errors = schema_errors(args.kind, data)
        valid = not errors
    if valid:
        print(f"VALID: {args.file}")
        print("Note: structural validity only; this is not a feasibility verdict or acceptance result.")
        return EXIT_VALID
    print(f"INVALID: {args.file}")
    for err in errors:
        print(f"  - {err}")
    return EXIT_INVALID


def _cmd_audit(args) -> int:
    if args.audit_command is None:
        raise InputError("audit requires an action: verify | replay | trace | states | head")
    log = AuditLog(args.log)
    if args.audit_command == "verify":
        anchor = None
        if args.anchor_seq is not None or args.anchor_hash:
            anchor = {"seq": args.anchor_seq, "head_hash": args.anchor_hash}
        report = log.verify(anchor=anchor)
        _emit(report)
        return 0 if report["ok"] else EXIT_INVALID
    if args.audit_command == "replay":
        if not log.verify()["ok"]:
            _emit({"error": "audit chain verification failed; refusing to replay", "chain": log.verify()})
            return EXIT_INVALID
        trust = TrustStore.from_dict(_load(args.trust)) if args.trust else None
        results = [replay_record(r, reverify=args.reverify, workspace=args.workspace, trust_store=trust)
                   for r in log.records() if r.get("record_type") == "phi_evaluation"]
        _emit({"replayed": len(results), "all_match": all(r["matches"] for r in results), "results": results})
        return 0 if all(r["matches"] for r in results) else EXIT_INVALID
    if args.audit_command == "trace":
        _emit(trace_evidence(log.records(), args.evidence_id))
        return 0
    if args.audit_command == "states":
        _emit(reconstruct_state_history(log.records(), args.task_id))
        return 0
    _emit(log.head())
    return 0


def _cmd_evidence(args) -> int:
    if args.evidence_command == "observe":
        _emit(observe_files(_load(args.contract), args.workspace, args.now, source=args.source,
                           checkpoint=args.checkpoint))
        return 0
    if args.evidence_command == "sign":
        store = _load(args.trust)
        spec = store.get("keys", {}).get(args.key_id)
        if spec is None:
            raise InputError(f"key {args.key_id!r} not in trust store")
        secret = bytes.fromhex(spec["secret_hex"])
        data = _load(args.file)
        signed = [sign_evidence(x, args.key_id, secret) for x in data] if isinstance(data, list) \
            else sign_evidence(data, args.key_id, secret)
        _emit(signed, args.output)
        return 0
    raise InputError("evidence requires an action: observe | sign")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "hash":
            data = _load(args.file)
            fn = {"contract": contract_hash, "baseline": baseline_hash, "json": hash_obj}[args.kind]
            print(fn(data))
            return 0
        if args.command == "seal":
            _emit(seal_contract(_load(args.file)), args.output)
            return 0
        if args.command == "evaluate":
            result = _run_eval(args)
            _emit({"protocol": PROTOCOL, **result.to_dict()}, args.output)
            return VERDICT_EXIT[result.verdict]
        if args.command == "plan":
            trust = TrustStore.from_dict(_load(args.trust)) if args.trust else None
            res = PhiEngine().evaluate_plan([_load(c) for c in args.contracts], _load(args.state),
                                            _load(args.evidence), workspace=args.workspace, trust_store=trust)
            _emit({"protocol": PROTOCOL, **res.to_dict()})
            return VERDICT_EXIT[res.verdict]
        if args.command == "gate-exec":
            cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
            if not cmd:
                raise InputError("gate-exec needs a command after --")
            result = _run_eval(args)
            _emit({"protocol": PROTOCOL, **result.to_dict()}, stream=sys.stderr)
            if not result.release:
                print(f"phi gate-exec: NOT EXECUTED ({result.verdict.value}: {result.action})", file=sys.stderr)
                return VERDICT_EXIT[result.verdict]
            return subprocess.run(cmd, shell=False).returncode
        if args.command == "audit":
            return _cmd_audit(args)
        if args.command == "accept":
            trust = TrustStore.from_dict(_load(args.trust)) if args.trust else None
            report = run_acceptance(_load(args.baseline), _load(args.anchor), _load(args.delivery),
                                    workspace=args.workspace, now=args.now, trust_store=trust,
                                    require_signed_anchor=args.require_signed_anchor)
            if args.audit:
                AuditLog(args.audit).append_acceptance(report, timestamp=args.now)
            _emit(report, args.output)
            return ACCEPT_EXIT[report["status"]]
        if args.command == "evidence":
            return _cmd_evidence(args)
    except InputError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_USAGE
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
