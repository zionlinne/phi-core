"""Command-line interface: ``phi``.

Exit codes:
  0  structurally valid contract (``validate``)
  1  structurally invalid contract (``validate``)
  2  usage error / unreadable file / malformed JSON
  3  NOT_IMPLEMENTED (``evaluate``)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .contracts import load_contract_file, validate_contract
from .evaluator import NOT_IMPLEMENTED_MESSAGE

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2
EXIT_NOT_IMPLEMENTED = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phi",
        description=(
            "phi-core scaffold. Validates task contract structure. "
            "The feasibility operator Phi(T, E) is NOT implemented."
        ),
    )
    parser.add_argument("--version", action="version", version=f"phi-core {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_validate = sub.add_parser(
        "validate",
        help="check that a task contract JSON file is structurally valid",
        description=(
            "Structural validation only. A VALID result does not mean the task is "
            "feasible and does not mean final acceptance has passed."
        ),
    )
    p_validate.add_argument("contract", help="path to task contract JSON file")

    p_eval = sub.add_parser(
        "evaluate",
        help="(NOT IMPLEMENTED) compute Phi(T, E); always exits with NOT_IMPLEMENTED",
    )
    p_eval.add_argument("contract", help="path to task contract JSON file")
    p_eval.add_argument("--evidence", help="path to evidence JSON file (ignored)")
    return parser


def _cmd_validate(path: str) -> int:
    try:
        data = load_contract_file(path)
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except json.JSONDecodeError as exc:
        print(f"ERROR: {path} is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = validate_contract(data)
    if result.valid:
        print(f"VALID: {path}")
        print("Note: structural validity only; this is not a feasibility verdict or acceptance result.")
        return EXIT_VALID
    print(f"INVALID: {path}")
    for err in result.errors:
        print(f"  - {err}")
    return EXIT_INVALID


def _cmd_evaluate() -> int:
    print("NOT_IMPLEMENTED", file=sys.stderr)
    print(NOT_IMPLEMENTED_MESSAGE, file=sys.stderr)
    return EXIT_NOT_IMPLEMENTED


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate":
        return _cmd_validate(args.contract)
    if args.command == "evaluate":
        return _cmd_evaluate()
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
