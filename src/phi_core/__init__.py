"""phi-core: engineering scaffold for the three-valued feasibility operator Phi(T, E).

Implemented: task contract / evidence data models, JSON Schema structural
validation, CLI. NOT implemented: Phi itself (``evaluate`` raises
NotImplementedError).
"""

from .contracts import (
    CONTRACT_VERSION,
    Constraint,
    ContractFormatError,
    TaskContract,
    ValidationResult,
    load_schema,
    validate_contract,
)
from .evaluator import NOT_IMPLEMENTED_MESSAGE, Verdict, evaluate
from .evidence import EvidenceItem, EvidenceSet

__version__ = "0.0.1.dev0"

__all__ = [
    "CONTRACT_VERSION",
    "Constraint",
    "ContractFormatError",
    "EvidenceItem",
    "EvidenceSet",
    "NOT_IMPLEMENTED_MESSAGE",
    "TaskContract",
    "ValidationResult",
    "Verdict",
    "__version__",
    "evaluate",
    "load_schema",
    "validate_contract",
]
