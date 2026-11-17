"""phi-core: deterministic three-valued feasibility operator Phi(T, S, E).

Phi(T, S, E) -> TRUE | FALSE | UNKNOWN. Only TRUE releases execution. Phi is a
feasibility gate; final delivery acceptance is a separate gate
(:mod:`phi_core.acceptance`). Phi TRUE does not imply Acceptance PASS.
"""

from .acceptance import AStatus, baseline_hash, make_anchor_entry, new_revision, run_acceptance
from .audit import (
    AuditLog,
    compare_versions,
    reconstruct_state_history,
    replay_log,
    replay_record,
    trace_evidence,
    verify_chain,
)
from .contracts import (
    CHECKPOINTS,
    CONTRACT_VERSION,
    LEGACY_CONTRACT_VERSION,
    CompiledConstraint,
    Constraint,
    ContractFormatError,
    TaskContract,
    ValidationResult,
    compile_constraints,
    contract_hash,
    load_schema,
    seal_contract,
    validate_contract,
)
from .evaluator import (
    EVALUATOR_VERSION,
    ConstraintResult,
    EvaluationResult,
    PhiEngine,
    PlanResult,
    Verdict,
    evaluate,
)
from .evidence import (
    EvidenceFormatError,
    EvidenceItem,
    TrustStore,
    VerificationContext,
    VerificationResult,
    VerifierRegistry,
    VStatus,
    default_verifier_registry,
    make_evidence,
    observe_files,
    sign_evidence,
    verify_evidence,
)
from .gate import (
    Decision,
    DecisionInvalid,
    GateBlocked,
    GateDenied,
    GatedRunner,
    GateNeedsEvidence,
    GateSequenceError,
    GateSession,
    HarnessAdapter,
    PhiGate,
    RunReport,
    Step,
)
from .predicates import (
    EvidencePredicate,
    FunctionPredicate,
    Outcome,
    Predicate,
    PredicateRegistry,
    StatePredicate,
    Status,
    default_predicate_registry,
)

__version__ = "1.0.0"

__all__ = [name for name in dir() if not name.startswith("_")] + ["__version__"]
