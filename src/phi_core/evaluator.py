"""Interface for the feasibility operator Phi(T, E) -> {TRUE, FALSE, UNKNOWN}.

NOT IMPLEMENTED. This module only fixes the Python call shape. Calling
:func:`evaluate` always raises :class:`NotImplementedError`; no verdict is ever
produced in this phase.

Intended meaning (for the future implementation, not enforced here):

* TRUE    -- the necessary execution conditions are satisfied.
* FALSE   -- a verified hard-constraint violation exists.
* UNKNOWN -- evidence is insufficient; execution should be deferred.

Phi(T, E) = TRUE does NOT imply Acceptance(T) = PASS. Feasibility and final
delivery acceptance are separate gates.
"""

from __future__ import annotations

from enum import Enum

from .contracts import TaskContract
from .evidence import EvidenceSet

NOT_IMPLEMENTED_MESSAGE = (
    "Phi(T, E) is not implemented in phi-core yet; no feasibility verdict can be produced."
)


class Verdict(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


def evaluate(contract: TaskContract, evidence: EvidenceSet) -> Verdict:
    """Compute Phi(contract, evidence). Always raises NotImplementedError."""
    raise NotImplementedError(NOT_IMPLEMENTED_MESSAGE)
