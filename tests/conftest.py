import copy
import hashlib
from pathlib import Path

import pytest

from phi_core import TrustStore, make_evidence, sign_evidence

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-11-17T00:00:00Z"
EARLIER = "2026-11-16T23:50:00Z"
SECRET = b"test-secret-0123456789abcdef-XYZ"
OTHER_SECRET = b"attacker-secret-0123456789abcdef"
TASK = "t-main"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def base_contract(**overrides):
    c = {
        "contract_version": "1.0",
        "task_id": TASK,
        "objective": "test task",
        "constraint_scope": {"complete": True},
    }
    c.update(copy.deepcopy(overrides))
    return c


def base_state(**overrides):
    s = {
        "state_version": "1.0",
        "now": NOW,
        "tasks": {TASK: {"status": "ready"}, "dep-a": {"status": "completed"}},
        "capabilities": ["python3"],
        "capabilities_complete": True,
        "resources": {"cpu": 4},
        "file_owners": {},
    }
    s.update(copy.deepcopy(overrides))
    return s


def attest(evidence_id, constraint_id, value, *, ts=EARLIER, source="ci-runner", key_id="k-ci",
           secret=SECRET, **kw):
    item = make_evidence(evidence_id, constraint_id, source=source, verifier_id="hmac_attestation",
                         observed_value=value, timestamp=ts, **kw)
    return sign_evidence(item, key_id, secret)


def file_ev(evidence_id, constraint_id, path, *, artifact_hash=None, ts=EARLIER, source="observer", **ov):
    return make_evidence(evidence_id, constraint_id, source=source, verifier_id="file_sha256",
                         observed_value={"path": path, **ov}, timestamp=ts, artifact_hash=artifact_hash)


@pytest.fixture
def trust():
    store = TrustStore()
    store.add_key("k-ci", SECRET, ["ci-runner"])
    store.add_key("k-lab", SECRET[::-1], ["lab"])
    return store


@pytest.fixture
def ws(tmp_path):
    w = tmp_path / "ws"
    w.mkdir()
    return w
