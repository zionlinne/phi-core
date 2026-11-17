import os

import pytest

from conftest import EARLIER, NOW, OTHER_SECRET, SECRET, attest, file_ev, sha
from phi_core import (
    TrustStore,
    VerificationContext,
    VerifierRegistry,
    VStatus,
    default_verifier_registry,
    make_evidence,
    sign_evidence,
    verify_evidence,
)
from phi_core.canonical import parse_time
from phi_core.evidence import VerificationResult


def ctx(ws=None, trust=None, now=NOW):
    return VerificationContext(now=parse_time(now), workspace=ws, trust_store=trust or TrustStore())


def one(items, c):
    res = verify_evidence(items, c)
    assert len(res) == len(items)
    return res[0]


def test_caller_claimed_status_is_never_trusted(ws):
    item = make_evidence("e1", "c1", source="x", verifier_id="no-such-verifier", observed_value=True,
                         timestamp=EARLIER, verification_status="VERIFIED")
    r = one([item], ctx(ws))
    assert r.status is VStatus.UNVERIFIABLE
    assert "NO_REGISTERED_VERIFIER" in r.reason_codes
    assert r.claimed_status == "VERIFIED"
    assert r.observed is None


def test_file_verifier_recomputes_hash(ws):
    (ws / "a.txt").write_bytes(b"abc")
    good = one([file_ev("e", "c", "a.txt", artifact_hash=sha(b"abc"))], ctx(ws))
    assert good.status is VStatus.VERIFIED and good.observed == {"path": "a.txt", "exists": True, "sha256": sha(b"abc")}
    forged = one([file_ev("e", "c", "a.txt", artifact_hash=sha(b"other"))], ctx(ws))
    assert forged.status is VStatus.REJECTED and "ARTIFACT_HASH_MISMATCH" in forged.reason_codes
    claimed = one([file_ev("e", "c", "a.txt", sha256=sha(b"other"))], ctx(ws))
    assert claimed.status is VStatus.REJECTED


def test_file_verifier_missing_file(ws):
    obs = one([file_ev("e", "c", "nope.txt")], ctx(ws))
    assert obs.status is VStatus.VERIFIED and obs.observed["exists"] is False
    lie = one([file_ev("e", "c", "nope.txt", exists=True)], ctx(ws))
    assert lie.status is VStatus.REJECTED and "CLAIM_CONTRADICTS_OBSERVATION" in lie.reason_codes


@pytest.mark.parametrize("path", ["../escape.txt", "/etc/passwd", "a/../../x"])
def test_file_verifier_rejects_paths_outside_workspace(ws, path):
    r = one([file_ev("e", "c", path)], ctx(ws))
    assert r.status is VStatus.REJECTED and "PATH_OUTSIDE_WORKSPACE" in r.reason_codes


def test_file_verifier_rejects_symlink_escape(ws, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    os.symlink(outside, ws / "link.txt")
    r = one([file_ev("e", "c", "link.txt")], ctx(ws))
    assert r.status is VStatus.REJECTED


def test_file_verifier_without_workspace_is_unverifiable():
    r = one([file_ev("e", "c", "a.txt")], ctx(None))
    assert r.status is VStatus.UNVERIFIABLE


def test_hmac_attestation(trust):
    good = one([attest("e", "c", {"passed": True})], ctx(trust=trust))
    assert good.status is VStatus.VERIFIED and good.observed == {"passed": True}
    unknown_key = one([attest("e", "c", True, key_id="k-nobody")], ctx(trust=trust))
    assert unknown_key.status is VStatus.UNVERIFIABLE and "UNKNOWN_SIGNING_KEY" in unknown_key.reason_codes
    wrong_secret = one([attest("e", "c", True, secret=OTHER_SECRET)], ctx(trust=trust))
    assert wrong_secret.status is VStatus.REJECTED and "SIGNATURE_INVALID" in wrong_secret.reason_codes
    wrong_source = one([attest("e", "c", True, source="lab")], ctx(trust=trust))
    assert wrong_source.status is VStatus.REJECTED and "SOURCE_NOT_AUTHORIZED_FOR_KEY" in wrong_source.reason_codes
    unsigned = make_evidence("e", "c", source="ci-runner", verifier_id="hmac_attestation", observed_value=True,
                             timestamp=EARLIER)
    assert one([unsigned], ctx(trust=trust)).status is VStatus.UNVERIFIABLE


@pytest.mark.parametrize("field, value", [
    ("observed_value", {"passed": False}), ("constraint_id", "other"), ("timestamp", "2026-11-16T23:59:00Z"),
    ("source", "ci-runner2"), ("artifact_hash", "0" * 64),
])
def test_hmac_detects_tampering_of_any_signed_field(trust, field, value):
    item = attest("e", "c", {"passed": True})
    item[field] = value
    r = one([item], ctx(trust=trust))
    assert r.status is not VStatus.VERIFIED


def test_hmac_ignores_claimed_status_field(trust):
    item = attest("e", "c", {"passed": True})
    item["verification_status"] = "anything"
    assert one([item], ctx(trust=trust)).status is VStatus.VERIFIED


def test_hmac_artifact_binding(ws, trust):
    (ws / "log.txt").write_bytes(b"ok")
    item = attest("e", "c", True, artifact_hash=sha(b"ok"), provenance={"artifact_path": "log.txt"})
    assert one([item], ctx(ws, trust)).status is VStatus.VERIFIED
    (ws / "log.txt").write_bytes(b"changed")
    r = one([item], ctx(ws, trust))
    assert r.status is VStatus.REJECTED and "ARTIFACT_HASH_MISMATCH" in r.reason_codes


def test_future_timestamp_rejected(trust):
    r = one([attest("e", "c", True, ts="2026-11-17T00:00:01Z")], ctx(trust=trust))
    assert r.status is VStatus.REJECTED and "TIMESTAMP_IN_FUTURE" in r.reason_codes


def test_no_trusted_time_is_unverifiable(trust):
    c = VerificationContext(now=None, trust_store=trust)
    assert one([attest("e", "c", True)], c).status is VStatus.UNVERIFIABLE


def test_duplicate_ids_rejected(trust):
    a = attest("dup", "c", True)
    b = attest("dup", "c", False)
    res = verify_evidence([a, b], ctx(trust=trust))
    assert [r.status for r in res] == [VStatus.REJECTED, VStatus.REJECTED]


@pytest.mark.parametrize("raw", [None, 5, "x", {}, {"evidence_id": "e"}, [1, 2]])
def test_malformed_items_rejected(raw):
    r = verify_evidence([raw], ctx())[0]
    assert r.status is VStatus.REJECTED and "MALFORMED_EVIDENCE" in r.reason_codes


def test_non_list_payload():
    r = verify_evidence({"not": "a list"}, ctx())
    assert r[0].status is VStatus.REJECTED and "EVIDENCE_PAYLOAD_NOT_A_LIST" in r[0].reason_codes


def test_crashing_or_lying_custom_verifier_gains_no_trust():
    class Boom:
        verifier_id = "boom"

        def verify(self, item, c):
            raise RuntimeError("x")

    class Liar:
        verifier_id = "liar"

        def verify(self, item, c):
            return "VERIFIED"

    reg = default_verifier_registry()
    reg.register(Boom())
    reg.register(Liar())
    items = [make_evidence(f"e-{v}", "c", source="s", verifier_id=v, observed_value=1, timestamp=EARLIER)
             for v in ("boom", "liar")]
    res = verify_evidence(items, ctx(), reg)
    assert all(r.status is VStatus.UNVERIFIABLE for r in res)


def test_custom_deterministic_verifier_registration():
    class Even:
        verifier_id = "even-number"

        def verify(self, item, c):
            ok = isinstance(item.observed_value, int) and item.observed_value % 2 == 0
            return VerificationResult(item.evidence_id, item.constraint_id, item.source, item.verifier_id,
                                      VStatus.VERIFIED if ok else VStatus.REJECTED, (), item.observed_value if ok else None,
                                      item.timestamp, item.verification_status)

    reg = VerifierRegistry()
    reg.register(Even())
    with pytest.raises(ValueError):
        reg.register(Even())
    items = [make_evidence(f"e{n}", "c", source="s", verifier_id="even-number", observed_value=n, timestamp=EARLIER)
             for n in (2, 3)]
    res = verify_evidence(items, ctx(), reg)
    assert [r.status for r in res] == [VStatus.VERIFIED, VStatus.REJECTED]


def test_json_schema_verifier(ws):
    (ws / "s.json").write_text('{"type":"object","required":["a"]}')
    (ws / "d.json").write_text('{"a":1}')
    item = make_evidence("e", "c", source="o", verifier_id="json_schema",
                         observed_value={"path": "d.json", "schema_path": "s.json"}, timestamp=EARLIER)
    r = one([item], ctx(ws))
    assert r.status is VStatus.VERIFIED and r.observed["valid"] is True
    (ws / "d.json").write_text('{"b":1}')
    assert one([item], ctx(ws)).observed["valid"] is False
    item["observed_value"]["valid"] = True
    assert one([item], ctx(ws)).status is VStatus.REJECTED


def test_trust_store_rejects_short_secret():
    with pytest.raises(ValueError):
        TrustStore().add_key("k", b"short", ["s"])


def test_sign_evidence_does_not_mutate_input():
    item = make_evidence("e", "c", source="s", verifier_id="hmac_attestation", observed_value=1, timestamp=EARLIER)
    before = repr(item)
    sign_evidence(item, "k", SECRET)
    assert repr(item) == before
