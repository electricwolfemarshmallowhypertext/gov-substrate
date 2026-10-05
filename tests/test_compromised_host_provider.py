"""Phase 9 controls for malicious adapters, approvals, witnesses, and anomalies."""

import base64
import copy
import hashlib

import pytest

from provider_gateway import create_receipt, verify_gateway_credential
from substrate import IntegrityError, Substrate


PROFILE = {
    "model": "fixed-model",
    "upstream": "fixed-upstream",
    "allow_fallbacks": False,
    "data_collection": "deny",
    "zdr": True,
    "retention": "none",
}
ACTOR = {
    "network": {"allowed": False},
    "filesystem": {"read": False, "write": False},
    "tools": {},
    "persistence": {"session": True, "cross_session": False},
    "shared_channels": [],
}
SECRET = b"phase-9-test-gateway-secret"


class MemoryWitness:
    def __init__(self):
        self.entries = []

    def append(self, event_id, event_hash, previous_hash):
        expected_id = len(self.entries) + 1
        expected_previous = self.entries[-1][1] if self.entries else "0" * 64
        if event_id != expected_id or previous_hash != expected_previous:
            raise RuntimeError("witness chain mismatch")
        self.entries.append((event_id, event_hash, previous_hash))

    def verify(self, event_id, event_hash):
        return bool(self.entries and self.entries[-1][:2] == (event_id, event_hash))


def registry(*, approval="private", monitoring=None):
    result = {
        "actors": {"a": copy.deepcopy(ACTOR), "b": copy.deepcopy(ACTOR)},
        "tokens": {"a-token": "a", "b-token": "b"},
        "operator_token": "operator-token",
        "circuit_operator_token": "circuit-token",
        "providers": {"strict-provider": {
            "max_classification": "restricted",
            "request": copy.deepcopy(PROFILE),
            "approval_required_at": approval,
            "gateway_required": True,
        }},
    }
    if monitoring is not None:
        result["monitoring"] = monitoring
    return result


def imported(substrate, actor, classification, content):
    return substrate.import_object(
        classification, "text/plain", base64.b64encode(content).decode(),
        [actor], "phase-9-fixture")["object_id"]


def action(object_id, **extra):
    return {"kind": "generation.prepare", "input_ids": [object_id],
            "provider": "strict-provider", "provider_request": copy.deepcopy(PROFILE),
            **extra}


def prepared(substrate, actor, session, object_id, **extra):
    return substrate.propose(actor, session, action(object_id, **extra))


def signed_completion(substrate, admitted, text="governed output"):
    claim = substrate.claim_generation(admitted["generation_id"],
                                       admitted["execution_token"], "strict-provider")
    assert claim["decision"] == "allow"
    receipt = create_receipt(
        SECRET, admitted["generation_id"], "strict-provider",
        claim["request_hash"], text.encode(), claim["gateway_credential"]).as_dict()
    return claim, receipt


def test_exact_provider_request_and_signed_completion_identity(tmp_path):
    substrate = Substrate(tmp_path / "exact.db", registry(approval=None),
                          gateway_secrets={"strict-provider": SECRET})
    session = substrate.create_session("a")["session_token"]
    source = imported(substrate, "a", "public", b"sealed public input")

    for field, value in (
            ("model", "substituted-model"), ("upstream", "fallback-upstream"),
            ("allow_fallbacks", True), ("data_collection", "allow"),
            ("zdr", False), ("retention", "30 days")):
        altered = copy.deepcopy(PROFILE)
        altered[field] = value
        denied = substrate.propose("a", session, {
            "kind": "generation.prepare", "input_ids": [source],
            "provider": "strict-provider", "provider_request": altered})
        assert denied["decision"] == "deny"
        assert denied["reason"] == "provider_request_mismatch"

    admitted = prepared(substrate, "a", session, source)
    claim, receipt = signed_completion(substrate, admitted)
    assert claim["provider_request"] == PROFILE
    assert [item["id"] for item in claim["inputs"]] == [source]

    mutations = {
        "generation_id": "0" * 32, "provider": "other-provider",
        "request_hash": "0" * 64, "response_hash": "0" * 64,
        "challenge": "other-challenge", "signature": "0" * 64,
    }
    for field, value in mutations.items():
        denied = substrate.complete_generation(
            admitted["generation_id"], "governed output", dict(receipt, **{field: value}))
        assert denied["reason"] == "provider_receipt_invalid"
    completed = substrate.complete_generation(admitted["generation_id"],
                                              "governed output", receipt)
    assert completed["decision"] == "succeeded"
    assert substrate.complete_generation(admitted["generation_id"],
                                         "governed output", receipt)["reason"] == (
                                             "generation_already_consumed")


def test_receipt_cannot_cross_generation_or_survive_circuit(tmp_path):
    substrate = Substrate(tmp_path / "receipt.db", registry(approval=None),
                          gateway_secrets={"strict-provider": SECRET})
    first_session = substrate.create_session("a")["session_token"]
    source = imported(substrate, "a", "public", b"one input")
    first = prepared(substrate, "a", first_session, source)
    _, first_receipt = signed_completion(substrate, first, "first")
    second_session = substrate.create_session("a")["session_token"]
    second = prepared(substrate, "a", second_session, source)
    second_claim = substrate.claim_generation(second["generation_id"],
                                               second["execution_token"], "strict-provider")
    first_claim = verify_gateway_credential(SECRET, first_receipt["challenge"])
    second_credential = verify_gateway_credential(
        SECRET, second_claim["gateway_credential"])
    assert first_claim["actor"] == second_credential["actor"] == "a"
    assert first_claim["generation_id"] != second_credential["generation_id"]
    assert first_receipt["challenge"] != second_claim["gateway_credential"]
    assert substrate.complete_generation(second["generation_id"], "first",
                                         first_receipt)["reason"] == "provider_receipt_invalid"
    stopped = substrate.set_circuit("circuit-token", "provider", "strict-provider",
                                    True, "provider compromise")
    assert stopped["decision"] == "allow"
    second_receipt = create_receipt(
        SECRET, second["generation_id"], "strict-provider",
        second_claim["request_hash"], b"second",
        second_claim["gateway_credential"]).as_dict()
    assert substrate.complete_generation(second["generation_id"], "second",
                                         second_receipt)["reason"] in {
                                             "generation_not_claimed", "execution_unavailable"}


def test_high_risk_approval_is_exact_short_lived_and_one_use(tmp_path, monkeypatch):
    substrate = Substrate(tmp_path / "approval.db", registry(),
                          gateway_secrets={"strict-provider": SECRET})
    session = substrate.create_session("a")["session_token"]
    source = imported(substrate, "a", "private", b"private input")
    pending = prepared(substrate, "a", session, source)
    assert pending["decision"] == "escalate"
    approved = substrate.approve_transfer(
        "operator-token", pending["approval_request_id"], "reviewed exact transfer")

    altered = action(source, approval_token=approved["approval_token"])
    altered["provider_request"] = dict(PROFILE, model="different")
    assert substrate.propose("a", session, altered)["decision"] == "deny"

    admitted = prepared(substrate, "a", session, source,
                        approval_token=approved["approval_token"])
    assert admitted["decision"] == "allow"
    replay = prepared(substrate, "a", session, source,
                      approval_token=approved["approval_token"])
    assert replay["decision"] == "escalate"
    rules = [event["policy"]["rule"] for event in substrate.audit()]
    assert "exact_transfer_approved" in rules

    expiring = prepared(substrate, "a", session, source)
    expiring_token = substrate.approve_transfer(
        "operator-token", expiring["approval_request_id"], "short review")
    monkeypatch.setattr("substrate.time.time", lambda: expiring_token["expires_at"] + 1)
    expired = prepared(substrate, "a", session, source,
                       approval_token=expiring_token["approval_token"])
    assert expired["decision"] == "escalate"


def test_independent_witness_divergence_fails_closed(tmp_path):
    witness = MemoryWitness()
    substrate = Substrate(tmp_path / "witness.db", registry(approval=None),
                          audit_witness=witness,
                          gateway_secrets={"strict-provider": SECRET})
    substrate.create_session("a")
    witness.entries[-1] = (witness.entries[-1][0], "f" * 64,
                           witness.entries[-1][2])
    with pytest.raises(IntegrityError, match="witness diverged"):
        substrate.audit()
    with pytest.raises(IntegrityError, match="witness diverged"):
        substrate.create_session("a")


def test_cross_actor_and_resource_abuse_trigger_scoped_containment(tmp_path):
    policy = registry(approval=None, monitoring={
        "window_seconds": 60, "actor_denials": 3, "cross_actor_denials": 2})
    substrate = Substrate(tmp_path / "monitor.db", policy,
                          gateway_secrets={"strict-provider": SECRET})
    a_session = substrate.create_session("a")["session_token"]
    b_session = substrate.create_session("b")["session_token"]
    denied_action = {"kind": "network.request", "url": "https://blocked.invalid/"}
    assert substrate.propose("a", a_session, denied_action)["decision"] == "deny"
    assert substrate.propose("b", b_session, denied_action)["decision"] == "deny"
    stops = [event for event in substrate.audit()
             if event["action"].get("kind") == "circuit.trigger"]
    assert stops[-1]["action"] == {"kind": "circuit.trigger",
                                    "scope": "capability", "target": "network"}

    fresh = Substrate(tmp_path / "abuse.db", policy,
                      gateway_secrets={"strict-provider": SECRET})
    session = fresh.create_session("a")["session_token"]
    for index in range(3):
        result = fresh.propose("a", session, {
            "kind": "state.read", "scope": "invalid", "key": f"key-{index}"})
        assert result["decision"] == "deny"
    stop = [event for event in fresh.audit()
            if event["action"].get("kind") == "circuit.trigger"][-1]
    assert stop["action"] == {"kind": "circuit.trigger", "scope": "actor", "target": "a"}
