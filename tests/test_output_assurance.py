"""Hosted output holds and controlled attestation, with no provider API calls."""

import base64
import copy

import pytest
from fastapi.testclient import TestClient

from provider_gateway import create_receipt
from substrate import Substrate, create_app


GATEWAY_KEY = b"synthetic-gateway-key"
PROFILE = {"model": "model-v1", "upstream": "fixture", "allow_fallbacks": False,
           "data_collection": "deny", "zdr": True, "retention": "none"}


def boundary(tmp_path, monkeypatch, assurance):
    actor = {
        "data": {"sensitive_access": False},
        "network": {"allowed": True, "publication": True, "services": [
            {"origin": "http://127.0.0.1:9", "mode": "publication",
             "egress": "external", "paths": ["/publish"]}]},
        "filesystem": {"read": False, "write": False}, "tools": {},
        "persistence": {"session": True, "cross_session": False},
        "shared_channels": [],
    }
    grant = {"max_classification": "public", "request": copy.deepcopy(PROFILE),
             "gateway_required": True, "assurance": assurance}
    substrate = Substrate(tmp_path / "assurance.db", {
        "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
        "operator_token": "operator-token", "providers": {"fixture": grant},
    }, gateway_secrets={"fixture": GATEWAY_KEY})
    published = []
    def fake_fetch(url, origins):
        published.append(url)
        return {"status": 200, "bytes": 1, "body_sha256": "0" * 64,
                "origin": origins[0], "resolved_ip": "127.0.0.1"}
    monkeypatch.setattr("substrate.fetch", fake_fetch)
    source = substrate.import_object("public", "text/plain",
                                     base64.b64encode(b"Public source.").decode(),
                                     ["agent"], "synthetic-fixture")["object_id"]
    session = substrate.create_session("agent")["session_token"]
    action = {"kind": "generation.prepare", "input_ids": [source],
              "provider": "fixture", "provider_request": PROFILE}
    prepared = substrate.propose("agent", session, action)
    assert prepared["decision"] == "allow"
    claim = substrate.claim_generation(prepared["generation_id"],
                                       prepared["execution_token"], "fixture")
    assert claim["decision"] == "allow"
    assert substrate.authorize_provider_call(prepared["generation_id"], "fixture",
                                             claim["gateway_credential"])["decision"] == "allow"
    return substrate, TestClient(create_app(substrate)), session, source, prepared, claim, published


def receipt(prepared, claim, text, attestation=None):
    return create_receipt(GATEWAY_KEY, prepared["generation_id"], "fixture",
                          claim["request_hash"], text.encode(),
                          claim["gateway_credential"], attestation).as_dict()


def test_valid_gateway_receipt_does_not_release_contaminated_public_output(tmp_path, monkeypatch):
    substrate, client, session, _, prepared, claim, published = boundary(
        tmp_path, monkeypatch, "hosted_opaque")
    text = "Private text from an unrelated request."
    result = substrate.complete_generation(prepared["generation_id"], text,
                                           receipt(prepared, claim, text))
    assert result["decision"] == "succeeded" and result["classification"] == "public"
    original = result["object_id"]
    publish = {"kind": "object.publish", "object_id": original,
               "destination": "http://127.0.0.1:9"}
    assert substrate.propose("agent", session, publish)["reason"] == "object_release_required"
    assert substrate.propose("agent", session, {"kind": "network.request",
               "url": "http://127.0.0.1:9/publish?data=leak"})["reason"] == (
                   "sensitive_external_egress_disabled")
    transformed = substrate.propose("agent", session, {"kind": "object.transform",
                                    "object_id": original, "operation": "base64"})
    assert transformed["decision"] == "allow"
    assert substrate.propose("agent", session, {**publish,
        "object_id": transformed["object_id"]})["reason"] == "object_release_required"
    local = substrate.propose("agent", session, {"kind": "generation.prepare",
                         "input_ids": [original]})
    assert local["decision"] == "allow"
    assert substrate.claim_generation(local["generation_id"],
                                     local["execution_token"])["decision"] == "allow"
    child = substrate.complete_generation(local["generation_id"], "Derived public text.")
    assert substrate.propose("agent", session, {**publish,
        "object_id": child["object_id"]})["reason"] == "object_release_required"
    assert not published
    assert client.post("/objects/release", headers={"Authorization": "Bearer agent-token"},
                       json={"object_id": original, "reason": "reviewed"}).status_code == 401
    released = client.post("/objects/release", headers={"Authorization": "Bearer operator-token"},
                           json={"object_id": original, "reason": "independent review"}).json()
    assert released["decision"] == "override" and released["parent_id"] == original
    assert substrate.propose("agent", session, publish)["reason"] == "object_release_required"
    assert substrate.propose("agent", session, {**publish,
        "object_id": released["object_id"]})["outcome"] == "succeeded"
    assert len(published) == 1
