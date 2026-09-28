"""Deterministic free-form generation through audited object context."""

import base64
import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from substrate import Substrate, create_app


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    actor = {
        "data": {"sensitive_access": True},
        "network": {"allowed": True, "publication": True, "services": [
            {"origin": "http://127.0.0.1:9", "mode": "publication",
             "egress": "external", "paths": ["/publish"]}]},
        "filesystem": {"scopes": {"session": {"read": True, "write": True},
                                  "actor": {"read": True, "write": True},
                                  "shared": {"channels": []}}},
        "tools": {}, "persistence": {"session": True, "cross_session": False},
        "shared_channels": [],
    }
    substrate = Substrate(tmp_path / "generation.db", {
        "actors": {"agent-a": actor, "agent-clean": copy.deepcopy(actor)},
        "tokens": {"agent-a-token": "agent-a", "agent-clean-token": "agent-clean"},
        "operator_token": "operator-token"})
    client = TestClient(create_app(substrate))
    published = []

    def fake_fetch(url, allowed_origins):
        assert allowed_origins == ["http://127.0.0.1:9"]
        published.append(parse_qs(urlsplit(url).query)["data"][0])
        return {"status": 200, "bytes": 0, "body_sha256": "0" * 64,
                "origin": allowed_origins[0], "resolved_ip": "127.0.0.1"}

    monkeypatch.setattr("substrate.fetch", fake_fetch)

    def imported(classification, content, readers=None):
        response = client.post("/objects/import", headers={"Authorization": "Bearer operator-token"},
                               json={"classification": classification, "media_type": "text/plain",
                                     "content_base64": base64.b64encode(content.encode()).decode(),
                                     "readers": readers or ["agent-a"], "source": "test-fixture"})
        assert response.status_code == 200, response.text
        return response.json()["object_id"]

    objects = {
        "public": imported("public", "Public source.", ["agent-a", "agent-clean"]),
        "internal": imported("internal", "Internal source."),
        "private": imported("private", "Private source."),
        "restricted": imported("restricted", "Restricted source."),
    }
    sessions = {name: substrate.create_session(name)["session_token"]
                for name in ("agent-a", "agent-clean")}

    def propose(action, actor_id="agent-a"):
        return substrate.propose(actor_id, sessions[actor_id], action)

    return substrate, client, objects, sessions, propose, published


def test_public_context_generates_publishable_public_object(boundary):
    substrate, _, objects, _, propose, published = boundary
    assert propose({"kind": "object.read", "object_id": objects["public"]})["decision"] == "allow"
    output = propose({"kind": "object.generate", "content": "A public answer."})
    assert output["decision"] == "allow"
    assert output["classification"] == "public" and output["parents"] == [objects["public"]]
    result = propose({"kind": "object.publish", "object_id": output["object_id"],
                      "destination": "http://127.0.0.1:9"})
    assert result["decision"] == "allow" and result["outcome"] == "succeeded"
    assert published == ["A public answer."]
    assert any(item["id"] == output["object_id"] and item["operation"] == "generate"
               for event in substrate.audit() if event["action"]["kind"] == "object.generate"
               for item in event["state_after"]["objects"])


def test_private_context_blocks_generated_publication(boundary):
    _, _, objects, _, propose, published = boundary
    propose({"kind": "object.read", "object_id": objects["private"]})
    output = propose({"kind": "object.generate", "content": "Rewritten private text."})
    assert output["classification"] == "private" and output["parents"] == [objects["private"]]
    denied = propose({"kind": "object.publish", "object_id": output["object_id"],
                      "destination": "http://127.0.0.1:9"})
    assert denied["decision"] == "deny"
    assert denied["reason"] == "object_classification_blocks_egress" and not published


def test_internal_context_generates_internal_output(boundary):
    _, _, objects, _, propose, _ = boundary
    propose({"kind": "object.read", "object_id": objects["internal"]})
    output = propose({"kind": "object.generate", "content": "Internal answer."})
    assert output["classification"] == "internal"
    assert output["parents"] == [objects["internal"]]


def test_mixed_context_inherits_highest_classification(boundary):
    _, _, objects, _, propose, _ = boundary
    propose({"kind": "object.read", "object_id": objects["public"]})
    propose({"kind": "object.read", "object_id": objects["private"]})
    output = propose({"kind": "object.generate", "content": "Combined answer."})
    assert output["classification"] == "private"
    assert output["parents"] == [objects["public"], objects["private"]]
    assert propose({"kind": "object.publish", "object_id": output["object_id"],
                    "destination": "http://127.0.0.1:9"})["decision"] == "deny"


def test_transformed_context_cannot_drop_restricted_source(boundary):
    _, _, objects, _, propose, _ = boundary
    transformed = propose({"kind": "object.transform", "object_id": objects["restricted"],
                           "operation": "base64"})
    assert transformed["classification"] == "restricted"
    output = propose({"kind": "object.generate", "content": "Rewritten transform."})
    assert output["classification"] == "restricted"
    assert output["parents"] == [objects["restricted"]]


@pytest.mark.parametrize("text", ["Paraphrase.", "Encoded: c2VjcmV0", "Summary.", "Rewrite."])
def test_restricted_context_survives_free_form_rewriting(boundary, text):
    _, _, objects, _, propose, _ = boundary
    propose({"kind": "object.read", "object_id": objects["restricted"]})
    output = propose({"kind": "object.generate", "content": text})
    assert output["classification"] == "restricted"
    assert output["parents"] == [objects["restricted"]]


def test_new_session_does_not_clear_context_classification(boundary):
    substrate, _, objects, sessions, propose, _ = boundary
    propose({"kind": "object.read", "object_id": objects["private"]})
    first = propose({"kind": "object.generate", "content": "First answer."})
    sessions["agent-a"] = substrate.create_session("agent-a")["session_token"]
    reread = propose({"kind": "object.read", "object_id": first["object_id"]})
    assert reread["classification"] == "private"
    propose({"kind": "object.read", "object_id": objects["public"]})
    second = propose({"kind": "object.generate", "content": "After session reset."})
    assert second["classification"] == "private"
    assert objects["private"] in second["parents"]


def test_model_cannot_set_output_classification_or_parents(boundary):
    substrate, _, objects, _, propose, _ = boundary
    propose({"kind": "object.read", "object_id": objects["private"]})
    denied = propose({"kind": "object.generate", "content": "Private source.",
                      "classification": "public", "parents": [objects["public"]]})
    assert denied["decision"] == "deny" and denied["reason"] == "generated_output_fields_forbidden"
    invalid = propose({"kind": "object.generate", "content": "\ud800"})
    assert invalid["decision"] == "deny" and invalid["reason"] == "invalid_content"
    assert "Private source." not in json.dumps(substrate.audit())


def test_operator_declassifies_generated_child_with_reason(boundary):
    substrate, client, objects, _, propose, published = boundary
    propose({"kind": "object.read", "object_id": objects["private"]})
    original = propose({"kind": "object.generate", "content": "Reviewed release."})
    assert client.post("/objects/declassify", headers={"Authorization": "Bearer agent-a-token"},
                       json={"object_id": original["object_id"], "classification": "public",
                             "reason": "approved"}).status_code == 401
    result = client.post("/objects/declassify", headers={"Authorization": "Bearer operator-token"},
                         json={"object_id": original["object_id"], "classification": "public",
                               "reason": "human reviewed output"}).json()
    assert result["decision"] == "override" and result["parent_id"] == original["object_id"]
    assert propose({"kind": "object.read", "object_id": original["object_id"]})["classification"] == "private"
    assert propose({"kind": "object.read", "object_id": result["object_id"]})["classification"] == "public"
    published_result = propose({"kind": "object.publish", "object_id": result["object_id"],
                                "destination": "http://127.0.0.1:9"})
    assert published_result["outcome"] == "succeeded" and published == ["Reviewed release."]
    assert any(event["decision"] == "override" and
               event["policy"]["reason"] == "human reviewed output"
               for event in substrate.audit())


def test_clean_public_only_actor_can_generate_public_output(boundary):
    _, _, objects, _, propose, published = boundary
    assert propose({"kind": "object.generate", "content": "No context."},
                   "agent-clean")["reason"] == "generation_context_required"
    assert propose({"kind": "object.read", "object_id": objects["private"]},
                   "agent-clean")["decision"] == "deny"
    assert propose({"kind": "object.read", "object_id": objects["public"]},
                   "agent-clean")["decision"] == "allow"
    output = propose({"kind": "object.generate", "content": "Clean answer."}, "agent-clean")
    assert output["classification"] == "public" and output["parents"] == [objects["public"]]
    assert propose({"kind": "object.publish", "object_id": output["object_id"],
                    "destination": "http://127.0.0.1:9"}, "agent-clean")["outcome"] == "succeeded"
    assert published == ["Clean answer."]
