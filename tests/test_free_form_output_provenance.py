"""Sealed generation manifests, exact lineage, and publication authority."""

import base64
import copy
import json
import sqlite3
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from generation_adapter import run_generation
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
    db_path = tmp_path / "generation.db"
    substrate = Substrate(db_path, {
        "actors": {"agent-a": actor, "agent-b": copy.deepcopy(actor)},
        "tokens": {"agent-a-token": "agent-a", "agent-b-token": "agent-b"},
        "operator_token": "operator-token"})
    client = TestClient(create_app(substrate))
    published = []

    def fake_fetch(url, allowed_origins):
        assert allowed_origins == ["http://127.0.0.1:9"]
        published.append(parse_qs(urlsplit(url).query)["data"][0])
        return {"status": 200, "bytes": 0, "body_sha256": "0" * 64,
                "origin": allowed_origins[0], "resolved_ip": "127.0.0.1"}

    monkeypatch.setattr("substrate.fetch", fake_fetch)
    operator = {"Authorization": "Bearer operator-token"}

    def imported(classification, content, readers=None):
        response = client.post("/objects/import", headers=operator,
                               json={"classification": classification, "media_type": "text/plain",
                                     "content_base64": base64.b64encode(content.encode()).decode(),
                                     "readers": readers or ["agent-a"], "source": "test-fixture"})
        assert response.status_code == 200, response.text
        return response.json()["object_id"]

    objects = {
        "prompt": imported("public", "Answer from the supplied sources."),
        "public": imported("public", "Public source."),
        "internal": imported("internal", "Internal source."),
        "private": imported("private", "Private source."),
        "restricted": imported("restricted", "Restricted source."),
        "other_actor": imported("private", "Other actor source.", ["agent-b"]),
    }
    sessions = {name: substrate.create_session(name)["session_token"]
                for name in ("agent-a", "agent-b")}

    def propose(action, actor_id="agent-a"):
        headers = {"Authorization": f"Bearer {actor_id}-token",
                   "X-Session-Token": sessions[actor_id]}
        response = client.post("/proposals", headers=headers, json={"action": action})
        assert response.status_code == 200, response.text
        return response.json()

    def prepare(input_ids, actor_id="agent-a", **extra):
        return propose({"kind": "generation.prepare", "input_ids": input_ids, **extra}, actor_id)

    def finish(input_ids, text, actor_id="agent-a"):
        prepared = prepare(input_ids, actor_id)
        assert prepared["decision"] == "allow", prepared
        claimed = client.post("/generations/claim", headers=operator,
                              json={"generation_id": prepared["generation_id"]}).json()
        assert claimed["decision"] == "allow", claimed
        assert [source["id"] for source in claimed["inputs"]] == input_ids
        result = client.post("/generations/complete", headers=operator,
                             json={"generation_id": prepared["generation_id"], "text": text}).json()
        assert result["decision"] == "succeeded", result
        return result

    return substrate, client, db_path, objects, sessions, propose, prepare, finish, published


def test_public_context_generates_publishable_public_object(boundary):
    substrate, _, _, objects, _, propose, _, finish, published = boundary
    output = finish([objects["prompt"], objects["public"]], "A public answer.")
    assert output["classification"] == "public"
    assert output["parents"] == [objects["prompt"], objects["public"]]
    result = propose({"kind": "object.publish", "object_id": output["object_id"],
                      "destination": "http://127.0.0.1:9"})
    assert result["decision"] == "allow" and result["outcome"] == "succeeded"
    assert published == ["A public answer."]
    assert any(item["id"] == output["object_id"] and item["operation"] == "generate"
               for event in substrate.audit() if event["action"]["kind"] == "generation.complete"
               for item in event["state_after"]["objects"])


def test_private_context_blocks_generated_publication(boundary):
    _, _, _, objects, _, propose, _, finish, published = boundary
    output = finish([objects["prompt"], objects["private"]], "Rewritten private text.")
    assert output["classification"] == "private"
    assert output["parents"] == [objects["prompt"], objects["private"]]
    denied = propose({"kind": "object.publish", "object_id": output["object_id"],
                      "destination": "http://127.0.0.1:9"})
    assert denied["reason"] == "object_classification_blocks_egress" and not published


def test_mixed_context_has_exact_parents_and_highest_label(boundary):
    _, _, _, objects, _, propose, _, finish, _ = boundary
    output = finish([objects["public"], objects["private"]], "Combined answer.")
    assert output["classification"] == "private"
    assert output["parents"] == [objects["public"], objects["private"]]
    assert propose({"kind": "object.publish", "object_id": output["object_id"],
                    "destination": "http://127.0.0.1:9"})["decision"] == "deny"


def test_internal_context_generates_internal_output(boundary):
    _, _, _, objects, _, _, _, finish, _ = boundary
    output = finish([objects["internal"]], "Internal answer.")
    assert output["classification"] == "internal"
    assert output["parents"] == [objects["internal"]]


@pytest.mark.parametrize("text", ["Paraphrase.", "Encoded: c2VjcmV0", "Summary.", "Rewrite."])
def test_restricted_input_cannot_be_rewritten_public(boundary, text):
    _, _, _, objects, _, _, _, finish, _ = boundary
    output = finish([objects["restricted"]], text)
    assert output["classification"] == "restricted"
    assert output["parents"] == [objects["restricted"]]


def test_transformed_input_keeps_transitive_restriction(boundary):
    _, _, _, objects, _, propose, _, finish, _ = boundary
    child = propose({"kind": "object.transform", "object_id": objects["restricted"],
                     "operation": "base64"})
    assert child["classification"] == "restricted"
    output = finish([child["object_id"]], "Rewritten transform.")
    assert output["classification"] == "restricted"
    assert output["parents"] == [child["object_id"]]


def test_session_reset_preserves_existing_label_without_permanent_actor_taint(boundary):
    substrate, _, _, objects, sessions, propose, _, finish, _ = boundary
    private = finish([objects["private"]], "First answer.")
    sessions["agent-a"] = substrate.create_session("agent-a")["session_token"]
    assert propose({"kind": "object.read", "object_id": private["object_id"]})["classification"] == "private"
    public = finish([objects["public"]], "Clean answer.")
    assert public["classification"] == "public"
    assert public["parents"] == [objects["public"]]


def test_model_cannot_assign_provenance_or_submit_text_directly(boundary):
    substrate, client, _, objects, _, propose, prepare, _, _ = boundary
    assert propose({"kind": "object.generate", "content": "Unsealed text.",
                    "classification": "public"})["reason"] == "unknown_action"
    denied = prepare([objects["private"]], classification="public")
    assert denied["reason"] == "generation_fields_forbidden"
    prepared = prepare([objects["private"]])
    generation_id = prepared["generation_id"]
    assert client.post("/generations/claim", headers={"Authorization": "Bearer agent-a-token"},
                       json={"generation_id": generation_id}).status_code == 401
    assert client.post("/generations/claim", headers={"Authorization": "Bearer operator-token"},
                       json={"generation_id": generation_id}).json()["decision"] == "allow"
    rejected = client.post("/generations/complete",
                           headers={"Authorization": "Bearer operator-token"},
                           json={"generation_id": generation_id, "text": "Answer.",
                                 "classification": "public", "parents": [objects["public"]]})
    assert rejected.status_code == 422
    assert "Unsealed text." not in json.dumps(substrate.audit())


def test_operator_declassification_creates_publishable_child(boundary):
    substrate, client, _, objects, _, propose, _, finish, published = boundary
    original = finish([objects["private"]], "Reviewed release.")
    assert client.post("/objects/declassify", headers={"Authorization": "Bearer agent-a-token"},
                       json={"object_id": original["object_id"], "classification": "public",
                             "reason": "approved"}).status_code == 401
    result = client.post("/objects/declassify", headers={"Authorization": "Bearer operator-token"},
                         json={"object_id": original["object_id"], "classification": "public",
                               "reason": "human reviewed output"}).json()
    assert result["decision"] == "override" and result["parent_id"] == original["object_id"]
    assert propose({"kind": "object.read", "object_id": original["object_id"]})["classification"] == "private"
    assert propose({"kind": "object.read", "object_id": result["object_id"]})["classification"] == "public"
    assert propose({"kind": "object.publish", "object_id": result["object_id"],
                    "destination": "http://127.0.0.1:9"})["outcome"] == "succeeded"
    assert published == ["Reviewed release."]
    assert any(event["decision"] == "override" and
               event["policy"]["reason"] == "human reviewed output"
               for event in substrate.audit())


def test_clean_public_context_after_private_work_is_publishable(boundary):
    _, _, _, objects, _, propose, _, finish, published = boundary
    finish([objects["private"]], "Prior private answer.")
    output = finish([objects["prompt"], objects["public"]], "Public answer.")
    assert output["classification"] == "public"
    assert output["parents"] == [objects["prompt"], objects["public"]]
    assert propose({"kind": "object.publish", "object_id": output["object_id"],
                    "destination": "http://127.0.0.1:9"})["outcome"] == "succeeded"
    assert published == ["Public answer."]


def test_missing_or_inaccessible_inputs_fail_closed(boundary):
    _, _, _, objects, _, _, prepare, _, _ = boundary
    assert prepare([])["reason"] == "invalid_generation_inputs"
    assert prepare([objects["public"], objects["public"]])["reason"] == "invalid_generation_inputs"
    assert prepare(["0" * 32])["reason"] == "object_not_accessible"
    assert prepare([objects["other_actor"]])["reason"] == "object_not_accessible"


def test_extra_prompt_and_history_are_rejected(boundary):
    _, client, _, objects, _, _, prepare, _, _ = boundary
    assert prepare([objects["public"]], prompt="unmediated")["reason"] == "generation_fields_forbidden"
    assert prepare([objects["public"]], history=["private"])["reason"] == "generation_fields_forbidden"
    prepared = prepare([objects["public"]])
    operator = {"Authorization": "Bearer operator-token"}
    assert client.post("/generations/claim", headers=operator,
                       json={"generation_id": prepared["generation_id"],
                             "prompt": "unmediated"}).status_code == 422
    assert client.post("/generations/claim", headers=operator,
                       json={"generation_id": prepared["generation_id"]}).json()["decision"] == "allow"
    assert client.post("/generations/complete", headers=operator,
                       json={"generation_id": prepared["generation_id"], "text": "Answer.",
                             "history": ["private"]}).status_code == 422


def test_altered_sealed_manifest_is_detected(boundary):
    substrate, _, db_path, objects, _, _, prepare, _, _ = boundary
    prepared = prepare([objects["private"]])
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE generations SET classification='public' WHERE id=?",
                   (prepared["generation_id"],))
    denied = substrate.claim_generation(prepared["generation_id"])
    assert denied["decision"] == "deny" and denied["reason"] == "state_integrity"


def test_manifest_claim_and_completion_are_one_use(boundary):
    _, client, _, objects, _, _, prepare, _, _ = boundary
    prepared = prepare([objects["public"]])
    generation_id = prepared["generation_id"]
    operator = {"Authorization": "Bearer operator-token"}
    def post(path, body):
        return client.post(path, headers=operator, json=body).json()
    assert post("/generations/claim", {"generation_id": generation_id})["decision"] == "allow"
    assert post("/generations/claim", {"generation_id": generation_id})["decision"] == "deny"
    assert post("/generations/complete", {"generation_id": generation_id,
                                           "text": "Answer."})["decision"] == "succeeded"
    replay = post("/generations/complete", {"generation_id": generation_id,
                                             "text": "Changed answer."})
    assert replay["decision"] == "deny" and replay["reason"] == "generation_already_consumed"


def test_adapter_rejects_worker_supplied_provenance(boundary, monkeypatch):
    substrate, client, _, objects, _, _, prepare, _, _ = boundary
    prepared = prepare([objects["private"]])
    monkeypatch.setattr("generation_adapter.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps({
                            "text": "Answer.", "classification": "public"})))
    with pytest.raises(RuntimeError, match="extra or missing fields"):
        run_generation(client, prepared["generation_id"], "operator-token", ["unused"])
    assert not any(event["action"]["kind"] == "generation.complete"
                   for event in substrate.audit())
