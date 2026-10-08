"""Classified-object provenance, publication, and declassification rules."""

import base64
import json
import sqlite3

from fastapi.testclient import TestClient

from governance_substrate.substrate import Substrate, create_app


IMAGE = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlFE0YAAAAASUVORK5CYII=")


def test_same_actor_public_summary_and_private_image(tmp_path):
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
    substrate = Substrate(tmp_path / "objects.db", {
        "actors": {"agent-a": actor}, "tokens": {"agent-secret": "agent-a"},
        "operator_token": "operator-secret"})
    client = TestClient(create_app(substrate))
    operator = {"Authorization": "Bearer operator-secret"}
    agent = {"Authorization": "Bearer agent-secret"}

    def imported(classification, media_type, payload):
        response = client.post("/objects/import", headers=operator, json={
            "classification": classification, "media_type": media_type,
            "content_base64": base64.b64encode(payload).decode(),
            "readers": ["agent-a"], "source": "trusted-fixture"})
        assert response.status_code == 200, response.text
        return response.json()["object_id"]

    image_id = imported("private", "image/png", IMAGE)
    public_id = imported("public", "text/plain", b"The sky is blue. This is public context.")
    private_text_id = imported("private", "text/plain", b"PRIVATE_SENTINEL")
    internal_id = imported("internal", "text/plain", b"internal")
    restricted_id = imported("restricted", "text/plain", b"restricted")
    agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]

    def propose(action):
        response = client.post("/proposals", headers=agent, json={"action": action})
        assert response.status_code == 200, response.text
        return response.json()

    read = propose({"kind": "object.read", "object_id": image_id})
    assert read["classification"] == "private"
    assert base64.b64decode(read["content_base64"]) == IMAGE
    encoded = propose({"kind": "object.transform", "object_id": image_id,
                       "operation": "base64"})
    assert encoded["classification"] == "private" and encoded["parents"] == [image_id]
    for object_id in (image_id, encoded["object_id"], private_text_id,
                      internal_id, restricted_id):
        denied = propose({"kind": "object.publish", "object_id": object_id,
                          "destination": "http://127.0.0.1:9"})
        assert denied["reason"] == "object_classification_blocks_egress"
        assert "outcome_event_id" not in denied

    summary = propose({"kind": "object.transform", "object_id": public_id,
                       "operation": "summary"})
    assert summary["classification"] == "public" and summary["parents"] == [public_id]
    allowed = propose({"kind": "object.publish", "object_id": summary["object_id"],
                       "destination": "http://127.0.0.1:9"})
    assert allowed["decision"] == "allow" and allowed["outcome"] == "failed"

    assert propose({"kind": "object.create", "classification": "public",
                    "content": "PRIVATE_SENTINEL"})["reason"] == "unknown_action"
    assert client.post("/objects/declassify", headers=agent, json={
        "object_id": private_text_id, "classification": "public", "reason": "bypass"}).status_code == 401
    refused = client.post("/objects/declassify", headers=operator, json={
        "object_id": private_text_id, "classification": "public", "reason": ""}).json()
    assert refused["reason"] == "declassification_reason_required"
    approved = client.post("/objects/declassify", headers=operator, json={
        "object_id": private_text_id, "classification": "public",
        "reason": "approved local release"}).json()
    assert approved["decision"] == "override" and approved["parent_id"] == private_text_id
    assert propose({"kind": "object.publish", "object_id": approved["object_id"],
                    "destination": "http://127.0.0.1:9"})["decision"] == "allow"
    audit = substrate.audit()
    assert "PRIVATE_SENTINEL" not in json.dumps(audit)
    assert any(event["decision"] == "override" and
               event["policy"]["rule"] == "human_declassification"
               for event in audit)


def test_object_payload_corruption_fails_closed(tmp_path):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    db_path = tmp_path / "tamper.db"
    substrate = Substrate(db_path, {
        "actors": {"agent-a": actor}, "tokens": {"agent-secret": "agent-a"},
        "operator_token": "operator-secret"})
    imported = substrate.import_object("private", "text/plain",
                                       base64.b64encode(b"private").decode(),
                                       ["agent-a"], "trusted-fixture")
    session = substrate.create_session("agent-a")["session_token"]
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TRIGGER objects_no_update")
        db.execute("UPDATE objects SET payload=? WHERE id=?",
                   (b"corrupted", imported["object_id"]))
    denied = substrate.propose("agent-a", session,
                               {"kind": "object.read", "object_id": imported["object_id"]})
    assert denied["decision"] == "deny" and denied["reason"] == "state_integrity"
    assert substrate.health()["legibility"] == 0.0
