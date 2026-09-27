import sqlite3

import pytest
from fastapi.testclient import TestClient

from substrate import Substrate, create_app


@pytest.fixture
def system(tmp_path):
    def actor(channels=()):
        return {
            "network": {"allowed": False},
            "filesystem": {"read": True, "write": "workspace_only"},
            "tools": {"shell": True, "external_api": False},
            "persistence": {"session": True, "cross_session": False},
            "shared_channels": list(channels),
        }

    db_path = tmp_path / "substrate.db"
    substrate = Substrate(db_path, {
        "actors": {"agent-a": actor(["approved"]), "agent-b": actor()},
        "tokens": {"agent-a-secret": "agent-a", "agent-b-secret": "agent-b"},
        "operator_token": "human-secret",
    })
    client = TestClient(create_app(substrate))

    def headers(name="agent-a", session=None):
        token = "agent-a-secret" if name == "agent-a" else "agent-b-secret"
        result = {"Authorization": f"Bearer {token}"}
        if session:
            result["X-Session-Token"] = session
        return result

    return substrate, client, db_path, headers


def new_session(client, headers, name="agent-a"):
    response = client.post("/sessions", headers=headers(name))
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    return response.json()["session_token"]


def propose(client, headers, session, action, name="agent-a"):
    response = client.post("/proposals", headers=headers(name, session), json={"action": action})
    assert response.status_code == 200
    return response.json()


def test_admitted_transition_and_attributable_log(system):
    substrate, client, _, headers = system
    session = new_session(client, headers)
    action = {"kind": "state.write", "scope": "session", "key": "note", "value": "ok"}
    result = propose(client, headers, session, action)
    assert result["decision"] == "allow"
    read = propose(client, headers, session, {"kind": "state.read", "scope": "session", "key": "note"})
    assert read["value"] == "ok"
    event = substrate.audit()[result["event_id"] - 1]
    assert event["actor"] == "agent-a"
    assert event["policy"]["rule"] == "capability_granted"
    assert event["state_before"] != event["state_after"]
    assert substrate.health()["legibility"] == 1.0


def test_network_policy_blocks_reachable_underlay(system):
    substrate, client, _, headers = system
    session = new_session(client, headers)
    # Reachability outside this process does not grant an API capability.
    result = propose(client, headers, session, {"kind": "network.request", "url": "https://example.org"})
    assert result["decision"] == "deny"
    assert result["reason"] == "network_disabled"
    assert substrate.audit()[-1]["state_before"] == substrate.audit()[-1]["state_after"]


def test_hidden_cross_session_memory_is_not_readable(system):
    _, client, _, headers = system
    old_session = new_session(client, headers)
    propose(client, headers, old_session, {"kind": "state.write", "scope": "session", "key": "secret", "value": 7})
    new_session_token = new_session(client, headers)
    stale = propose(client, headers, old_session, {"kind": "state.read", "scope": "session", "key": "secret"})
    assert stale["reason"] == "invalid_session"
    fresh = propose(client, headers, new_session_token,
                    {"kind": "state.read", "scope": "session", "key": "secret"})
    assert fresh["decision"] == "allow" and fresh["value"] is None
    persistent = propose(client, headers, new_session_token,
                         {"kind": "state.read", "scope": "persistent", "key": "secret"})
    assert persistent["decision"] == "deny"


def test_credential_scope_expansion_is_denied(system):
    _, client, _, headers = system
    session = new_session(client, headers)
    result = propose(client, headers, session,
                     {"kind": "credential.expand", "requested_scope": "admin"})
    assert result["reason"] == "credential_scope_fixed"


def test_cross_agent_state_requires_explicit_shared_channel(system):
    _, client, _, headers = system
    a = new_session(client, headers)
    b = new_session(client, headers, "agent-b")
    write = propose(client, headers, a,
                    {"kind": "state.write", "scope": "shared", "channel": "approved", "key": "x", "value": 1})
    assert write["decision"] == "allow"
    read = propose(client, headers, b,
                   {"kind": "state.read", "scope": "shared", "channel": "approved", "key": "x"}, "agent-b")
    assert read["reason"] == "shared_channel_disabled"
    hidden = propose(client, headers, a,
                     {"kind": "state.write", "scope": "shared", "channel": "hidden", "key": "x", "value": 2})
    assert hidden["decision"] == "deny"


def test_corrupted_state_fails_closed_and_is_logged(system):
    substrate, client, db_path, headers = system
    session = new_session(client, headers)
    propose(client, headers, session,
            {"kind": "state.write", "scope": "session", "key": "balance", "value": 1})
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE state SET value='999' WHERE key='balance'")
    result = propose(client, headers, session,
                     {"kind": "state.write", "scope": "session", "key": "approved", "value": 1})
    assert result["decision"] == "deny" and result["reason"] == "state_integrity"
    assert substrate.health()["legibility"] == 0.0
    assert not any(row["key"] == "approved" for row in substrate.audit()[-1]["state_after"]["state"])


def test_override_is_authenticated_one_shot_and_append_only(system):
    substrate, client, db_path, headers = system
    session = new_session(client, headers)
    denied = propose(client, headers, session,
                     {"kind": "state.write", "scope": "persistent", "key": "plan", "value": "v1"})
    assert denied["decision"] == "escalate"
    body = {"event_id": denied["event_id"], "reason": "approved for this one write"}
    assert client.post("/overrides", headers=headers(), json=body).status_code == 401
    rejected = client.post("/overrides", headers={"Authorization": "Bearer human-secret"},
                           json={"event_id": denied["event_id"], "reason": ""})
    assert rejected.json()["reason"] == "override_reason_required"
    assert substrate.audit()[-1]["decision"] == "deny"
    response = client.post("/overrides", headers={"Authorization": "Bearer human-secret"}, json=body)
    assert response.status_code == 200
    assert response.json()["override_of"] == denied["event_id"]
    repeated = client.post("/overrides", headers={"Authorization": "Bearer human-secret"}, json=body)
    assert repeated.json()["reason"] == "already_overridden"
    event = substrate.audit()[-2]
    assert event["actor"] == "human-operator"
    assert event["override_of"] == denied["event_id"]
    assert event["policy"]["reason"] == body["reason"]
    with sqlite3.connect(db_path) as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM events WHERE id=?", (event["id"],))
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE events SET decision='allow' WHERE id=?", (event["id"],))
    assert substrate.health()["plasticity_seconds"] is not None


def test_audit_tampering_blocks_further_actions(system):
    _, client, db_path, headers = system
    session = new_session(client, headers)
    with sqlite3.connect(db_path) as db:
        db.execute("DROP TRIGGER events_no_update")
        db.execute("UPDATE events SET decision='deny' WHERE id=1")
    response = client.post("/proposals", headers=headers(session=session), json={
        "action": {"kind": "state.write", "scope": "session", "key": "x", "value": 1}})
    assert response.status_code == 503


def test_unlogged_registry_change_fails_closed(system):
    substrate, client, db_path, headers = system
    session = new_session(client, headers)
    changed = {
        "actors": {key: {**value} for key, value in substrate.actors.items()},
        "tokens": substrate.tokens,
        "operator_token": substrate.operator_token,
    }
    changed["actors"]["agent-a"] = {
        **changed["actors"]["agent-a"], "network": {"allowed": True}}
    restarted = TestClient(create_app(Substrate(db_path, changed)))
    response = restarted.post("/proposals", headers=headers(session=session), json={
        "action": {"kind": "state.write", "scope": "session", "key": "x", "value": 1}})
    assert response.status_code == 503
