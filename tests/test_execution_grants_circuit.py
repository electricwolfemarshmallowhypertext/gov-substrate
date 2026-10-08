"""One-use execution grants and operator-only emergency stops."""

import base64
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from governance_substrate.generation_adapter import run_with_adapter
from governance_substrate.hosted_generation_adapters import OpenAITextAdapter
from governance_substrate.runtime_supervisor import StopResult
from governance_substrate.substrate import Substrate, create_app


@pytest.fixture
def boundary(tmp_path):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    stopped_workers = []

    class FakeRuntime:
        def run(self, generation_id, sealed_context):
            raise AssertionError("fixture does not run a worker")

        def stop(self, generation_ids):
            stopped_workers.extend(generation_ids)
            return tuple(StopResult(run_id, "fake", run_id, True, "stopped")
                         for run_id in generation_ids)

        def reconcile(self):
            return ()

    substrate = Substrate(tmp_path / "grants.db", {
        "actors": {"a": actor, "b": actor},
        "tokens": {"a-token": "a", "b-token": "b"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token",
        "providers": {"openai": {"max_classification": "private"}}},
        runtime_supervisor=FakeRuntime())
    client = TestClient(create_app(substrate))

    def headers(actor_id):
        return {"Authorization": f"Bearer {actor_id}-token"}

    sessions = {actor_id: client.post("/sessions", headers=headers(actor_id)).json()
                for actor_id in ("a", "b")}

    def request(path, actor_id, action, token=None):
        body = {"action": action}
        if token is not None:
            body["execution_token"] = token
        return client.post(path, headers={**headers(actor_id),
                                          "X-Session-Token": sessions[actor_id]["session_token"]},
                           json=body).json()

    def imported(classification="public"):
        result = client.post("/objects/import", headers={"Authorization": "Bearer adapter-token"},
                             json={"classification": classification, "media_type": "text/plain",
                                   "content_base64": base64.b64encode(b"Governed input").decode(),
                                   "readers": ["a"], "source": "fixture"}).json()
        assert result["decision"] == "allow"
        return result["object_id"]

    return substrate, client, sessions, request, imported, stopped_workers


def test_grant_is_opaque_bound_one_use_and_audited(boundary):
    substrate, _, sessions, request, _, _ = boundary
    action = {"kind": "state.write", "scope": "session", "key": "x", "value": 1}
    granted = request("/authorizations", "a", action)
    token = granted["execution_token"]
    assert granted["decision"] == "allow" and len(token) >= 32
    assert token not in str(substrate.audit())
    assert any(event["action"]["kind"] == "execution.grant.issue"
               for event in substrate.audit())
    assert request("/executions", "b", action, token)["reason"] == "execution_grant_binding_mismatch"
    assert request("/executions", "a", {**action, "value": 2}, token)["reason"] == "execution_grant_binding_mismatch"
    assert request("/executions", "a", action, token + "x")["reason"] == "execution_grant_invalid"
    executed = request("/executions", "a", action, token)
    assert executed["decision"] == "allow"
    assert request("/executions", "a", action, token)["reason"] == "execution_grant_reused"
    sessions["a"] = substrate.create_session("a")
    assert request("/executions", "a", action, token)["reason"] == "execution_grant_reused"
    uses = [event for event in substrate.audit() if event["action"]["kind"] == "execution.grant.use"]
    assert sum(event["decision"] == "allow" for event in uses) == 1


def test_expired_and_wrong_session_grants_fail(boundary, monkeypatch):
    substrate, _, sessions, request, _, _ = boundary
    action = {"kind": "state.write", "scope": "session", "key": "x", "value": 1}
    old = request("/authorizations", "a", action)["execution_token"]
    sessions["a"] = substrate.create_session("a")
    assert request("/executions", "a", action, old)["reason"] == "execution_grant_binding_mismatch"
    token = request("/authorizations", "a", action)["execution_token"]
    import governance_substrate.substrate as module
    now = module.time.time()
    monkeypatch.setattr(module.time, "time", lambda: now + 121)
    assert request("/executions", "a", action, token)["reason"] == "execution_grant_expired"


def test_manifest_provider_and_capability_binding_precede_model_call(boundary):
    substrate, client, _, request, imported, _ = boundary
    object_id = imported("private")
    prepared = request("/proposals", "a", {"kind": "generation.prepare",
                                           "input_ids": [object_id], "provider": "openai"})
    assert prepared["decision"] == "allow"
    sdk = SimpleNamespace(calls=[], responses=None)
    sdk.responses = sdk
    sdk.with_options = lambda **_: sdk
    def fake_create(**kwargs):
        sdk.calls.append(kwargs)
        return SimpleNamespace(status="completed", output_text="Answer", output=[
            SimpleNamespace(type="message", content=[SimpleNamespace(type="output_text")])])
    sdk.create = fake_create
    operator = {"Authorization": "Bearer adapter-token"}
    wrong = client.post("/generations/claim", headers=operator, json={
        "generation_id": prepared["generation_id"],
        "execution_token": prepared["execution_token"], "provider": "anthropic"}).json()
    assert wrong["decision"] == "deny" and sdk.calls == []
    altered = client.post("/generations/claim", headers=operator, json={
        "generation_id": "0" * 32, "execution_token": prepared["execution_token"],
        "provider": "openai"}).json()
    assert altered["decision"] == "deny" and sdk.calls == []
    output = run_with_adapter(client, prepared["generation_id"], "adapter-token",
                              OpenAITextAdapter(sdk, "fake", 16),
                              prepared["execution_token"])
    assert len(sdk.calls) == 1 and output["classification"] == "private"
    assert output["parents"] == [object_id]
    assert client.post("/generations/claim", headers=operator, json={
        "generation_id": prepared["generation_id"],
        "execution_token": prepared["execution_token"],
        "provider": "openai"}).json()["decision"] == "deny"
    assert any(event["action"]["kind"] == "execution.grant.use" and
               event["action"]["provider"] == "openai" and event["decision"] == "allow"
               for event in substrate.audit())


def test_global_trigger_revokes_sessions_tokens_claims_and_logs_shutdown(boundary):
    substrate, client, _, request, imported, stopped_workers = boundary
    token = request("/authorizations", "a", {"kind": "state.write", "scope": "session",
                                               "key": "x", "value": 1})["execution_token"]
    prepared = request("/proposals", "a", {"kind": "generation.prepare",
                                            "input_ids": [imported()]})
    assert prepared["decision"] == "allow"
    with pytest.raises(PermissionError):
        substrate.set_circuit("adapter-token", "global", "*", True, "incident")
    assert client.post("/circuit", headers={"Authorization": "Bearer a-token"}).status_code == 404
    trip = substrate.set_circuit("control-token", "global", "*", True, "incident")
    assert prepared["generation_id"] in stopped_workers
    audit = substrate.audit()
    trigger = next(event for event in audit if event["id"] == trip["event_id"])
    receipt_event = next(event for event in audit if event["id"] == trip["receipt_event_id"])
    receipt = receipt_event["action"]["receipt"]
    assert receipt_event["action"]["trigger_event_id"] == trigger["id"]
    assert receipt_event["decision"] == "succeeded"
    assert receipt["what"]["state"] == "tripped"
    assert receipt["what"]["shutdown_confirmed"] is True
    assert receipt["what"]["revoked"]["execution_grants"] >= 2
    assert receipt["what"]["revoked"]["generations"] == 1
    assert receipt["what"]["revoked"]["sessions"] == 2
    assert receipt["when"]["triggered_at"] == trigger["timestamp"]
    assert receipt["when"]["shutdown_recorded_at"] >= trigger["timestamp"]
    assert receipt["how"]["initiator"] == "circuit-operator"
    assert receipt["how"]["runtime_control"] == "supervisor"
    assert receipt["where"]["scope"] == "global"
    assert receipt["where"]["target"] == "*"
    assert receipt["where"]["workers"][0]["generation_id"] == prepared["generation_id"]
    assert receipt["why"] == {"reason": "incident", "detection_event_id": None}
    assert request("/executions", "a", {"kind": "state.write", "scope": "session",
                                                "key": "x", "value": 1}, token)["decision"] == "deny"
    assert client.post("/generations/claim", headers={"Authorization": "Bearer adapter-token"},
                       json={"generation_id": prepared["generation_id"],
                             "execution_token": prepared["execution_token"]}).json()["decision"] == "deny"
    assert substrate.create_session("a")["reason"] == "capability_unavailable"
    kinds = [event["action"]["kind"] for event in substrate.audit()]
    assert "circuit.trigger" in kinds and "circuit.shutdown" in kinds
    substrate.set_circuit("control-token", "global", "*", False, "operator reset")
    assert substrate.create_session("a")["decision"] == "allow"
    assert substrate.audit()[-2]["action"]["kind"] == "circuit.reset"


def test_actor_capability_and_provider_stops_are_scoped(boundary):
    substrate, client, _, request, imported, _ = boundary
    substrate.set_circuit("control-token", "actor", "a", True, "stop a")
    assert request("/proposals", "a", {"kind": "state.read", "scope": "session",
                                        "key": "x"})["reason"] in ("capability_unavailable", "invalid_session")
    assert request("/proposals", "b", {"kind": "state.write", "scope": "session",
                                        "key": "x", "value": 1})["decision"] == "allow"
    substrate.set_circuit("control-token", "actor", "a", False, "reset a")
    fresh = substrate.create_session("a")
    assert fresh["decision"] == "allow"
    substrate.set_circuit("control-token", "capability", "state", True, "stop state")
    assert substrate.propose("a", fresh["session_token"], {"kind": "state.write",
                            "scope": "session", "key": "y", "value": 2})["reason"] == "capability_unavailable"
    substrate.set_circuit("control-token", "capability", "state", False, "reset state")
    fresh = substrate.create_session("a")
    object_id = imported()
    substrate.set_circuit("control-token", "provider", "openai", True, "stop provider")
    blocked = substrate.propose("a", fresh["session_token"], {
        "kind": "generation.prepare", "input_ids": [object_id], "provider": "openai"})
    assert blocked["reason"] == "capability_unavailable"
    local = substrate.propose("a", fresh["session_token"], {
        "kind": "generation.prepare", "input_ids": [object_id]})
    assert local["decision"] == "allow"


def test_trigger_between_network_admission_and_fetch_blocks_outbound(tmp_path, monkeypatch):
    actor = {"network": {"allowed": True, "destinations": ["http://127.0.0.1:9"]},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "network-stop.db", {
        "actors": {"a": actor}, "tokens": {"a-token": "a"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token"})
    session = substrate.create_session("a")["session_token"]
    fetches = []
    monkeypatch.setattr("governance_substrate.substrate.fetch", lambda *args: fetches.append(args))
    original_check = substrate._external_execution_open

    def trip_then_check(actor_id, session_token):
        substrate.set_circuit("control-token", "global", "*", True, "incident")
        return original_check(actor_id, session_token)

    monkeypatch.setattr(substrate, "_external_execution_open", trip_then_check)
    result = substrate.propose("a", session, {"kind": "network.request",
                                               "url": "http://127.0.0.1:9/"})
    assert result["decision"] == "allow" and result["outcome"] == "failed"
    assert result["error"] == "capability_unavailable" and not fetches


def test_unwired_shutdown_is_audited_as_unconfirmed(tmp_path):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    registry = {
        "actors": {"a": actor}, "tokens": {"a-token": "a"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token"}
    db_path = tmp_path / "unwired.db"
    substrate = Substrate(db_path, registry)
    session = substrate.create_session("a")["session_token"]
    imported = substrate.import_object("public", "text/plain",
                                       base64.b64encode(b"prompt").decode(), ["a"], "fixture")
    prepared = substrate.propose("a", session, {"kind": "generation.prepare",
                                               "input_ids": [imported["object_id"]]})
    assert prepared["decision"] == "allow"
    result = substrate.set_circuit("control-token", "global", "*", True, "incident")
    assert result["shutdown_confirmed"] is False
    event = substrate.audit()[-1]
    assert event["action"]["kind"] == "circuit.shutdown"
    assert event["decision"] == "failed"
    assert event["action"]["results"][0]["state"] == "stop_unconfirmed"
    assert event["action"]["trip_to_shutdown_ms"] is None
    assert event["action"]["receipt"]["what"]["shutdown_confirmed"] is False
    assert event["action"]["receipt"]["where"]["workers"][0]["runtime"] == "unwired"
    assert event["action"]["receipt"]["how"]["runtime_control"] == "unwired"
    with pytest.raises(ValueError, match="unconfirmed"):
        substrate.set_circuit("control-token", "global", "*", False, "unsafe reset")

    class ReconciledRuntime:
        def reconcile(self):
            return ()

        def stop(self, generation_ids):
            return ()

        def run(self, generation_id, sealed_context):
            raise AssertionError("no run expected")

    restarted = Substrate(db_path, registry, runtime_supervisor=ReconciledRuntime())
    assert restarted.audit()[-1]["action"]["kind"] == "runtime.reconcile"
    assert restarted.set_circuit("control-token", "global", "*", False,
                                 "verified empty runtime")["decision"] == "allow"


def test_restart_reconciliation_revokes_orphan_claim_and_grant(tmp_path):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    registry = {"actors": {"a": actor}, "tokens": {"a-token": "a"},
                "operator_token": "adapter-token"}
    db_path = tmp_path / "restart.db"
    original = Substrate(db_path, registry)
    session = original.create_session("a")["session_token"]
    imported = original.import_object("public", "text/plain",
                                      base64.b64encode(b"prompt").decode(), ["a"], "fixture")
    prepared = original.propose("a", session, {"kind": "generation.prepare",
                                            "input_ids": [imported["object_id"]]})

    class RecoveredRuntime:
        def reconcile(self):
            return (StopResult(prepared["generation_id"], "fake", "orphan", True,
                               "stopped"),)

        def stop(self, generation_ids):
            return ()

        def run(self, generation_id, sealed_context):
            raise AssertionError("no run expected")

    restarted = Substrate(db_path, registry, runtime_supervisor=RecoveredRuntime())
    assert restarted.audit()[-1]["action"]["kind"] == "runtime.reconcile"
    denied = restarted.claim_generation(prepared["generation_id"],
                                        prepared["execution_token"])
    assert denied["decision"] == "deny"
