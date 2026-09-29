"""Provider transfer grants are decided and audited before hosted execution."""

import base64
import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from generation_adapter import run_with_adapter
from hosted_generation_adapters import OpenAITextAdapter
from substrate import IntegrityError, Substrate, create_app


class FakeOpenAI:
    def __init__(self):
        self.responses = self
        self.calls = []

    def with_options(self, **options):
        assert options == {"max_retries": 0}
        return self

    def create(self, **request):
        self.calls.append(request)
        return SimpleNamespace(status="completed", output_text="A governed answer.",
                               output=[SimpleNamespace(type="message", content=[
                                   SimpleNamespace(type="output_text")])])


def boundary(tmp_path, providers):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    registry = {"actors": {"agent-a": actor}, "tokens": {"agent-token": "agent-a"},
                "operator_token": "operator-token", "providers": providers}
    substrate = Substrate(tmp_path / "transfer.db", registry)
    client = TestClient(create_app(substrate))
    operator = {"Authorization": "Bearer operator-token"}
    agent = {"Authorization": "Bearer agent-token"}
    agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]

    def imported(classification, content):
        response = client.post("/objects/import", headers=operator, json={
            "classification": classification, "media_type": "text/plain",
            "content_base64": base64.b64encode(content).decode(),
            "readers": ["agent-a"], "source": "trusted-fixture"})
        assert response.status_code == 200
        return response.json()["object_id"]

    def prepare(ids, provider=None):
        action = {"kind": "generation.prepare", "input_ids": ids}
        if provider is not None:
            action["provider"] = provider
        response = client.post("/proposals", headers=agent, json={"action": action})
        assert response.status_code == 200
        return response.json()

    return substrate, client, registry, imported, prepare


def test_public_to_approved_openai_is_allowed_and_audited(tmp_path):
    substrate, client, _, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "public"}})
    object_id = imported("public", b"Public governed context.")
    admitted = prepare([object_id], "openai")
    assert admitted["decision"] == "allow"
    event = substrate.audit()[-1]
    assert event["decision"] == "allow"
    assert event["action"]["provider"] == "openai"
    assert event["action"]["input_ids"] == [object_id]
    assert event["action"]["input_hashes"] == [
        hashlib.sha256(b"Public governed context.").hexdigest()]
    assert event["action"]["classification"] == "public"
    sdk = FakeOpenAI()
    output = run_with_adapter(client, admitted["generation_id"], "operator-token",
                              OpenAITextAdapter(sdk, "model", 128), admitted["execution_token"])
    assert len(sdk.calls) == 1
    assert output["classification"] == "public" and output["parents"] == [object_id]


def test_private_to_public_only_provider_denied_before_api(tmp_path):
    substrate, _, _, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "public"}})
    object_id = imported("private", b"Private governed context.")
    sdk = FakeOpenAI()
    denied = prepare([object_id], "openai")
    assert denied["decision"] == "deny"
    assert denied["reason"] == "provider_classification_denied"
    assert "generation_id" not in denied and sdk.calls == []
    event = substrate.audit()[-1]
    assert event["decision"] == "deny"
    assert event["action"]["provider"] == "openai"
    assert event["action"]["input_ids"] == [object_id]
    assert event["action"]["input_hashes"] == [
        hashlib.sha256(b"Private governed context.").hexdigest()]
    assert event["action"]["classification"] == "private"


def test_private_to_explicit_private_provider_allowed(tmp_path):
    _, client, _, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "private"}})
    object_id = imported("private", b"Private governed context.")
    admitted = prepare([object_id], "openai")
    sdk = FakeOpenAI()
    output = run_with_adapter(client, admitted["generation_id"], "operator-token",
                              OpenAITextAdapter(sdk, "model", 128), admitted["execution_token"])
    assert len(sdk.calls) == 1
    assert output["classification"] == "private" and output["parents"] == [object_id]


def test_restricted_to_unapproved_provider_denied(tmp_path):
    _, _, _, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "private"}})
    object_id = imported("restricted", b"Restricted governed context.")
    denied = prepare([object_id], "openai")
    assert denied["decision"] == "deny"
    assert denied["reason"] == "provider_classification_denied"


def test_unknown_provider_denied_by_default(tmp_path):
    _, _, _, imported, prepare = boundary(tmp_path, {})
    object_id = imported("public", b"Public governed context.")
    denied = prepare([object_id], "unknown-provider")
    assert denied["decision"] == "deny"
    assert denied["reason"] == "provider_unregistered"


def test_local_adapter_needs_no_external_transfer_grant(tmp_path):
    _, client, _, imported, prepare = boundary(tmp_path, {})
    object_id = imported("restricted", b"Restricted governed context.")
    admitted = prepare([object_id])
    assert admitted["decision"] == "allow" and admitted["provider"] is None

    class LocalAdapter:
        service_id = None

        def generate(self, inputs):
            assert inputs[0].content == b"Restricted governed context."
            return "Local output."

    output = run_with_adapter(client, admitted["generation_id"], "operator-token",
                              LocalAdapter(), admitted["execution_token"])
    assert output["classification"] == "restricted"


def test_hosted_adapter_cannot_claim_local_or_other_provider_run(tmp_path):
    substrate, client, _, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "public"}})
    object_id = imported("public", b"Public governed context.")
    local = prepare([object_id])
    sdk = FakeOpenAI()
    with pytest.raises(RuntimeError, match="could not be claimed"):
        run_with_adapter(client, local["generation_id"], "operator-token",
                         OpenAITextAdapter(sdk, "model", 128), local["execution_token"])
    assert sdk.calls == []
    assert substrate.audit()[-1]["policy"]["rule"] == "generation_provider_mismatch"


def test_provider_policy_change_requires_audited_migration(tmp_path):
    substrate, _, registry, imported, prepare = boundary(
        tmp_path, {"openai": {"max_classification": "public"}})
    registry["providers"]["openai"]["max_classification"] = "private"
    private_id = imported("private", b"Still private to the provider.")
    assert prepare([private_id], "openai")["reason"] == "provider_classification_denied"
    changed = Substrate(substrate.db_path, registry)
    with pytest.raises(IntegrityError, match="capability registry changed"):
        changed.audit()
