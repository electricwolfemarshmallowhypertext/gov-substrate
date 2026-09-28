"""Provider-shaped fakes prove sealed context handoff without paid requests."""

import base64
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from generation_adapter import SealedInput, run_with_adapter
from hosted_generation_adapters import AnthropicTextAdapter, OpenAITextAdapter
from substrate import Substrate, create_app


class FakeOpenAI:
    def __init__(self):
        self.responses = self
        self.calls = []
        self.options = []

    def with_options(self, **options):
        self.options.append(options)
        return self

    def create(self, **request):
        self.calls.append(request)
        return SimpleNamespace(status="completed", output_text="The model says public.",
                               output=[SimpleNamespace(type="message", content=[
                                   SimpleNamespace(type="output_text")])])


class FakeAnthropic:
    def __init__(self):
        self.messages = self
        self.calls = []
        self.options = []

    def with_options(self, **options):
        self.options.append(options)
        return self

    def create(self, **request):
        self.calls.append(request)
        return SimpleNamespace(stop_reason="end_turn", content=[
            SimpleNamespace(type="text", text="The model says public.")])


@pytest.fixture
def boundary(tmp_path):
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "hosted-generation.db", {
        "actors": {"agent-a": actor}, "tokens": {"agent-token": "agent-a"},
        "operator_token": "operator-token"})
    client = TestClient(create_app(substrate))
    operator = {"Authorization": "Bearer operator-token"}
    agent = {"Authorization": "Bearer agent-token"}
    agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]

    def imported(classification, content, media_type="text/plain"):
        response = client.post("/objects/import", headers=operator, json={
            "classification": classification, "media_type": media_type,
            "content_base64": base64.b64encode(content).decode(),
            "readers": ["agent-a"], "source": "trusted-fixture"})
        assert response.status_code == 200
        return response.json()["object_id"]

    def prepare(input_ids):
        response = client.post("/proposals", headers=agent,
                               json={"action": {"kind": "generation.prepare",
                                                "input_ids": input_ids}}).json()
        assert response["decision"] == "allow", response
        return response["generation_id"]

    return client, imported, prepare


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_hosted_provider_inherits_sealed_classification_and_exact_parents(boundary, provider):
    client, imported, prepare = boundary
    prompt = imported("public", b"Answer using only these governed inputs.")
    private = imported("private", b"Private project detail.")
    public = imported("public", b"Public project detail.")
    sdk = FakeOpenAI() if provider == "openai" else FakeAnthropic()
    adapter = (OpenAITextAdapter(sdk, "explicit-openai-model", 128) if provider == "openai"
               else AnthropicTextAdapter(sdk, "explicit-anthropic-model", 128))

    private_output = run_with_adapter(client, prepare([prompt, private]),
                                      "operator-token", adapter)
    assert private_output["classification"] == "private"
    assert private_output["parents"] == [prompt, private]
    public_output = run_with_adapter(client, prepare([prompt, public]),
                                     "operator-token", adapter)
    assert public_output["classification"] == "public"
    assert public_output["parents"] == [prompt, public]
    assert sdk.options == [{"max_retries": 0}, {"max_retries": 0}]
    assert len(sdk.calls) == 2

    first = sdk.calls[0]
    if provider == "openai":
        assert first == {
            "model": "explicit-openai-model",
            "input": [{"role": "user", "content": [
                {"type": "input_text", "text": "Answer using only these governed inputs."},
                {"type": "input_text", "text": "Private project detail."}]}],
            "max_output_tokens": 128, "truncation": "disabled", "store": False}
    else:
        assert first == {
            "model": "explicit-anthropic-model", "max_tokens": 128,
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "Answer using only these governed inputs."},
                {"type": "text", "text": "Private project detail."}]}]}


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_unsupported_input_fails_before_provider_call(boundary, provider):
    client, imported, prepare = boundary
    image = imported("private", b"not an image", "image/png")
    sdk = FakeOpenAI() if provider == "openai" else FakeAnthropic()
    adapter = (OpenAITextAdapter(sdk, "model", 128) if provider == "openai"
               else AnthropicTextAdapter(sdk, "model", 128))
    with pytest.raises(RuntimeError, match="governed text only"):
        run_with_adapter(client, prepare([image]), "operator-token", adapter)
    assert sdk.calls == []


def test_unexpected_provider_action_never_completes(boundary):
    client, imported, prepare = boundary
    prompt = imported("private", b"Private governed context.")
    sdk = FakeOpenAI()
    sdk.create = lambda **request: SimpleNamespace(
        status="completed", output_text="untrusted text",
        output=[SimpleNamespace(type="function_call")])
    with pytest.raises(RuntimeError, match="unexpected action"):
        run_with_adapter(client, prepare([prompt]), "operator-token",
                         OpenAITextAdapter(sdk, "model", 128))


def test_incomplete_or_tool_response_is_rejected():
    inputs = (SealedInput("text/plain", b"Governed input."),)
    openai = FakeOpenAI()
    openai.create = lambda **request: SimpleNamespace(
        status="incomplete", output_text="partial",
        output=[SimpleNamespace(type="message", content=[
            SimpleNamespace(type="output_text")])])
    with pytest.raises(RuntimeError, match="did not complete"):
        OpenAITextAdapter(openai, "model", 128).generate(inputs)

    anthropic = FakeAnthropic()
    anthropic.create = lambda **request: SimpleNamespace(
        stop_reason="tool_use", content=[SimpleNamespace(type="tool_use")])
    with pytest.raises(RuntimeError, match="did not complete"):
        AnthropicTextAdapter(anthropic, "model", 128).generate(inputs)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_context_limit_prevents_provider_call(provider):
    sdk = FakeOpenAI() if provider == "openai" else FakeAnthropic()
    adapter = (OpenAITextAdapter(sdk, "model", 128, max_context_bytes=3)
               if provider == "openai" else
               AnthropicTextAdapter(sdk, "model", 128, max_context_bytes=3))
    with pytest.raises(RuntimeError, match="configured limit"):
        adapter.generate((SealedInput("text/plain", b"four"),))
    assert sdk.calls == []


def test_future_provider_uses_same_sealed_input_interface(boundary):
    client, imported, prepare = boundary
    prompt = imported("internal", b"One governed input.")

    class CustomProvider:
        def generate(self, inputs):
            assert inputs == (SealedInput("text/plain", b"One governed input."),)
            return "A generated answer."

    output = run_with_adapter(client, prepare([prompt]), "operator-token",
                              CustomProvider())
    assert output["classification"] == "internal"
    assert output["parents"] == [prompt]
