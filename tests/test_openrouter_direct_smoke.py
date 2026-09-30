"""Deterministic OpenRouter driver checks; the paid run is separate evidence."""

import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from generation_adapter import SealedInput
from hosted_generation_adapters import (OpenRouterClient, OpenRouterHTTPError,
                                        OpenRouterResponseError,
                                        OpenRouterTextAdapter)


def load_driver():
    path = Path(__file__).with_name("openrouter_direct_smoke.py")
    spec = importlib.util.spec_from_file_location("openrouter_direct_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(provider="Z.AI", model="z-ai/glm-5.2"):
    return {"id": "gen-fixture", "model": model,
            "choices": [{"finish_reason": "stop", "message": {
                "role": "assistant", "content": "Synthetic generated answer."}}],
            "usage": {"prompt_tokens": 40, "completion_tokens": 6,
                      "total_tokens": 46, "cost": 0.00002,
                      "completion_tokens_details": {"reasoning_tokens": 2}},
            "openrouter_metadata": {"requested": model, "attempt": 1,
                "endpoints": {"total": 1, "available": [
                    {"model": model, "provider": provider,
                     "selected": True}]}}}


def test_direct_client_pins_model_provider_and_privacy(monkeypatch):
    requests = []

    class FakeOpener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return io.BytesIO(json.dumps(response()).encode())

    monkeypatch.setattr("hosted_generation_adapters.build_opener",
                        lambda *_handlers: FakeOpener())
    client = OpenRouterClient("fixture-key", "z-ai")
    result = client.chat_completion(
        "z-ai/glm-5.2", [{"role": "user", "content": [
            {"type": "text", "text": "governed"}]}], 256)
    assert result["model"] == "z-ai/glm-5.2"
    assert len(requests) == 1
    request, timeout = requests[0]
    assert request.full_url == "https://openrouter.ai/api/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer fixture-key"
    assert request.headers["X-openrouter-metadata"] == "enabled"
    assert timeout == 45
    assert json.loads(request.data) == {
        "model": "z-ai/glm-5.2",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "governed"}]}],
        "max_completion_tokens": 256,
        "stream": False,
        "provider": {"only": ["z-ai"], "allow_fallbacks": False,
                     "data_collection": "deny", "zdr": True}}


def test_direct_client_can_record_non_zdr_pinned_provider(monkeypatch):
    requests = []

    class FakeOpener:
        def open(self, request, timeout):
            requests.append(request)
            return io.BytesIO(json.dumps(response("xAI", "x-ai/grok-4.7")).encode())

    monkeypatch.setattr("hosted_generation_adapters.build_opener",
                        lambda *_handlers: FakeOpener())
    client = OpenRouterClient("fixture-key", "xai", zdr=False)
    client.chat_completion(
        "x-ai/grok-4.7", [{"role": "user", "content": "governed"}], 2048)
    provider = json.loads(requests[0].data)["provider"]
    assert provider == {"only": ["xai"], "allow_fallbacks": False,
                        "data_collection": "deny", "zdr": False}


def test_adapter_fails_closed_if_router_selects_other_upstream():
    class WrongRoute:
        upstream_provider = "z-ai"

        def chat_completion(self, **_request):
            return response("Unexpected Provider")

    with pytest.raises(OpenRouterResponseError) as caught:
        OpenRouterTextAdapter(WrongRoute(), "z-ai/glm-5.2", 256).generate(
            (SealedInput("text/plain", b"Governed input."),))
    assert caught.value.reason == "pinned_upstream_not_confirmed"
    assert caught.value.metadata["selected_providers"] == ["Unexpected Provider"]


def test_openrouter_error_is_sanitized_and_key_status_is_limited(monkeypatch):
    error_body = {"error": {"code": 402, "type": "payment_required",
        "message": "Key sk-or-v1-secret hit its limit",
        "metadata": {"limit_source": "openrouter_key_limit",
                     "prompt": "private governed content",
                     "authorization": "Bearer sk-or-v1-secret"}}}

    class ErrorOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 402, "Payment Required", {},
                            io.BytesIO(json.dumps(error_body).encode()))

    monkeypatch.setattr("hosted_generation_adapters.build_opener",
                        lambda *_handlers: ErrorOpener())
    with pytest.raises(OpenRouterHTTPError) as caught:
        OpenRouterClient("fixture-key", "z-ai").chat_completion(
            "z-ai/glm-5.2", [{"role": "user", "content": "governed"}], 256)
    error = caught.value
    assert error.status_code == 402 and error.code == 402
    assert error.error_type == "payment_required"
    assert error.message == "Key [REDACTED] hit its limit"
    assert error.metadata == {"limit_source": "openrouter_key_limit"}

    driver = load_driver()

    class KeyStatusClient:
        def __init__(self, api_key, upstream_provider, zdr=True):
            assert api_key == "fixture-key" and upstream_provider == "z-ai"
            assert zdr is True

        def current_key_status(self):
            return {"available": True, "spending_limit_configured": True,
                    "limit_usd": 1, "limit_remaining_usd": 0,
                    "limit_reset": "monthly"}

    monkeypatch.setattr(driver, "OpenRouterClient", KeyStatusClient)
    report = driver.failure_report(error, "fixture-key")
    encoded = json.dumps(report)
    assert report["key_status"]["limit_remaining_usd"] == 0
    assert "private governed content" not in encoded
    assert "sk-or-v1-secret" not in encoded

    response_error = OpenRouterResponseError(
        "non_normal_finish", {"finish_reason": "length",
                              "content": "must-not-be-reported"})
    response_report = driver.failure_report(response_error, "fixture-key")
    assert response_report["openrouter_response_failure"] == "non_normal_finish"
    assert response_report["openrouter_response_metadata"] == {
        "finish_reason": "length"}
    assert response_report["key_status"]["limit_remaining_usd"] == 0


def test_current_key_status_reports_limit_without_key_identity(monkeypatch):
    class KeyOpener:
        def open(self, request, timeout):
            assert request.full_url == "https://openrouter.ai/api/v1/key"
            assert timeout == 15
            return io.BytesIO(json.dumps({"data": {
                "label": "must-not-be-returned", "limit": 5,
                "limit_remaining": 4.75, "limit_reset": "monthly"}}).encode())

    monkeypatch.setattr("hosted_generation_adapters.build_opener",
                        lambda *_handlers: KeyOpener())
    status = OpenRouterClient("fixture-key", "z-ai").current_key_status()
    assert status == {"available": True, "spending_limit_configured": True,
                      "limit_usd": 5, "limit_remaining_usd": 4.75,
                      "limit_reset": "monthly"}


@pytest.mark.parametrize(
    "profile_name,model,upstream,reported_provider,zdr,retention,estimate",
    [("glm", "z-ai/glm-5.2", "z-ai", "Z.AI", True,
      "zero retention", "0.0294912"),
     ("grok", "x-ai/grok-4.7", "xai", "xAI", False,
      "30 days", "0.04096"),
     ("kimi", "moonshotai/kimi-k3", "moonshotai", "Moonshot AI", True,
      "zero retention", "0.086016")])
def test_bounded_driver_follows_same_governed_path_with_fake_model(
        monkeypatch, capsys, profile_name, model, upstream, reported_provider,
        zdr, retention, estimate):
    driver = load_driver()
    profile = driver.PROFILES[profile_name]
    planned = driver.plan(profile)
    assert planned["model"] == model
    assert planned["upstream"] == upstream
    assert planned["routing"] == {
        "only": [upstream], "allow_fallbacks": False,
        "data_collection": "deny", "zdr": zdr,
        "provider_retention": retention}
    assert planned["max_output_tokens_per_request"] == 2048
    assert planned["estimated_max_cost_usd"] == estimate
    calls = []

    class FakeOpenRouter:
        def __init__(self, api_key, upstream_provider, requested_zdr):
            assert api_key == "fixture-key"
            assert upstream_provider == upstream
            assert requested_zdr is zdr
            self.upstream_provider = upstream_provider

        def chat_completion(self, **request):
            calls.append(request)
            return response(reported_provider, model)

    monkeypatch.setenv("OPENROUTER_API_KEY", "fixture-key")
    monkeypatch.setattr(driver, "OpenRouterClient", FakeOpenRouter)
    driver.run(profile)
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["scenario"] for row in rows[:-1]] == [
        "private_transfer_denied_before_api",
        "private_generation_and_publication_denial",
        "clean_public_generation_and_publication"]
    assert rows[0]["api_requests"] == 0
    assert rows[1]["classification"] == "private" and rows[1]["publication"] == "deny"
    assert rows[2]["classification"] == "public" and rows[2]["publication"] == "succeeded"
    assert rows[1]["upstream"] == reported_provider
    assert rows[2]["upstream"] == reported_provider
    assert rows[-1]["result"] == "pass" and rows[-1]["api_requests"] == 2
    assert len(calls) == 2
    assert all(call["max_completion_tokens"] == 2048 for call in calls)
