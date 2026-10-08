"""Deterministic host-driver checks; the real Google run is separate evidence."""

import importlib.util
import io
import json
from pathlib import Path

from hosted_generation_adapters import GeminiDeveloperClient


def load_driver():
    path = Path(__file__).with_name("gemini_direct_smoke.py")
    spec = importlib.util.spec_from_file_location("gemini_direct_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_direct_client_sends_only_sealed_parts_to_google(monkeypatch):
    requests = []

    class FakeOpener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return io.BytesIO(b'{"candidates": []}')

    monkeypatch.setattr("hosted_generation_adapters.build_opener",
                        lambda *_handlers: FakeOpener())
    client = GeminiDeveloperClient("fixture-key")
    result = client.generate_content(
        "gemini-3.8-flash", [{"role": "user", "parts": [{"text": "governed"}]}],
        {"candidateCount": 1, "maxOutputTokens": 256})
    assert result == {"candidates": []}
    assert len(requests) == 1
    request, timeout = requests[0]
    assert request.full_url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.8-flash:generateContent")
    assert request.headers["X-goog-api-key"] == "fixture-key"
    assert timeout == 45
    assert json.loads(request.data) == {
        "contents": [{"role": "user", "parts": [{"text": "governed"}]}],
        "generationConfig": {"candidateCount": 1, "maxOutputTokens": 256}}


def test_bounded_driver_follows_governed_path_with_fake_model(monkeypatch, capsys):
    driver = load_driver()
    calls = []

    class FakeGemini:
        def __init__(self, api_key):
            assert api_key == "fixture-key"

        def generate_content(self, **request):
            calls.append(request)
            return {"candidates": [{"finishReason": "STOP", "content": {
                "parts": [{"text": "Synthetic generated answer."}]}}],
                "usageMetadata": {"promptTokenCount": 40,
                                  "candidatesTokenCount": 6, "totalTokenCount": 46}}

    monkeypatch.setenv("GEMINI_API_KEY", "fixture-key")
    monkeypatch.setattr(driver, "GeminiDeveloperClient", FakeGemini)
    driver.run()
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row["scenario"] for row in rows[:-1]] == [
        "private_transfer_denied_before_api",
        "private_generation_and_publication_denial",
        "clean_public_generation_publication_hold"]
    assert rows[0]["api_requests"] == 0
    assert rows[1]["classification"] == "private" and rows[1]["publication"] == "deny"
    assert rows[2]["classification"] == "public" and rows[2]["publication"] == "deny"
    assert rows[2]["reason"] == "object_release_required"
    assert rows[-1]["result"] == "pass" and rows[-1]["api_requests"] == 2
    assert len(calls) == 2
