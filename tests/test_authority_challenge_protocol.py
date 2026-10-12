"""Unit checks for protocol evidence retention. No model or runtime proof."""

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_challenge import OpenRouterAgent, call_for_action
from openrouter_profiles import PROFILES


@pytest.mark.parametrize("reply", ["final", "tool", "batch", "wrong_model"])
def test_native_response_is_saved_before_protocol_validation(tmp_path, reply):
    profile = PROFILES["glm"]
    key = "unit-test-credential-never-log"
    path = tmp_path / "trace.jsonl"
    agent = OpenRouterAgent(key, profile, trace_path=path)
    call = {"id": "call_1", **call_for_action(
        {"kind": "network.request", "url": "http://127.0.0.1:1234/seed"})}
    message = {"role": "assistant", "content": "I need the record."}
    if reply in ("tool", "batch"):
        calls = [{**call, "id": f"call_{i}"} for i in range(4 if reply == "batch" else 1)]
        message.update(content=None, tool_calls=calls)
    response = {"id": "response_1", "model": profile.model if reply != "wrong_model" else "wrong",
                "choices": [{"finish_reason": "tool_calls" if reply in ("tool", "batch") else "stop",
                             "message": message}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 10, "cost": 0.001},
                "openrouter_metadata": {"requested": profile.model, "endpoints": {
                    "available": [{"selected": True, "provider": "Z.AI"}]}}}

    class Opener:
        def open(self, request, timeout):
            body = json.loads(request.data)
            assert body["tool_choice"] == "auto"
            assert body["tools"]
            return io.StringIO(json.dumps(response))

    agent.transport._opener = Opener()
    if reply == "wrong_model":
        with pytest.raises(RuntimeError, match="provider_model_mismatch"):
            agent.ask([{"role": "user", "content": "Read the record."}], require_tool=False)
    else:
        action, terminal, _ = agent.ask(
            [{"role": "user", "content": "Read the record."}], require_tool=False)
        assert terminal == ("tool_call" if reply in ("tool", "batch") else "model_final")
        assert (action is not None) == (reply in ("tool", "batch"))
        if reply in ("tool", "batch"):
            assert len(action) == len(calls)
    saved = path.read_text(encoding="utf-8")
    assert key not in saved
    evidence = json.loads(saved)
    assert evidence["request_messages"] == [{"role": "user", "content": "Read the record."}]
    assert evidence["message"]["content"] == message["content"]
    assert evidence["message"]["tool_calls"] == message.get("tool_calls")
    assert evidence["finish_reason"] == response["choices"][0]["finish_reason"]
