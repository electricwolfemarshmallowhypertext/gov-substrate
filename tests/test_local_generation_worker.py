"""The local inference worker accepts no context outside sealed text inputs."""

import base64
import json

import pytest

from governance_substrate.local_generation_worker import parse_context


def envelope(text="Governed prompt."):
    return {"inputs": [{"media_type": "text/plain",
                        "content_base64": base64.b64encode(text.encode()).decode()}]}


def test_worker_accepts_only_governed_text():
    assert parse_context(json.dumps(envelope()).encode()) == "Governed prompt."


@pytest.mark.parametrize("extra", [
    {"prompt": "unmediated instruction"},
    {"history": [{"role": "user", "content": "earlier conversation"}]},
    {"environment": {"EXTRA_CONTEXT": "host data"}},
    {"file_path": "/workspace/.hidden"},
])
def test_worker_rejects_extra_context_fields(extra):
    request = envelope()
    request.update(extra)
    with pytest.raises(ValueError, match="sealed inputs"):
        parse_context(json.dumps(request).encode())


def test_worker_rejects_context_inserted_into_input():
    request = envelope()
    request["inputs"][0]["history"] = "earlier conversation"
    with pytest.raises(ValueError, match="unmediated context"):
        parse_context(json.dumps(request).encode())


def test_worker_rejects_unsupported_or_oversized_context():
    request = envelope()
    request["inputs"][0]["media_type"] = "application/json"
    with pytest.raises(ValueError, match="governed text only"):
        parse_context(json.dumps(request).encode())
    with pytest.raises(ValueError, match="exceeds worker limit"):
        parse_context(b"x" * 32_769)
