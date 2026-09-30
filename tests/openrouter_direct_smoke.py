"""Bounded OpenRouter replay of the Gemini governed scenarios.

The default invocation prints a plan without reading a key or making a request.
The opt-in --run mode sends at most two synthetic text requests from the host.
"""

import argparse
import base64
import json
import os
import sys
import tempfile
import threading
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generation_adapter import run_with_adapter
from hosted_generation_adapters import (OpenRouterClient, OpenRouterHTTPError,
                                        OpenRouterResponseError,
                                        OpenRouterTextAdapter)
from substrate import Substrate, create_app


MODEL = "z-ai/glm-5.2"
PROVIDER = "openrouter"
UPSTREAM = "z-ai"
MAX_OUTPUT_TOKENS = 2048
INPUT_RESERVE = 4096  # Estimate only; OpenRouter does not enforce this input cap.
INPUT_RATE = Decimal("1.40")
OUTPUT_RATE = Decimal("4.40")
MAX_REQUESTS = 2


class LocalPublisher(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        values = parse_qs(url.query).get("data")
        if url.path != "/publish" or not values:
            self.send_error(404)
            return
        self.server.received.append(values[0])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"stored")

    def log_message(self, *_args):
        pass


def boundary(db_path: Path, max_classification: str, origin: str):
    actor = {
        "data": {"sensitive_access": True},
        "network": {"allowed": True, "publication": True, "services": [
            {"origin": origin, "mode": "publication", "egress": "external",
             "paths": ["/publish"]}]},
        "filesystem": {"scopes": {
            "session": {"read": False, "write": False},
            "actor": {"read": False, "write": False},
            "shared": {"channels": []}}},
        "tools": {}, "persistence": {"session": True, "cross_session": False},
        "shared_channels": [],
    }
    substrate = Substrate(db_path, {
        "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
        "operator_token": "operator-token",
        "providers": {PROVIDER: {"max_classification": max_classification}}})
    client = TestClient(create_app(substrate))
    operator = {"Authorization": "Bearer operator-token"}
    agent = {"Authorization": "Bearer agent-token"}
    agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]

    def imported(classification: str, text: str):
        response = client.post("/objects/import", headers=operator, json={
            "classification": classification, "media_type": "text/plain",
            "content_base64": base64.b64encode(text.encode()).decode(),
            "readers": ["agent"], "source": "synthetic-openrouter-fixture"})
        assert response.status_code == 200
        return response.json()["object_id"]

    def propose(action: dict):
        response = client.post("/proposals", headers=agent, json={"action": action})
        assert response.status_code == 200
        return response.json()

    return substrate, client, imported, propose


def result_metadata(adapter: OpenRouterTextAdapter):
    usage = adapter.last_usage
    routing = adapter.last_routing
    assert type(usage) is dict, "OpenRouter did not report token usage"
    input_tokens = usage.get("prompt_tokens")
    output_tokens = usage.get("completion_tokens")
    assert all(type(value) is int and value >= 0
               for value in (input_tokens, output_tokens))
    assert input_tokens <= INPUT_RESERVE, "Observed input exceeded the estimate reserve"
    cost = usage.get("cost")
    assert type(cost) in (int, float) and cost >= 0, "OpenRouter did not report cost"
    selected = [item for item in routing["endpoints"]["available"]
                if item.get("selected") is True]
    assert len(selected) == 1
    reasoning = usage.get("completion_tokens_details", {}).get("reasoning_tokens", 0)
    assert type(reasoning) is int and reasoning >= 0
    return ({"input_tokens": input_tokens, "output_tokens": output_tokens,
             "reasoning_tokens": reasoning, "reported_cost_usd": str(cost)},
            selected[0]["provider"])


def plan():
    estimate = MAX_REQUESTS * (INPUT_RESERVE * INPUT_RATE +
                               MAX_OUTPUT_TOKENS * OUTPUT_RATE) / 1_000_000
    return {"model": MODEL, "provider": PROVIDER, "upstream": UPSTREAM,
            "routing": {"only": [UPSTREAM], "allow_fallbacks": False,
                        "data_collection": "deny", "zdr": True},
            "max_api_requests": MAX_REQUESTS,
            "max_output_tokens_per_request": MAX_OUTPUT_TOKENS,
            "input_token_reserve_per_request": INPUT_RESERVE,
            "estimated_max_cost_usd": str(estimate),
            "cost_limit": "Input reserve is an estimate, not a billing cap.",
            "scenarios": ["private_transfer_denied_before_api",
                          "private_generation_and_publication_denial",
                          "clean_public_generation_and_publication"]}


def failure_report(error, api_key: str | None):
    failure = {"result": "fail", "error_type": type(error).__name__}
    if isinstance(error, OpenRouterHTTPError):
        failure.update({"http_status": error.status_code,
                        "openrouter_error_message": error.message,
                        "openrouter_error_code": error.code,
                        "openrouter_error_type": error.error_type,
                        "openrouter_error_metadata": error.metadata})
    elif isinstance(error, OpenRouterResponseError):
        failure.update({"openrouter_response_failure": error.reason,
                        "openrouter_response_metadata": error.metadata})
    else:
        return failure
    if not api_key:
        failure["key_status"] = {"available": False, "reason": "key_absent"}
        return failure
    try:
        failure["key_status"] = OpenRouterClient(
            api_key, UPSTREAM).current_key_status()
    except OpenRouterHTTPError as status_error:
        failure["key_status"] = {"available": False,
                                 "http_status": status_error.status_code}
    except Exception as status_error:
        failure["key_status"] = {"available": False,
                                 "error_type": type(status_error).__name__}
    return failure


def run():
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is absent from this PowerShell session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalPublisher)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    requests = 0
    total_input = 0
    total_output = 0
    total_cost = Decimal("0")
    try:
        with tempfile.TemporaryDirectory(prefix=".pytest_tmp_openrouter_", dir=ROOT) as directory:
            base = Path(directory)
            denied_substrate, _, denied_import, denied_propose = boundary(
                base / "public-only.db", "public", origin)
            blocked_input = denied_import("private", "Synthetic private ticket: amber-17.")
            blocked = denied_propose({"kind": "generation.prepare",
                                      "input_ids": [blocked_input], "provider": PROVIDER})
            assert blocked["decision"] == "deny"
            assert blocked["reason"] == "provider_classification_denied"
            assert "generation_id" not in blocked
            assert denied_substrate.audit()[-1]["action"]["provider"] == PROVIDER
            print(json.dumps({"scenario": "private_transfer_denied_before_api",
                              "decision": "deny", "reason": blocked["reason"],
                              "api_requests": requests}))

            substrate, client, imported, propose = boundary(
                base / "private-approved.db", "private", origin)
            prompt = imported("public", "Reply in one short sentence using only these sources.")
            private = imported("private", "Synthetic private ticket: amber-17.")
            public = imported("public", "Public source: the sky is blue.")
            router = OpenRouterClient(api_key, UPSTREAM)

            private_run = propose({"kind": "generation.prepare",
                                   "input_ids": [prompt, private], "provider": PROVIDER})
            assert private_run["decision"] == "allow"
            private_adapter = OpenRouterTextAdapter(
                router, MODEL, MAX_OUTPUT_TOKENS, max_context_bytes=2048)
            requests += 1
            private_result = run_with_adapter(
                client, private_run["generation_id"], "operator-token",
                private_adapter, private_run["execution_token"])
            private_usage, private_upstream = result_metadata(private_adapter)
            total_input += private_usage["input_tokens"]
            total_output += private_usage["output_tokens"]
            total_cost += Decimal(private_usage["reported_cost_usd"])
            assert private_result["classification"] == "private"
            assert private_result["parents"] == [prompt, private]
            private_publish = propose({"kind": "object.publish",
                                       "object_id": private_result["object_id"],
                                       "destination": origin})
            assert private_publish["decision"] == "deny"
            assert private_publish["reason"] == "object_classification_blocks_egress"
            assert not server.received
            print(json.dumps({"scenario": "private_generation_and_publication_denial",
                              "generation": "succeeded", "classification": "private",
                              "publication": "deny", "parents": private_result["parents"],
                              "upstream": private_upstream, "usage": private_usage,
                              "api_requests": requests}))

            public_run = propose({"kind": "generation.prepare",
                                  "input_ids": [prompt, public], "provider": PROVIDER})
            assert public_run["decision"] == "allow"
            public_adapter = OpenRouterTextAdapter(
                router, MODEL, MAX_OUTPUT_TOKENS, max_context_bytes=2048)
            requests += 1
            public_result = run_with_adapter(
                client, public_run["generation_id"], "operator-token",
                public_adapter, public_run["execution_token"])
            public_usage, public_upstream = result_metadata(public_adapter)
            total_input += public_usage["input_tokens"]
            total_output += public_usage["output_tokens"]
            total_cost += Decimal(public_usage["reported_cost_usd"])
            assert public_result["classification"] == "public"
            assert public_result["parents"] == [prompt, public]
            public_publish = propose({"kind": "object.publish",
                                      "object_id": public_result["object_id"],
                                      "destination": origin})
            assert public_publish["decision"] == "allow"
            assert public_publish["outcome"] == "succeeded"
            assert len(server.received) == 1
            print(json.dumps({"scenario": "clean_public_generation_and_publication",
                              "generation": "succeeded", "classification": "public",
                              "publication": "succeeded", "parents": public_result["parents"],
                              "upstream": public_upstream, "usage": public_usage,
                              "api_requests": requests}))
            assert any(item["action"]["kind"] == "generation.complete"
                       for item in substrate.audit())
    finally:
        server.shutdown()
        server.server_close()
    print(json.dumps({"result": "pass", "model": MODEL, "api_requests": requests,
                      "input_tokens": total_input, "output_tokens": total_output,
                      "openrouter_reported_cost_usd": str(total_cost)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="Use OPENROUTER_API_KEY for two OpenRouter requests")
    args = parser.parse_args()
    print(json.dumps(plan(), indent=2))
    if args.run:
        try:
            run()
        except Exception as error:
            print(json.dumps(failure_report(
                error, os.getenv("OPENROUTER_API_KEY"))))
            raise SystemExit(1) from None
