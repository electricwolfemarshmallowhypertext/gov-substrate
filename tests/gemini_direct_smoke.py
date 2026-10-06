"""Bounded direct-Google replay of the sealed hosted-generation boundary.

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
from hosted_generation_adapters import (GeminiDeveloperClient, GeminiHTTPError,
                                        GeminiTextAdapter)
from substrate import Substrate, create_app


MODEL = "gemini-3.8-flash"
PROVIDER = "google-gemini"
MAX_OUTPUT_TOKENS = 256
INPUT_RESERVE = 4096  # Estimate only; Google does not enforce this input cap.
INPUT_RATE = Decimal("0.75")
OUTPUT_RATE = Decimal("3.75")
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
        "network": {"allowed": True, "publication": True,
                    "private_ip_origins": [origin], "services": [
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
            "readers": ["agent"], "source": "synthetic-gemini-fixture"})
        assert response.status_code == 200
        return response.json()["object_id"]

    def propose(action: dict):
        response = client.post("/proposals", headers=agent, json={"action": action})
        assert response.status_code == 200
        return response.json()

    return substrate, client, imported, propose


def token_usage(adapter: GeminiTextAdapter):
    usage = adapter.last_usage
    assert type(usage) is dict, "Google did not report token usage"
    input_tokens = usage.get("promptTokenCount")
    output_tokens = usage.get("candidatesTokenCount")
    thinking_tokens = usage.get("thoughtsTokenCount", 0)
    assert all(type(value) is int and value >= 0 for value in
               (input_tokens, output_tokens, thinking_tokens))
    assert input_tokens <= INPUT_RESERVE, "Observed input exceeded the estimate reserve"
    return {"input_tokens": input_tokens,
            "output_tokens": output_tokens + thinking_tokens,
            "thinking_tokens": thinking_tokens}


def plan():
    estimate = MAX_REQUESTS * (INPUT_RESERVE * INPUT_RATE +
                               MAX_OUTPUT_TOKENS * OUTPUT_RATE) / 1_000_000
    return {"model": MODEL, "provider": PROVIDER, "max_api_requests": MAX_REQUESTS,
            "max_output_tokens_per_request": MAX_OUTPUT_TOKENS,
            "input_token_reserve_per_request": INPUT_RESERVE,
            "estimated_max_cost_usd": str(estimate),
            "estimate_limit": "Input reserve is not a server-side billing cap.",
            "scenarios": ["private_transfer_denied_before_api",
                          "private_generation_and_publication_denial",
                          "clean_public_generation_and_publication"]}


def run():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is absent from this PowerShell session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalPublisher)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    requests = 0
    total_input = 0
    total_output = 0
    try:
        with tempfile.TemporaryDirectory(prefix=".pytest_tmp_gemini_", dir=ROOT) as directory:
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
            provider = GeminiDeveloperClient(api_key)

            private_run = propose({"kind": "generation.prepare",
                                   "input_ids": [prompt, private], "provider": PROVIDER})
            assert private_run["decision"] == "allow"
            private_adapter = GeminiTextAdapter(provider, MODEL, MAX_OUTPUT_TOKENS,
                                                max_context_bytes=2048)
            requests += 1
            private_result = run_with_adapter(
                client, private_run["generation_id"], "operator-token",
                private_adapter, private_run["execution_token"])
            private_usage = token_usage(private_adapter)
            total_input += private_usage["input_tokens"]
            total_output += private_usage["output_tokens"]
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
                              "usage": private_usage, "api_requests": requests}))

            public_run = propose({"kind": "generation.prepare",
                                  "input_ids": [prompt, public], "provider": PROVIDER})
            assert public_run["decision"] == "allow"
            public_adapter = GeminiTextAdapter(provider, MODEL, MAX_OUTPUT_TOKENS,
                                               max_context_bytes=2048)
            requests += 1
            public_result = run_with_adapter(
                client, public_run["generation_id"], "operator-token",
                public_adapter, public_run["execution_token"])
            public_usage = token_usage(public_adapter)
            total_input += public_usage["input_tokens"]
            total_output += public_usage["output_tokens"]
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
                              "usage": public_usage, "api_requests": requests}))
            assert any(item["action"]["kind"] == "generation.complete"
                       for item in substrate.audit())
    finally:
        server.shutdown()
        server.server_close()
    charge = (Decimal(total_input) * INPUT_RATE +
              Decimal(total_output) * OUTPUT_RATE) / 1_000_000
    print(json.dumps({"result": "pass", "model": MODEL, "api_requests": requests,
                      "input_tokens": total_input, "output_tokens": total_output,
                      "calculated_standard_cost_usd": str(charge)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="Use GEMINI_API_KEY for two direct Google API requests")
    args = parser.parse_args()
    print(json.dumps(plan(), indent=2))
    if args.run:
        try:
            run()
        except Exception as error:
            failure = {"result": "fail", "error_type": type(error).__name__}
            if isinstance(error, GeminiHTTPError):
                failure["http_status"] = error.status_code
            print(json.dumps(failure))
            raise SystemExit(1) from None
