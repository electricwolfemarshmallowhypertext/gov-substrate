"""Actual HTTP clients/receivers and substrate: deny an ungranted origin."""

import json
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import uvicorn

from governance_substrate.substrate import Substrate, create_app, digest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_tool_enforcement import CLIENT


def run_network_destination(action_factory=None):
    directory = ROOT / "dist" / "network-destination-proof" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    receivers, receiver_threads, hits = [], [], {"allowed": [], "forbidden": []}
    server = None
    api_thread = None
    listener = None
    try:
        def handler(name):
            class Receiver(BaseHTTPRequestHandler):
                def do_GET(self):
                    hits[name].append(self.path)
                    body = (name + "-real-receiver").encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_):
                    pass
            return Receiver

        origins = {}
        for name in hits:
            receiver = ThreadingHTTPServer(("127.0.0.1", 0), handler(name))
            receiver.daemon_threads = True
            thread = threading.Thread(target=receiver.serve_forever, daemon=True)
            receivers.append(receiver)
            receiver_threads.append(thread)
            thread.start()
            origins[name] = f"http://127.0.0.1:{receiver.server_port}"

        # Independently prove the forbidden receiver is live and reachable.
        baseline = subprocess.run([sys.executable, "-c",
            "import sys; from urllib.request import build_opener,ProxyHandler; "
            "print(build_opener(ProxyHandler({})).open(sys.argv[1],timeout=5).read().decode())",
            origins["forbidden"] + "/reachability-control"], capture_output=True,
            text=True, check=True, timeout=10)
        assert baseline.stdout.strip() == "forbidden-real-receiver"
        assert hits["forbidden"] == ["/reachability-control"]
        token = secrets.token_hex(32)
        actor = {"network": {"allowed": True, "destinations": [origins["allowed"]],
                             "private_ip_origins": [origins["allowed"]]},
                 "filesystem": {"read": False, "write": False}, "tools": {},
                 "persistence": {"session": True, "cross_session": False},
                 "shared_channels": [], "data": {"sensitive_access": False}}
        substrate = Substrate(directory / "substrate.db", {
            "actors": {"agent": actor}, "tokens": {token: "agent"},
            "operator_token": secrets.token_hex(32)})
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        api_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(create_app(substrate), log_level="error"))
        api_thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        api_thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            assert api_thread.is_alive() and time.monotonic() < deadline, "HTTP API did not start"
            time.sleep(0.01)

        def submit(action):
            client = subprocess.run([sys.executable, "-c", CLIENT],
                input=json.dumps({"url": api_url, "token": token, "action": action}),
                text=True, capture_output=True, check=True, timeout=15)
            return json.loads(client.stdout)

        path = "/attempt/" + uuid.uuid4().hex
        allowed_action = {"kind": "network.request", "url": origins["allowed"] + path}
        allowed = submit(allowed_action)
        assert allowed["decision"] == "allow" and allowed["outcome"] == "succeeded"
        assert allowed["response"]["body"] == "allowed-real-receiver"
        assert hits["allowed"] == [path]
        forbidden_before = list(hits["forbidden"])
        denied_action = (action_factory('fetch_url', {'url': origins['forbidden'] + path}) if action_factory else
                         {"kind": "network.request", "url": origins["forbidden"] + path})
        denied = submit(denied_action)
        assert denied["decision"] == "deny" and denied["reason"] == "destination_not_allowed"
        assert hits["forbidden"] == forbidden_before
        assert hits["allowed"] == [path]
        events = substrate.audit()
        event = next(e for e in events if e["id"] == denied["event_id"])
        assert event["actor"] == "agent" and event["decision"] == "deny"
        assert event["action"] == denied_action
        assert not any(e["action"].get("request_event_id") == event["id"] for e in events)
        receipt = {"result": "PASS", "case": "denied_network_destination",
            "evidence_kind": "real_HTTP_mediated_network_enforcement",
            "model_generated": getattr(action_factory, 'model_generated', False), "isolated_worker_proof": False,
            "request_sha256": digest(denied_action), "allowed_receiver_hits": 1,
            "forbidden_receiver_reachability_hits": 1,
            "forbidden_receiver_additional_hits": 0,
            "observed_paths": hits, "denial": denied, "audit_receipt": event}
        receipt_path = directory / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps({"result": "PASS", "case": "denied_network_destination",
            "allowed_receiver_hits": 1, "forbidden_receiver_reachability_hits": 1,
            "forbidden_receiver_additional_hits": 0,
            "denial_event_id": event["id"], "receipt": str(receipt_path)}))
        return {**receipt, 'receipt': str(directory / 'receipt.json')}
    finally:
        if server:
            server.should_exit = True
        if api_thread:
            api_thread.join(timeout=10)
        if listener:
            listener.close()
        for receiver, thread in zip(receivers, receiver_threads):
            receiver.shutdown()
            receiver.server_close()
            thread.join(timeout=5)
        assert not api_thread or not api_thread.is_alive(), "HTTP API cleanup failed"
        assert all(not thread.is_alive() for thread in receiver_threads), "Receiver cleanup failed"


def test_real_network_destination_denial_has_no_receiver_effect():
    run_network_destination()
