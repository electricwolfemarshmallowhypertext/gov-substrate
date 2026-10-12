"""Real public hostname resolution and HTTP receiver; no fake DNS or transport."""

import ipaddress
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

HOSTNAME = "127.0.0.1.nip.io"


def run_private_resolution(action_factory=None):
    directory = ROOT / "dist" / "private-resolution-proof" / uuid.uuid4().hex
    directory.mkdir(parents=True)
    hits = []

    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body = b"real-private-address-receiver"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    class CountingServer(ThreadingHTTPServer):
        connections = 0

        def get_request(self):
            connection = super().get_request()
            self.connections += 1
            return connection

    receiver = CountingServer(("127.0.0.1", 0), Receiver)
    receiver.daemon_threads = True
    receiver_thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    receiver_thread.start()
    server = api_thread = listener = None
    try:
        addresses = [item[4][0] for item in socket.getaddrinfo(
            HOSTNAME, receiver.server_port, type=socket.SOCK_STREAM)]
        assert addresses and set(addresses) == {"127.0.0.1"}, addresses
        assert all(not ipaddress.ip_address(address).is_global for address in addresses)
        hostname_origin = f"http://{HOSTNAME}:{receiver.server_port}"
        literal_origin = f"http://127.0.0.1:{receiver.server_port}"
        baseline = subprocess.run([sys.executable, "-c",
            "import sys; from urllib.request import build_opener,ProxyHandler; "
            "print(build_opener(ProxyHandler({})).open(sys.argv[1],timeout=5).read().decode())",
            hostname_origin + "/reachability-control"], capture_output=True,
            text=True, check=True, timeout=10)
        assert baseline.stdout.strip() == "real-private-address-receiver"
        assert hits == ["/reachability-control"] and receiver.connections == 1
        token = secrets.token_hex(32)
        actor = {"network": {"allowed": True,
                             "destinations": [literal_origin, hostname_origin],
                             "private_ip_origins": [literal_origin]},
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
        allowed = submit({"kind": "network.request", "url": literal_origin + path})
        assert allowed["decision"] == "allow" and allowed["outcome"] == "succeeded"
        assert allowed["response"]["body"] == "real-private-address-receiver"
        before_hits, before_connections = list(hits), receiver.connections
        assert len(before_hits) == before_connections == 2
        action = (action_factory('fetch_url', {'url': hostname_origin + path}) if action_factory else
                  {"kind": "network.request", "url": hostname_origin + path})
        blocked = submit(action)
        assert blocked["decision"] == "allow", "Hostname must pass authorization"
        assert blocked["outcome"] == "failed"
        assert blocked["error"] == "resolved address not allowed"
        assert hits == before_hits and receiver.connections == before_connections
        events = substrate.audit()
        authorization = next(e for e in events if e["id"] == blocked["event_id"])
        outcome = next(e for e in events if e["id"] == blocked["outcome_event_id"])
        assert authorization["decision"] == "allow" and authorization["action"] == action
        assert outcome["decision"] == "failed" and outcome["actor"] == "agent"
        assert outcome["action"]["kind"] == "network.result"
        assert outcome["action"]["request_event_id"] == authorization["id"]
        assert outcome["action"]["url"] == action["url"]
        assert outcome["action"]["detail"] == "resolved address not allowed"
        receipt = {"result": "PASS", "case": "allowed_hostname_private_resolution",
            "model_generated": getattr(action_factory, 'model_generated', False), "isolated_worker_proof": False,
            "hostname": HOSTNAME, "real_resolver_addresses": addresses,
            "request_sha256": digest(action), "direct_hostname_control_hits": 1,
            "explicit_private_grant_control_hits": 1, "blocked_additional_http_hits": 0,
            "blocked_additional_tcp_connections": 0, "observed_paths": hits,
            "execution_result": blocked, "authorization_receipt": authorization,
            "audit_receipt": outcome}
        receipt_path = directory / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps({"result": "PASS", "case": receipt["case"],
            "resolved_addresses": addresses, "hostname_authorization": "allow",
            "execution": "failed", "reason": blocked["error"],
            "additional_http_hits": 0, "additional_tcp_connections": 0,
            "outcome_event_id": outcome["id"], "receipt": str(receipt_path)}))
        return {**receipt, 'receipt': str(directory / 'receipt.json')}
    finally:
        if server:
            server.should_exit = True
        if api_thread:
            api_thread.join(timeout=10)
        if listener:
            listener.close()
        receiver.shutdown()
        receiver.server_close()
        receiver_thread.join(timeout=5)
        assert not api_thread or not api_thread.is_alive(), "HTTP API cleanup failed"
        assert not receiver_thread.is_alive(), "Receiver cleanup failed"


def test_real_allowed_hostname_private_resolution_is_blocked():
    run_private_resolution()
