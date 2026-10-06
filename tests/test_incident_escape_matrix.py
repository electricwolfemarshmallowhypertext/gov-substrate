"""Incident-derived policy checks that do not require an external model."""

import base64
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import network_adapter
from substrate import Substrate


def actor(*, sensitive=False):
    return {
        "data": {"sensitive_access": sensitive},
        "network": {"allowed": True, "services": [
            {"origin": "http://127.0.0.1:9", "mode": "terminal",
             "egress": "internal", "paths": ["/safe"]},
            {"origin": "http://relay:8001", "mode": "delegated"},
            {"origin": "http://127.0.0.1:10", "mode": "publication",
             "egress": "external", "paths": ["/publish"]},
        ], "publication": True},
        "filesystem": {"scopes": {
            "session": {"read": True, "write": True},
            "actor": {"read": True, "write": True},
            "shared": {"read": False, "write": False, "channels": []},
        }},
        "tools": {}, "persistence": {"session": True, "cross_session": False},
        "shared_channels": [],
    }


@pytest.fixture
def boundary(tmp_path):
    substrate = Substrate(tmp_path / "incident.db", {
        "actors": {"agent-a": actor(sensitive=True), "agent-b": actor()},
        "tokens": {"a-token": "agent-a", "b-token": "agent-b"},
        "operator_token": "operator-token", "circuit_operator_token": "control-token",
    })
    sessions = {name: substrate.create_session(name)["session_token"]
                for name in ("agent-a", "agent-b")}
    return substrate, sessions


def test_network_request_rejects_exfiltration_fields_and_url_ambiguity(boundary):
    substrate, sessions = boundary
    allowed = {"kind": "network.request", "url": "http://127.0.0.1:9/safe"}
    assert substrate.propose("agent-b", sessions["agent-b"], allowed,
                             authorize_only=True)["decision"] == "allow"

    for field, value in (
        ("headers", {"X-Private": "PRIVATE_SENTINEL"}),
        ("callback", "http://attacker.invalid/PRIVATE_SENTINEL"),
        ("telemetry", "PRIVATE_SENTINEL"),
        ("tool_arguments", {"secret": "PRIVATE_SENTINEL"}),
    ):
        denied = substrate.propose("agent-b", sessions["agent-b"],
                                   {**allowed, field: value}, authorize_only=True)
        assert denied["reason"] == "invalid_network_request"

    urls = (
        "http://127.0.0.1:9/safe?data=PRIVATE_SENTINEL",
        "http://127.0.0.1:9/safe/../safe",
        "http://user:pass@127.0.0.1:9/safe",
        "http://127.0.0.1:9/safe#PRIVATE_SENTINEL",
        "http://127.0.0.1.evil.invalid:9/safe",
        "http://[::1]:9/safe",
        "file:///etc/passwd",
    )
    for url in urls:
        denied = substrate.propose("agent-b", sessions["agent-b"],
                                   {"kind": "network.request", "url": url},
                                   authorize_only=True)
        assert denied["decision"] == "deny"

    assert "PRIVATE_SENTINEL" not in json.dumps(substrate.audit())


def test_nonpublic_reader_cannot_use_raw_egress_or_shared_channels(tmp_path):
    reader = actor()
    reader["network"] = {"allowed": True, "destinations": ["https://example.com"]}
    reader["shared_channels"] = ["messages"]
    reader["filesystem"]["scopes"]["shared"] = {
        "read": True, "write": True, "channels": ["messages"]}
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    substrate = Substrate(tmp_path / "reader.db", {
        "actors": {"reader": reader}, "tokens": {"reader-token": "reader"},
        "operator_token": "operator-token"}, workspace_root=workspace)
    session = substrate.create_session("reader")["session_token"]
    raw = {"kind": "network.request", "url": "https://example.com/private-value"}
    shared = {"kind": "state.write", "scope": "shared", "channel": "messages",
              "key": "message", "value": "private-value"}
    shared_file = {"kind": "filesystem.write", "scope": "shared",
                   "channel": "messages", "path": "message.txt", "content": "private-value"}
    for action in (raw, shared):
        result = substrate.propose("reader", session, action, authorize_only=True)
        assert result["decision"] == "allow", (action["kind"], result)

    private = substrate.import_object("private", "text/plain",
                                      base64.b64encode(b"private-value").decode(),
                                      ["reader"], "fixture")
    assert substrate.propose("reader", session, {"kind": "object.read",
                                                   "object_id": private["object_id"]})["decision"] == "allow"
    assert substrate.propose("reader", session, raw, authorize_only=True)["reason"] == "sensitive_external_egress_disabled"
    assert substrate.propose("reader", session, shared)["reason"] == "sensitive_shared_write_disabled"
    assert substrate.propose("reader", session, shared_file)["reason"] == "sensitive_shared_write_disabled"
    new_session = substrate.create_session("reader")["session_token"]
    assert substrate.propose("reader", new_session, raw, authorize_only=True)["decision"] == "deny"


def test_delegation_reachability_and_stale_authority_fail_closed(boundary):
    substrate, sessions = boundary
    delegated = substrate.propose("agent-b", sessions["agent-b"], {
        "kind": "network.request", "url": "http://relay:8001/proxy?target=thirdparty",
    }, authorize_only=True)
    assert delegated["reason"] == "delegated_service_unmediated"

    action = {"kind": "network.request", "url": "http://127.0.0.1:9/safe"}
    authorized = substrate.propose("agent-b", sessions["agent-b"], action,
                                   authorize_only=True)
    substrate.set_circuit("control-token", "actor", "agent-b", True,
                          "authorization revoked during task")
    stale = substrate.propose("agent-b", sessions["agent-b"], action,
                              execution_token=authorized["execution_token"])
    assert stale["reason"] == "invalid_session"
    assert any(event["action"]["kind"] == "circuit.trigger" and
               event["decision"] == "allow" for event in substrate.audit())


def test_classification_survives_encoding_and_cross_agent_channels(boundary):
    substrate, sessions = boundary
    private = substrate.import_object(
        "private", "text/plain", base64.b64encode(b"PRIVATE_SENTINEL").decode(),
        ["agent-a"], "incident-fixture")
    encoded = substrate.propose("agent-a", sessions["agent-a"], {
        "kind": "object.transform", "object_id": private["object_id"],
        "operation": "base64"})
    assert encoded["classification"] == "private"
    publish = substrate.propose("agent-a", sessions["agent-a"], {
        "kind": "object.publish", "object_id": encoded["object_id"],
        "destination": "http://127.0.0.1:10"})
    assert publish["reason"] == "object_classification_blocks_egress"

    for action in (
        {"kind": "state.write", "scope": "shared", "channel": "logs",
         "key": "PRIVATE_SENTINEL", "value": "message"},
        {"kind": "filesystem.write", "scope": "shared", "channel": "cache",
         "path": "PRIVATE_SENTINEL", "content": "message"},
        {"kind": "worker.label", "name": "PRIVATE_SENTINEL"},
        {"kind": "telemetry.emit", "message": "PRIVATE_SENTINEL"},
    ):
        assert substrate.propose("agent-a", sessions["agent-a"], action)["decision"] == "deny"
    assert "PRIVATE_SENTINEL" not in json.dumps(substrate.audit())


def test_redirect_is_returned_but_never_followed():
    downstream_hits = []

    class Downstream(BaseHTTPRequestHandler):
        def do_GET(self):
            downstream_hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    downstream = ThreadingHTTPServer(("127.0.0.1", 0), Downstream)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location",
                             f"http://127.0.0.1:{downstream.server_port}/PRIVATE_SENTINEL")
            self.end_headers()

        def log_message(self, *_args):
            pass

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [threading.Thread(target=server.serve_forever, daemon=True)
               for server in (downstream, redirect)]
    for thread in threads:
        thread.start()
    try:
        url = f"http://127.0.0.1:{redirect.server_port}/safe"
        response = network_adapter.fetch(url, [url], allow_private=True)
        assert response["status"] == 302
        assert downstream_hits == []
    finally:
        redirect.shutdown()
        downstream.shutdown()


def test_dns_resolution_is_pinned_once(monkeypatch):
    resolutions = []
    connections = []

    def resolve(host, port, type):
        resolutions.append((host, port, type))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def connect(address, timeout, source_address=None):
        connections.append(address)
        raise OSError("synthetic connect stop")

    monkeypatch.setattr(network_adapter.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(network_adapter.socket, "create_connection", connect)
    with pytest.raises(OSError, match="synthetic connect stop"):
        network_adapter.fetch("http://allowed.invalid/safe",
                              ["http://allowed.invalid"])
    assert len(resolutions) == 1
    assert connections == [("93.184.216.34", 80)]


@pytest.mark.parametrize("address", ["10.0.0.5", "169.254.169.254", "fd00::1", "127.0.0.1"])
def test_external_origin_rejects_private_dns_result(monkeypatch, address):
    connections = []
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(network_adapter.socket, "getaddrinfo",
                        lambda host, port, type: [(family, socket.SOCK_STREAM, 6, "", (address, port))])
    monkeypatch.setattr(network_adapter.socket, "create_connection",
                        lambda *args, **kwargs: connections.append(args))
    with pytest.raises(ValueError, match="resolved address not allowed"):
        network_adapter.fetch("https://allowed.example/safe", ["https://allowed.example"])
    assert connections == []


def test_explicit_internal_origin_allows_private_but_not_metadata(monkeypatch):
    connections = []
    address = ["10.0.0.5"]
    monkeypatch.setattr(network_adapter.socket, "getaddrinfo",
                        lambda host, port, type: [(socket.AF_INET, socket.SOCK_STREAM, 6,
                                                   "", (address[0], port))])
    def connect(target, timeout, source_address=None):
        connections.append(target)
        raise OSError("synthetic connect stop")
    monkeypatch.setattr(network_adapter.socket, "create_connection", connect)
    with pytest.raises(OSError, match="synthetic connect stop"):
        network_adapter.fetch("http://fixture:8000/", ["http://fixture:8000"],
                              allow_private=True)
    assert connections == [("10.0.0.5", 8000)]
    address[0] = "169.254.169.254"
    with pytest.raises(ValueError, match="resolved address not allowed"):
        network_adapter.fetch("http://fixture:8000/", ["http://fixture:8000"],
                              allow_private=True)
    assert len(connections) == 1


def test_loopback_origin_requires_explicit_private_grant():
    with pytest.raises(ValueError, match="resolved address not allowed"):
        network_adapter.fetch("http://localhost:1/", ["http://localhost:1"])
