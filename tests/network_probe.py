"""Untrusted deterministic agent run inside the networkless container."""

import http.client
import json
import os
import socket
import sys
import time
from pathlib import Path


class UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/ipc/substrate.sock")


def request(method, path, token, body=None, session=None):
    connection = UnixHTTPConnection("substrate", timeout=10)
    headers = {"Authorization": f"Bearer {token}"}
    if session:
        headers["X-Session-Token"] = session
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=json.dumps(body) if body is not None else None,
                           headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def proposal(token, session, url):
    return request("POST", "/proposals", token,
                   {"action": {"kind": "network.request", "url": url}}, session)


def direct_network_blocked():
    targets = [("1.1.1.1", 443)]
    if os.environ.get("FIXTURE_IP"):
        targets.append((os.environ["FIXTURE_IP"], 8000))
    for address in targets:
        try:
            with socket.create_connection(address, timeout=2):
                return False
        except OSError:
            pass
    return True


def alternate_storage_blocked():
    if Path("/var/run/docker.sock").exists():
        return False
    for name in ("/ipc/hidden-channel", "/app/hidden-channel"):
        try:
            Path(name).write_text("bypass", encoding="utf-8")
            Path(name).unlink()
            return False
        except OSError:
            pass
    return True


def main():
    phase = sys.argv[1]
    token = os.environ["RESEARCH_AGENT_TOKEN"]
    for _ in range(60):
        try:
            status, session_result = request("POST", "/sessions", token)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise AssertionError("substrate socket unavailable")
    assert direct_network_blocked(), "direct outbound connection succeeded"
    assert alternate_storage_blocked(), "an alternate shared storage route is writable"

    if phase == "changed_registry_restart":
        assert status == 503, (status, session_result)
        print(json.dumps({"phase": phase, "direct_blocked": True,
                          "alternate_storage_blocked": True, "registry_failed_closed": True}))
        return

    assert status == 200 and session_result["decision"] == "allow", (status, session_result)
    session = session_result["session_token"]
    if phase == "tool":
        requested_status, requested = proposal(token, session, os.environ["TOOL_URL"])
        assert requested_status == 200, (requested_status, requested)
        print(json.dumps({"phase": phase, "direct_blocked": True,
                          "alternate_storage_blocked": True, "proposal": requested}))
        return
    allowed_status, allowed = proposal(token, session, "http://fixture:8000/")
    assert allowed_status == 200 and allowed["decision"] == "allow", allowed
    assert allowed["outcome"] == "succeeded" and allowed["response"]["status"] == 200, allowed
    denied_status, denied = proposal(token, session, "http://fixture:8001/")
    assert denied_status == 200 and denied["decision"] == "deny", denied
    assert denied["reason"] == "destination_not_allowed", denied

    if phase == "first":
        override_status, _ = request("POST", "/overrides", token,
                                     {"event_id": denied["event_id"], "reason": "bypass"})
        assert override_status == 401
    elif phase == "yaml_changed":
        old = os.environ["OLD_SESSION_TOKEN"]
        status, stale = proposal(token, old, "http://fixture:8000/")
        assert status == 200 and stale["reason"] == "invalid_session", stale
    else:
        raise AssertionError(f"unknown phase: {phase}")

    print(json.dumps({"phase": phase, "direct_blocked": True, "alternate_storage_blocked": True,
                      "allowed_event": allowed["event_id"], "outcome_event": allowed["outcome_event_id"],
                      "denied_event": denied["event_id"], "session_token": session}))


if __name__ == "__main__":
    main()
