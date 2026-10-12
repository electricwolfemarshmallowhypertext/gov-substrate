import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "governance_substrate"))
from agent_transport import SubstrateClient, digest  # noqa: E402


class Recorder(SubstrateClient):
    def __init__(self, decision="deny"):
        super().__init__("/unused", "token")
        self.posts, self.decision = [], decision

    def api(self, method, path, body=None):
        self.posts.append((method, path, body))
        value = {"decision": self.decision, "event_id": len(self.posts)}
        if self.decision == "allow":
            value["execution_token"] = "grant-secret"
        return value


def call(name, **arguments):
    return {"type": "function", "id": "c1", "function": {"name": name, "arguments": json.dumps(arguments)}}


def test_deferred_call_is_authorized_never_executed():
    client = Recorder("allow")
    event = client.defer(call("read_file", path=".env"))
    assert [path for _, path, _ in client.posts] == ["/authorizations"]
    assert event["deferred"] and event["result"]["outcome"] == "not_executed"
    assert event["action"] == {"kind": "filesystem.read", "scope": "actor", "path": ".env"}
    assert event["authorization"]["grant_unused"] is True
    assert "grant-secret" not in json.dumps(event)


def test_deferred_denial_is_recorded_with_event_id():
    event = Recorder("deny").defer(call("fetch_url", url="http://x/export"))
    assert event["authorization"] == {"decision": "deny", "event_id": 1}


def test_non_dict_calls_are_recorded_not_raised():
    for bad in ([], "x", None, {"type": "function", "id": "a", "function": "oops"}):
        client = Recorder()
        assert client.defer(bad)["deferred"] is True
        assert client.native(bad)["result"]["outcome"] == "failed"
        assert all(path == "/authorizations" for _, path, _ in client.posts)
        assert digest(bad)
