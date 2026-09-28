"""Fail-closed checks for the new scoped authority schema."""

import pytest
from fastapi.testclient import TestClient

from substrate import Substrate, create_app


def registry(services):
    return {
        "actors": {"agent-a": {
            "network": {"allowed": True, "services": services},
            "filesystem": {"scopes": {"session": {"read": True, "write": True},
                                      "actor": {"read": True, "write": True},
                                      "shared": {"channels": []}}},
            "tools": {}, "persistence": {"session": True, "cross_session": False},
            "shared_channels": [],
        }},
        "tokens": {"agent-a-secret": "agent-a"},
        "operator_token": "human-secret",
    }


def test_service_routes_and_delegation_fail_closed(tmp_path):
    policy = registry([
        {"origin": "http://127.0.0.1:9", "mode": "terminal", "paths": ["/safe"]},
        {"origin": "http://127.0.0.1:10", "mode": "delegated"},
    ])
    client = TestClient(create_app(Substrate(tmp_path / "service.db", policy)))
    headers = {"Authorization": "Bearer agent-a-secret"}
    session = client.post("/sessions", headers=headers).json()["session_token"]
    headers["X-Session-Token"] = session

    def decision(url):
        return client.post("/proposals", headers=headers, json={"action": {
            "kind": "network.request", "url": url}}).json()

    assert decision("http://127.0.0.1:9/proxy")["reason"] == "service_route_not_allowed"
    assert decision("http://127.0.0.1:9/safe?forward=yes")["reason"] == "service_route_not_allowed"
    assert decision("http://127.0.0.1:10/safe")["reason"] == "delegated_service_unmediated"
    assert decision("http://127.0.0.1:11/safe")["reason"] == "destination_not_allowed"


@pytest.mark.parametrize("services", [
    [{"origin": "http://127.0.0.1:9", "mode": "terminal"}],
    [{"origin": "http://127.0.0.1:9", "mode": "terminal", "paths": ["/"]},
     {"origin": "http://127.0.0.1:9", "mode": "delegated"}],
    [{"origin": "http://127.0.0.1:9/proxy", "mode": "delegated"}],
])
def test_ambiguous_service_policy_rejected_at_startup(tmp_path, services):
    with pytest.raises(ValueError):
        Substrate(tmp_path / "invalid.db", registry(services))
