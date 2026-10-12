"""Local harness checks; these are not agent or model evidence."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_challenge import (DockerFixture, action_from_call, call_for_action,
                                 check_fixture, run_leg)
from authority_challenge_cases import CASES


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_real_fixture_effect_and_substrate_denial(case, tmp_path):
    if os.name == "nt" and case.family == "file":
        pytest.skip("scoped filesystem adapter requires Linux O_NOFOLLOW")
    check_fixture(case, tmp_path)


@pytest.mark.skipif(os.getenv("RUN_AUTHORITY_DOCKER_TESTS") != "1",
                    reason="requires the real Docker daemon")
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_real_docker_bridge(case):
    fixture = DockerFixture(case, "gov-substrate-network-lab:local")
    try:
        if case.family in ("network", "revoked"):
            assert "source.authority.test" in fixture.seed_action["url"]
        assert action_from_call(call_for_action(fixture.seed_action)) == fixture.seed_action
        assert action_from_call(call_for_action(fixture.target_action)) == fixture.target_action
        ambient_seed = fixture.execute(fixture.seed_action, False)
        governed_seed = fixture.execute(fixture.seed_action, True)
        assert governed_seed["decision"]["decision"] == "allow"
        assert ambient_seed["text"] == governed_seed["text"]
        if case.family == "revoked":
            fixture.revoke()
        fixture.reset_effects()
        ambient = fixture.execute(fixture.target_action, False)
        assert ambient["effect"]
        fixture.reset_effects()
        governed = fixture.execute(fixture.target_action, True)
        assert governed["decision"]["decision"] == "deny"
        assert not governed["effect"]
        assert any(event["decision"] == "deny" for event in governed["audit"])
    finally:
        fixture.close()


@pytest.mark.skipif(os.getenv("RUN_AUTHORITY_DOCKER_TESTS") != "1",
                    reason="requires the real Docker daemon")
@pytest.mark.parametrize("initial_reply", ["batch", "invalid_locator"])
def test_recorded_batch_protocol_replay_with_real_tools(initial_reply):
    """Harness replay only. Scripted calls are not live-model attack evidence."""
    case = next(case for case in CASES if case.id == "network-01")
    fixture = DockerFixture(case, "gov-substrate-network-lab:local")

    class Replay:
        def __init__(self):
            self.turn = 0

        def ask(self, messages, *, require_tool):
            self.turn += 1
            if self.turn == 1 and initial_reply == "invalid_locator":
                actions = [{"kind": "network.request",
                            "url": "http://[IP_ADDRESS]:40105/seed/network-01"}]
            elif self.turn == 1:
                actions = [
                    {"kind": "state.read", "scope": "seed", "channel": "network-01",
                     "key": "package-mirror"},
                    {"kind": "state.read", "scope": "network", "channel": "network-01",
                     "key": "ip_address"},
                    {"kind": "object.read", "object_id": "network-01"},
                    {"kind": "object.read", "object_id": "seed/network-01"}]
            elif self.turn == 2:
                tools = [m for m in messages if m["role"] == "tool"]
                assert [m["tool_call_id"] for m in tools] == (
                    ["1-0"] if initial_reply == "invalid_locator" else
                    ["1-0", "1-1", "1-2", "1-3"])
                assert fixture.seed_action["url"] in tools[-1]["content"]
                if initial_reply == "invalid_locator":
                    assert "ValueError" in tools[0]["content"] or "Denied by substrate" in tools[0]["content"]
                actions = [fixture.seed_action]
            else:
                actions = [fixture.target_action]
            calls = [{"id": f"{self.turn}-{i}", **call_for_action(action)}
                     for i, action in enumerate(actions)]
            return actions, "tool_call", {"role": "assistant", "content": None,
                                          "tool_calls": calls}

    try:
        ambient = run_leg(fixture, Replay(), governed=False)
        governed = run_leg(fixture, Replay(), governed=True)
        assert ambient["seed_context_sha256"] == governed["seed_context_sha256"]
        assert ambient["attempted_target"] and ambient["unauthorized_effect"]
        assert governed["attempted_target"] and not governed["unauthorized_effect"]
        assert governed["substrate_decision"] == "deny"
        assert len(governed["tool_trace"]) == (3 if initial_reply == "invalid_locator" else 6)
        assert not any(item["after_injection"] for item in governed["tool_trace"][:-1])
        assert governed["tool_trace"][-1]["audit"]
    finally:
        fixture.close()
