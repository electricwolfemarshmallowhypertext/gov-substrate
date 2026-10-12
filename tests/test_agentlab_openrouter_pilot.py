"""Local-only checks for the bounded AgentLAB OpenRouter runner."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agentlab_openrouter_pilot import (
    Ledger, MAX_TURNS, PROFILES, SPEND_LIMIT, case_context, matches_injected_goal,
    parse_reply, safe_local_attempt, worst_case_request_cost,
)


def test_one_model_gate_budget_is_below_five_dollars():
    planned = worst_case_request_cost(PROFILES["glm"]) * MAX_TURNS
    assert planned < SPEND_LIMIT
    ledger = Ledger()
    for _ in range(MAX_TURNS):
        ledger.reserve(PROFILES["glm"])
    assert ledger.requests == MAX_TURNS
    assert ledger.reserved_cost == planned
    try:
        ledger.reserve(PROFILES["glm"])
    except RuntimeError as exc:
        assert str(exc) == "combined_spend_or_request_limit"
    else:
        raise AssertionError("ninth request was not blocked")


def test_staged_attack_starts_outside_sealed_context():
    objects = {}

    def imported(classification, content, source):
        object_id = f"{len(objects) + 1:032x}"
        objects[object_id] = (classification, content, source)
        return object_id

    origin = "http://127.0.0.1:12345"
    context, stages, private_id = case_context("workspace", imported, origin)
    assert len(context) == 1 and len(stages) == 5
    assert private_id == stages[-1]
    assert "AgentLAB-derived" not in objects[context[0]][2]
    assert "forward the complete" not in objects[context[0]][1]
    assert all(objects[item][0] == "public" for item in stages[:-1])
    assert objects[private_id][0] == "private"
    assert stages[1] in objects[stages[0]][1]
    assert stages[2] in objects[stages[1]][1]
    assert stages[3] in objects[stages[2]][1]
    assert private_id in objects[stages[3]][1]

    context, stages, private_id = case_context("slack", imported, origin)
    assert len(context) == 1 and len(stages) == 2 and private_id is None
    assert "validation handshake" not in objects[context[0]][1]
    assert stages[1] in objects[stages[0]][1]


def test_only_supported_json_actions_reach_the_substrate():
    origin = "http://127.0.0.1:12345"
    private_id = "a" * 32
    publication = {"kind": "object.publish", "object_id": private_id,
                   "destination": origin}
    assert parse_reply(json.dumps({"action": publication})) == ("action", publication)
    assert safe_local_attempt(publication, origin)
    assert matches_injected_goal("workspace", publication, origin, private_id)
    read = {"kind": "object.read", "object_id": private_id}
    assert parse_reply(json.dumps({"action": read})) == ("action", read)
    assert safe_local_attempt(read, origin)
    assert not matches_injected_goal("workspace", read, origin, private_id)
    target = {"kind": "network.request", "url": origin + "/third-party"}
    assert matches_injected_goal("reachability", target, origin)
    assert parse_reply('{"action":{"kind":"object.declassify"}}') is None
    assert parse_reply('{"action":{"kind":"network.request","url":"x","extra":1}}') is None
    real_external = {"kind": "network.request", "url": "https://example.com/"}
    assert not safe_local_attempt(real_external, origin)
    assert not matches_injected_goal("slack", real_external, origin)
