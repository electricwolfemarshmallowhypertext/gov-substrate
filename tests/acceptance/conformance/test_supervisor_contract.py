"""Shared supervisor assertions. Backend fixtures contain runtime-specific control."""

import base64
import concurrent.futures
import json
import os

import pytest
from fastapi.testclient import TestClient

from generation_adapter import run_local_generation
from substrate import Substrate, create_app


ACTOR = {
    "network": {"allowed": False},
    "filesystem": {"read": False, "write": False},
    "tools": {},
    "persistence": {"session": True, "cross_session": False},
    "shared_channels": [],
}
REGISTRY = {
    "actors": {"agent": ACTOR},
    "tokens": {"actor-token": "agent"},
    "operator_token": "adapter-token",
    "circuit_operator_token": "control-token",
}


@pytest.fixture
def conformance_lab(tmp_path, conformance_backend):
    substrate = Substrate(
        tmp_path / "conformance.db", REGISTRY,
        runtime_supervisor=conformance_backend.supervisor,
    )
    client = TestClient(create_app(substrate))
    return substrate, client, conformance_backend


def import_text(substrate, classification, text):
    return substrate.import_object(
        classification, "text/plain", base64.b64encode(text.encode()).decode(),
        ["agent"], "runtime-conformance-fixture",
    )["object_id"]


def config_text(mode, nonce, **values):
    fields = {"mode": mode, "nonce": nonce, **values}
    return "GOV_PROBE_CONFIG\n" + "".join(
        f"{name}={value}\n" for name, value in fields.items()
    )


def prepare(substrate, input_ids):
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose(
        "agent", session, {"kind": "generation.prepare", "input_ids": input_ids}
    )
    assert prepared["decision"] == "allow", prepared
    return session, prepared


def read_output(substrate, session, output):
    read = substrate.propose(
        "agent", session, {"kind": "object.read", "object_id": output["object_id"]}
    )
    assert read["decision"] == "allow", read
    return json.loads(base64.b64decode(read["content_base64"], validate=True))


def sealed_envelope(payloads):
    return json.dumps({
        "inputs": [
            {"media_type": "text/plain",
             "content_base64": base64.b64encode(payload).decode()}
            for payload in payloads
        ]
    })


@pytest.mark.conformance
def test_real_worker_sealed_context_governed_output_and_one_use_grant(conformance_lab):
    substrate, client, backend = conformance_lab
    nonce = os.urandom(12).hex()
    config = import_text(substrate, "public", config_text("echo", nonce))
    private = import_text(substrate, "private", "private governed context")
    session, prepared = prepare(substrate, [config, private])

    altered = substrate.claim_generation(
        prepared["generation_id"], prepared["execution_token"] + "altered"
    )
    assert altered["decision"] == "deny"
    assert altered["reason"] == "execution_grant_invalid"

    output = run_local_generation(
        client, prepared["generation_id"], "adapter-token",
        prepared["execution_token"], backend.supervisor,
    )
    assert output["decision"] == "succeeded"
    assert output["classification"] == "private"
    assert output["parents"] == [config, private]
    report = read_output(substrate, session, output)
    assert report["schema"] == 1
    assert report["nonce"] == nonce
    assert report["target"] == "linux"
    assert report["attempts"] == [{
        "attempt": "sealed_context_stdin",
        "allowed": True,
        "result": f"received_nonce={nonce}",
    }]

    replay = substrate.claim_generation(
        prepared["generation_id"], prepared["execution_token"]
    )
    assert replay["decision"] == "deny"
    assert replay["reason"] == "generation_already_claimed"


@pytest.mark.conformance
def test_circuit_stops_exact_worker_and_rejects_late_completion(conformance_lab):
    substrate, client, backend = conformance_lab
    config = import_text(substrate, "public", config_text("hold", os.urandom(12).hex()))
    _, prepared = prepare(substrate, [config])

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(
            run_local_generation, client, prepared["generation_id"], "adapter-token",
            prepared["execution_token"], backend.supervisor,
        )
        identity = backend.wait_running(prepared["generation_id"])
        stop = substrate.set_circuit(
            "control-token", "global", "*", True, "runtime conformance stop"
        )
        assert stop["shutdown_confirmed"] is True
        with pytest.raises(RuntimeError, match="stopped or failed"):
            running.result(timeout=20)

    backend.assert_terminated(identity.runtime_id)
    shutdown = [
        event for event in substrate.audit()
        if event["action"]["kind"] == "circuit.shutdown"
    ][-1]
    assert shutdown["decision"] == "succeeded"
    assert shutdown["action"]["results"] == [{
        "generation_id": prepared["generation_id"],
        "runtime": backend.name,
        "runtime_id": identity.runtime_id,
        "confirmed": True,
        "state": "stopped",
    }]
    assert substrate.complete_generation(
        prepared["generation_id"], "late completion"
    )["decision"] == "deny"


@pytest.mark.conformance
def test_supervisor_restart_reconciles_real_orphan(conformance_lab):
    substrate, _, backend = conformance_lab
    nonce = os.urandom(12).hex()
    payload = config_text("hold", nonce).encode()
    config = import_text(substrate, "public", payload.decode())
    _, prepared = prepare(substrate, [config])
    claimed = substrate.claim_generation(
        prepared["generation_id"], prepared["execution_token"]
    )
    assert claimed["decision"] == "allow"
    identity = backend.launch_orphan(
        prepared["generation_id"], sealed_envelope([payload])
    )

    restarted = Substrate(
        substrate.db_path, REGISTRY, runtime_supervisor=backend.new_supervisor()
    )
    backend.assert_terminated(identity.runtime_id)
    reconciled = [
        event for event in restarted.audit()
        if event["action"]["kind"] == "runtime.reconcile"
    ][-1]
    assert reconciled["decision"] == "allow"
    assert reconciled["action"]["results"] == [{
        "generation_id": prepared["generation_id"],
        "runtime": backend.name,
        "runtime_id": identity.runtime_id,
        "confirmed": True,
        "state": "stopped",
    }]
    assert restarted.complete_generation(
        prepared["generation_id"], "late completion"
    )["decision"] == "deny"
