"""Real forbidden and granted capability attempts from the hostile worker."""

import base64
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
def enforcement_lab(tmp_path, conformance_backend):
    substrate = Substrate(
        tmp_path / "enforcement.db", REGISTRY,
        runtime_supervisor=conformance_backend.supervisor,
    )
    return substrate, TestClient(create_app(substrate)), conformance_backend


def import_text(substrate, classification, text):
    return substrate.import_object(
        classification, "text/plain", base64.b64encode(text.encode()).decode(),
        ["agent"], "runtime-enforcement-fixture",
    )["object_id"]


def config_text(mode, nonce, **values):
    fields = {"mode": mode, "nonce": nonce, **values}
    return "GOV_PROBE_CONFIG\n" + "".join(
        f"{name}={value}\n" for name, value in fields.items()
    )


def execute(substrate, client, backend, inputs):
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose(
        "agent", session, {"kind": "generation.prepare", "input_ids": inputs}
    )
    assert prepared["decision"] == "allow", prepared
    output = run_local_generation(
        client, prepared["generation_id"], "adapter-token",
        prepared["execution_token"], backend.supervisor,
    )
    assert output["decision"] == "succeeded"
    read = substrate.propose(
        "agent", session, {"kind": "object.read", "object_id": output["object_id"]}
    )
    assert read["decision"] == "allow", read
    report = json.loads(base64.b64decode(read["content_base64"], validate=True))
    return output, report


def rows_by_name(report):
    rows = {row["attempt"]: row for row in report["attempts"]}
    assert len(rows) == len(report["attempts"])
    assert all(set(row) == {"attempt", "allowed", "result"} for row in rows.values())
    return rows


@pytest.mark.runtime_enforcement
def test_ungranted_paths_are_physically_blocked_and_grants_still_work(
        enforcement_lab, tmp_path):
    substrate, client, backend = enforcement_lab
    target = backend.start_reachable_target()
    nonce = os.urandom(12).hex()
    marker = "previous-" + os.urandom(8).hex()
    host_marker = "host-canary-" + os.urandom(8).hex()
    host_canary = tmp_path.parent / host_marker
    host_canary.write_text("host-only", encoding="utf-8")
    try:
        config = import_text(substrate, "public", config_text(
            "scan", nonce, target_ip=target.address, gateway_ip=target.gateway,
            host_pid=os.getpid(), host_marker=host_marker, marker=marker,
        ))
        private = import_text(substrate, "private", "classified context")
        output, report = execute(substrate, client, backend, [config, private])
    finally:
        host_canary.unlink(missing_ok=True)

    assert output["classification"] == "private"
    assert output["parents"] == [config, private]
    assert report["target"] == backend.probe_target
    assert report["nonce"] == nonce
    rows = rows_by_name(report)
    assert {
        name for name, row in rows.items() if row["allowed"]
    } == backend.granted_attempts, rows
    required_forbidden = {
        "direct_ipv4", "direct_ipv6", "dns_public", "dns_other_container",
        "docker_gateway", "host_docker_internal", "cloud_metadata_ipv4",
        "cloud_metadata_ipv6", "other_container", "loopback_ipv4:2375",
        "loopback_ipv6", "unix_socket:/var/run/docker.sock",
        "unix_socket:/run/containerd/containerd.sock",
        "unexpected_mount:/workspace", "unexpected_mount:/run/secrets",
        "unexpected_mount:/model", "environment_secrets", "proc_self_secrets",
        "proc_pid1_secrets", "unrelated_host_pid", "unrelated_processes",
        "previous_worker:/tmp", "previous_worker:/dev/shm",
    }
    assert required_forbidden <= rows.keys()
    assert all(not rows[name]["allowed"] for name in required_forbidden), rows
    for row in rows.values():
        print(json.dumps(row))


@pytest.mark.runtime_enforcement
def test_fresh_worker_has_no_prior_temporary_or_ipc_state(enforcement_lab):
    substrate, client, backend = enforcement_lab
    marker = "carryover-" + os.urandom(8).hex()
    first_nonce = os.urandom(12).hex()
    first_config = import_text(
        substrate, "public", config_text("write_marker", first_nonce, marker=marker)
    )
    _, first_report = execute(substrate, client, backend, [first_config])
    first_rows = rows_by_name(first_report)
    assert first_rows["write_private:/tmp"]["allowed"] is True
    assert first_rows["write_private:/dev/shm"]["allowed"] is True

    second_nonce = os.urandom(12).hex()
    second_config = import_text(
        substrate, "public", config_text("scan", second_nonce, marker=marker)
    )
    _, second_report = execute(substrate, client, backend, [second_config])
    second_rows = rows_by_name(second_report)
    assert second_rows["previous_worker:/tmp"]["allowed"] is False
    assert second_rows["previous_worker:/dev/shm"]["allowed"] is False
    assert first_report["nonce"] == first_nonce
    assert second_report["nonce"] == second_nonce
