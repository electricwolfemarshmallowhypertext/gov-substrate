"""End-to-end checks against Docker, one pinned local model, and the real substrate."""

import base64
import json
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from docker_runtime_supervisor import DockerRuntimeSupervisor
from generation_adapter import run_local_generation
from substrate import Substrate, create_app

from conftest import LOCAL_COMPOSE, ROOT, docker_command


ACTOR = {"network": {"allowed": False},
         "filesystem": {"read": False, "write": False},
         "tools": {}, "persistence": {"session": True, "cross_session": False},
         "shared_channels": []}
REGISTRY = {"actors": {"agent": ACTOR}, "tokens": {"actor-token": "agent"},
            "operator_token": "adapter-token", "circuit_operator_token": "control-token"}


@pytest.fixture
def lab(tmp_path, local_model_blob, local_generator_image):
    project = "govaccept" + uuid.uuid4().hex[:12]
    runtime = DockerRuntimeSupervisor(LOCAL_COMPOSE, local_model_blob, project)
    substrate = Substrate(tmp_path / "acceptance.db", REGISTRY,
                          runtime_supervisor=runtime)
    client = TestClient(create_app(substrate))
    try:
        yield substrate, client, runtime, project, local_generator_image
    finally:
        subprocess.run(["docker", "compose", "-f", str(LOCAL_COMPOSE),
                        "-p", project, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=local_generator_image, capture_output=True,
                       timeout=60)


def imported(substrate, classification, text):
    return substrate.import_object(
        classification, "text/plain", base64.b64encode(text.encode()).decode(),
        ["agent"], "trusted-acceptance-fixture")["object_id"]


def prepared_generation(substrate, inputs):
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose("agent", session,
                                 {"kind": "generation.prepare", "input_ids": inputs})
    assert prepared["decision"] == "allow", prepared
    return session, prepared


def launch_waiting_worker(prepared, project, env):
    """Start the actual one-shot worker with stdin open, before supplying context."""
    generation_id = prepared["generation_id"]
    name = f"gov-substrate-{generation_id}"
    container_id = docker_command(
        "compose", "-f", str(LOCAL_COMPOSE), "-p", project, "run", "-d", "-i",
        "-T", "--no-deps", "--name", name,
        "--label", "gov.substrate.managed=true",
        "--label", f"gov.substrate.generation_id={generation_id}",
        "--label", f"gov.substrate.owner={project}", "generator", env=env).strip()
    info = json.loads(docker_command("container", "inspect", container_id, env=env))[0]
    assert info["State"]["Running"], info["State"]
    assert info["Id"] == container_id
    assert info["HostConfig"]["NetworkMode"] == "none"
    assert info["HostConfig"]["ReadonlyRootfs"] is True
    assert info["Config"]["Entrypoint"][:2] == ["/usr/bin/env", "-i"]
    assert len(info["Mounts"]) == 1
    assert info["Mounts"][0]["Destination"] == "/model/model.gguf"
    assert info["Mounts"][0]["RW"] is False
    return name, container_id


def docker_events(container_id, since, env):
    until = datetime.now(timezone.utc) + timedelta(seconds=2)
    output = docker_command(
        "events", "--since", since.isoformat(), "--until", until.isoformat(),
        "--filter", f"container={container_id}", "--format", "{{json .}}",
        env=env, timeout=15)
    return [json.loads(line) for line in output.splitlines() if line.strip()]


def assert_stopped_and_removed(container_id, since, env):
    events = docker_events(container_id, since, env)
    actions = {event.get("Action") for event in events
               if event.get("Actor", {}).get("ID") == container_id}
    assert {"die", "destroy"} <= actions, actions
    inspection = subprocess.run(["docker", "container", "inspect", container_id],
                                cwd=ROOT, env=env, capture_output=True, timeout=15)
    assert inspection.returncode != 0, "Docker still reports the worker container"


def test_real_inference_returns_governed_private_object(lab):
    substrate, client, runtime, _, _ = lab
    prompt = imported(substrate, "public", "Complete this sentence: The garden is")
    private = imported(substrate, "private", "A private note says blue windows.")
    session, prepared = prepared_generation(substrate, [prompt, private])

    output = run_local_generation(client, prepared["generation_id"],
                                  "adapter-token", prepared["execution_token"], runtime)

    assert output["decision"] == "succeeded"
    assert output["classification"] == "private"
    assert output["parents"] == [prompt, private]
    read = substrate.propose("agent", session,
                             {"kind": "object.read", "object_id": output["object_id"]})
    assert read["decision"] == "allow"
    assert read["classification"] == "private"
    assert base64.b64decode(read["content_base64"], validate=True).strip()
    completion = [event for event in substrate.audit()
                  if event["action"]["kind"] == "generation.complete"]
    assert len(completion) == 1
    assert completion[0]["action"]["parents"] == [prompt, private]


def test_circuit_stops_exact_worker_and_rejects_late_completion(lab):
    substrate, _, _, project, env = lab
    source = imported(substrate, "private", "Governed context for a live worker.")
    _, prepared = prepared_generation(substrate, [source])
    claimed = substrate.claim_generation(prepared["generation_id"],
                                         prepared["execution_token"])
    assert claimed["decision"] == "allow"
    name, container_id = launch_waiting_worker(prepared, project, env)
    since = datetime.now(timezone.utc) - timedelta(seconds=1)
    try:
        stop = substrate.set_circuit("control-token", "global", "*", True,
                                     "acceptance emergency stop")
        assert stop["shutdown_confirmed"] is True
        assert_stopped_and_removed(container_id, since, env)
        shutdown = [event for event in substrate.audit()
                    if event["action"]["kind"] == "circuit.shutdown"][-1]
        assert shutdown["decision"] == "succeeded"
        assert shutdown["action"]["results"][0]["runtime_id"] == container_id
        late = substrate.complete_generation(prepared["generation_id"], "late text")
        assert late["decision"] == "deny"
        assert not any(event["action"]["kind"] == "generation.complete"
                       and event["decision"] == "succeeded" for event in substrate.audit())
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name], env=env,
                       capture_output=True, timeout=15)


def test_supervisor_restart_reconciles_real_orphan(lab):
    substrate, _, _, project, env = lab
    source = imported(substrate, "public", "Governed context for restart.")
    _, prepared = prepared_generation(substrate, [source])
    claimed = substrate.claim_generation(prepared["generation_id"],
                                         prepared["execution_token"])
    assert claimed["decision"] == "allow"
    name, container_id = launch_waiting_worker(prepared, project, env)
    since = datetime.now(timezone.utc) - timedelta(seconds=1)
    try:
        fresh_runtime = DockerRuntimeSupervisor(LOCAL_COMPOSE,
                                                env["GENERATION_MODEL_BLOB"], project)
        restarted = Substrate(substrate.db_path, REGISTRY,
                              runtime_supervisor=fresh_runtime)
        assert_stopped_and_removed(container_id, since, env)
        reconciled = [event for event in restarted.audit()
                      if event["action"]["kind"] == "runtime.reconcile"]
        assert reconciled and reconciled[-1]["decision"] == "allow"
        assert reconciled[-1]["action"]["results"][0]["runtime_id"] == container_id
        late = restarted.complete_generation(prepared["generation_id"], "late text")
        assert late["decision"] == "deny"
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name], env=env,
                       capture_output=True, timeout=15)
