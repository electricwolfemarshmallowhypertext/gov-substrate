"""Opt-in Docker proof that circuit shutdown stops the worker container."""

import base64
import os
import subprocess
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from docker_runtime_supervisor import DockerRuntimeSupervisor
from generation_adapter import run_local_generation
from substrate import Substrate, create_app


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1",
                    reason="set RUN_DOCKER_TESTS=1 for Docker integration")
def test_circuit_verifies_running_container_stopped(tmp_path):
    project = "govsubstrate" + uuid.uuid4().hex[:10]
    compose = tmp_path / "compose.yaml"
    compose.write_text('''services:
  generator:
    image: python:3.12-slim
    pull_policy: never
    entrypoint: ["python", "-c", "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"]
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
''')
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"GGUFfixture")
    runtime = DockerRuntimeSupervisor(compose, model, project)
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "runtime.db", {
        "actors": {"agent": actor}, "tokens": {"actor-token": "agent"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token"},
        runtime_supervisor=runtime)
    client = TestClient(create_app(substrate))
    imported = substrate.import_object("public", "text/plain",
                                       base64.b64encode(b"governed context").decode(),
                                       ["agent"], "fixture")
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose("agent", session, {"kind": "generation.prepare",
                                                   "input_ids": [imported["object_id"]]})
    errors = []

    def generate():
        try:
            run_local_generation(client, prepared["generation_id"], "adapter-token",
                                 prepared["execution_token"], runtime)
        except RuntimeError as exc:
            errors.append(str(exc))

    worker = threading.Thread(target=generate)
    worker.start()
    name = f"gov-substrate-{prepared['generation_id']}"
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = runtime._inspect(name)
            if info is not None and info["State"]["Running"]:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("worker container never started")
        stop = substrate.set_circuit("control-token", "global", "*", True, "fixture stop")
        worker.join(timeout=15)
        assert stop["shutdown_confirmed"] is True
        assert not worker.is_alive() and errors
        assert runtime._inspect(name) is None
        assert not any(event["action"]["kind"] == "generation.complete"
                       for event in substrate.audit())
        event = substrate.audit()[-1]
        assert event["action"]["kind"] == "circuit.shutdown"
        assert event["decision"] == "succeeded"
        assert event["action"]["results"][0]["runtime_id"] == info["Id"]
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name],
                       capture_output=True, timeout=15)
        worker.join(timeout=5)


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1",
                    reason="set RUN_DOCKER_TESTS=1 for Docker integration")
def test_restart_reconciles_orphaned_worker(tmp_path):
    project = "govsubstrate" + uuid.uuid4().hex[:10]
    compose = tmp_path / "compose.yaml"
    compose.write_text('''services:
  generator:
    image: python:3.12-slim
    pull_policy: never
    entrypoint: ["python", "-c", "import time; time.sleep(60)"]
    network_mode: none
    read_only: true
    cap_drop: [ALL]
''')
    model = tmp_path / "fixture.gguf"
    model.write_bytes(b"GGUFfixture")
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    registry = {"actors": {"agent": actor}, "tokens": {"actor-token": "agent"},
                "operator_token": "adapter-token"}
    db_path = tmp_path / "restart.db"
    first = Substrate(db_path, registry)
    imported = first.import_object("public", "text/plain",
                                   base64.b64encode(b"context").decode(), ["agent"], "fixture")
    session = first.create_session("agent")["session_token"]
    prepared = first.propose("agent", session, {"kind": "generation.prepare",
                                                "input_ids": [imported["object_id"]]})
    claimed = first.claim_generation(prepared["generation_id"],
                                     prepared["execution_token"])
    assert claimed["decision"] == "allow"
    name = f"gov-substrate-{prepared['generation_id']}"
    command = ["docker", "compose", "-f", str(compose), "-p", project,
               "run", "-d", "--name", name,
               "--label", "gov.substrate.managed=true",
               "--label", f"gov.substrate.generation_id={prepared['generation_id']}",
               "--label", f"gov.substrate.owner={project}",
               "--no-deps", "generator"]
    try:
        launched = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert launched.returncode == 0, launched.stderr
        runtime = DockerRuntimeSupervisor(compose, model, project)
        assert runtime._inspect(name)["State"]["Running"]
        restarted = Substrate(db_path, registry, runtime_supervisor=runtime)
        assert runtime._inspect(name) is None
        assert restarted.audit()[-1]["action"]["kind"] == "runtime.reconcile"
        assert restarted.complete_generation(prepared["generation_id"], "late output")[
            "decision"] == "deny"
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name],
                       capture_output=True, timeout=15)
