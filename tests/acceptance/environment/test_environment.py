"""Real OS probes in the unchanged reference generation-worker container."""

import base64
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from docker_runtime_supervisor import DockerRuntimeSupervisor
from substrate import Substrate

from conftest import LOCAL_COMPOSE, ROOT, docker_command


PROBE_SOURCE = Path(__file__).with_name("environment_probe.py").read_text(encoding="utf-8")
ENTRYPOINT_ARGS = ("-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp",
                   "PYTHONDONTWRITEBYTECODE=1", "OMP_NUM_THREADS=2",
                   "OPENBLAS_NUM_THREADS=1", "python", "-")


def inspect(container_id, env):
    return json.loads(docker_command("container", "inspect", container_id, env=env))[0]


def matching_runtime(reference, probe):
    for field in ("Image", "User", "Env", "WorkingDir"):
        assert probe["Config"][field] == reference["Config"][field], field
    for field in ("NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt",
                  "PidsLimit", "Tmpfs", "Privileged", "IpcMode", "PidMode"):
        assert probe["HostConfig"][field] == reference["HostConfig"][field], field
    assert probe["Mounts"] == reference["Mounts"]


@pytest.fixture
def worker_lab(tmp_path, local_model_blob, local_generator_image):
    project = "govenviron" + uuid.uuid4().hex[:10]
    env = {**local_generator_image, "GOV_ACCEPTANCE_SECRET": uuid.uuid4().hex}
    reference = f"gov-env-reference-{uuid.uuid4().hex[:10]}"
    command = ("compose", "-f", str(LOCAL_COMPOSE), "-p", project)
    reference_id = docker_command(*command, "run", "-d", "-i", "-T",
                                  "--no-deps", "--name", reference,
                                  "generator", env=env).strip()
    reference_info = inspect(reference_id, env)
    assert reference_info["State"]["Running"]
    assert reference_info["HostConfig"]["NetworkMode"] == "none"
    assert reference_info["Config"]["Entrypoint"][:2] == ["/usr/bin/env", "-i"]
    assert len(reference_info["Mounts"]) == 1
    assert reference_info["Mounts"][0]["Destination"] == "/model/model.gguf"
    assert reference_info["Mounts"][0]["RW"] is False
    try:
        yield project, env, reference_info, tmp_path, local_model_blob
    finally:
        subprocess.run(["docker", "container", "rm", "-f", reference_id],
                       cwd=ROOT, env=env, capture_output=True, timeout=20)
        subprocess.run(["docker", *command, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)


def run_probe(project, env, reference, config):
    name = "gov-env-probe-" + uuid.uuid4().hex[:12]
    command = probe_command(project, name, config)
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, input=PROBE_SOURCE,
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=90)
        assert completed.returncode == 0, completed.stderr
        info = inspect(name, env)
        matching_runtime(reference, info)
        rows = json.loads(completed.stdout.strip().splitlines()[-1])
        assert all(set(row) == {"attempt", "allowed", "result"} for row in rows)
        return {row["attempt"]: row for row in rows}
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name], cwd=ROOT,
                       env=env, capture_output=True, timeout=20)


def probe_command(project, name, config):
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    return ["docker", "compose", "-f", str(LOCAL_COMPOSE), "-p", project,
            "run", "-T", "--no-deps", "--name", name,
            "--entrypoint", "/usr/bin/env", "generator",
            *ENTRYPOINT_ARGS, encoded]


def test_worker_environment_has_only_granted_capabilities(worker_lab):
    project, env, reference, _, _ = worker_lab
    marker = ".pytest_tmp_env_canary_" + uuid.uuid4().hex
    host_canary = ROOT / marker
    host_canary.write_text("host only", encoding="utf-8")
    target_name = "gov-env-target-" + uuid.uuid4().hex[:10]
    target = None
    try:
        target = docker_command("run", "-d", "--name", target_name,
                                "--network", "bridge", "python:3.12-slim",
                                "python", "-m", "http.server", "8002", "--bind", "0.0.0.0",
                                env=env).strip()
        target_ip = docker_command("inspect", "-f",
                                   "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                                   target, env=env).strip()
        gateway_ip = docker_command("network", "inspect", "bridge", "-f",
                                    "{{(index .IPAM.Config 0).Gateway}}", env=env).strip()
        assert target_ip and gateway_ip
        for _ in range(40):
            control = subprocess.run(
                ["docker", "run", "--rm", "--network", "bridge", "python:3.12-slim",
                 "python", "-c", "import urllib.request; "
                 f"assert urllib.request.urlopen('http://{target_ip}:8002/', timeout=2).status == 200"],
                cwd=ROOT, env=env, capture_output=True, timeout=10)
            if control.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("target container is not reachable from another bridge container")

        rows = run_probe(project, env, reference, {
            "mode": "scan", "target_ip": target_ip, "gateway_ip": gateway_ip,
            "host_marker": marker, "host_pid": os.getpid(),
            "marker": "worker-private-" + uuid.uuid4().hex})
        for row in rows.values():
            print(json.dumps(row))
        allowed = {"model_read", "private_tmp", "private_shm",
                   "ipc_namespace", "mount_namespace"}
        assert all(row["allowed"] is (name in allowed)
                   for name, row in rows.items()), rows
        routed = {"direct_ipv4", "direct_ipv6", "docker_gateway",
                  "cloud_metadata_ipv4", "cloud_metadata_ipv6", "other_container"}
        assert all("errno=101" in rows[name]["result"] or
                   "errno=99" in rows[name]["result"] or
                   "errno=97" in rows[name]["result"] for name in routed), rows
        assert rows["model_read"]["result"] == "read 4 bytes"
    finally:
        host_canary.unlink(missing_ok=True)
        if target:
            subprocess.run(["docker", "container", "rm", "-f", target], cwd=ROOT,
                           env=env, capture_output=True, timeout=20)


def test_fresh_worker_cannot_read_prior_worker_storage(worker_lab):
    project, env, reference, _, _ = worker_lab
    marker = "cross-worker-" + uuid.uuid4().hex
    first = run_probe(project, env, reference, {"mode": "write_markers", "marker": marker})
    second = run_probe(project, env, reference, {"mode": "read_markers", "marker": marker})
    for row in [*first.values(), *second.values()]:
        print(json.dumps(row))
    assert first["write_private:/tmp"]["allowed"] is True
    assert first["write_private:/dev/shm"]["allowed"] is True
    assert second["previous_worker:/tmp"]["allowed"] is False
    assert second["previous_worker:/dev/shm"]["allowed"] is False


def test_simultaneous_workers_cannot_share_ipc_or_unix_sockets(worker_lab):
    project, env, reference, _, _ = worker_lab
    marker = "parallel-worker-" + uuid.uuid4().hex
    name = "gov-env-hold-" + uuid.uuid4().hex[:10]
    first = subprocess.Popen(
        probe_command(project, name, {"mode": "hold_markers", "marker": marker}),
        cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        first.stdin.write(PROBE_SOURCE)
        first.stdin.close()
        ready = first.stdout.readline()
        assert ready, first.stderr.read()
        first_rows = {row["attempt"]: row for row in json.loads(ready)}
        matching_runtime(reference, inspect(name, env))
        second = run_probe(project, env, reference,
                           {"mode": "read_markers", "marker": marker})
        for row in [*first_rows.values(), *second.values()]:
            print(json.dumps(row))
        for parent in ("/tmp", "/dev/shm"):
            assert first_rows[f"listen_private:{parent}"]["allowed"] is True
            assert second[f"previous_worker:{parent}"]["allowed"] is False
            assert second[f"previous_socket:{parent}"]["allowed"] is False
        assert first_rows["ipc_namespace"]["result"] != second["ipc_namespace"]["result"]
    finally:
        subprocess.run(["docker", "container", "stop", "--time", "1", name],
                       cwd=ROOT, env=env, capture_output=True, timeout=15)
        subprocess.run(["docker", "container", "rm", "-f", name],
                       cwd=ROOT, env=env, capture_output=True, timeout=15)
        first.wait(timeout=15)


def test_circuit_removes_worker_and_prevents_restart(worker_lab):
    project, env, _, tmp_path, model_blob = worker_lab
    runtime = DockerRuntimeSupervisor(LOCAL_COMPOSE, model_blob, project)
    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "circuit.db", {
        "actors": {"agent": actor}, "tokens": {"actor-token": "agent"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token"},
        runtime_supervisor=runtime)
    source = substrate.import_object("public", "text/plain",
                                     base64.b64encode(b"governed context").decode(),
                                     ["agent"], "fixture")["object_id"]
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose("agent", session, {"kind": "generation.prepare",
                                                    "input_ids": [source]})
    assert prepared["decision"] == "allow"
    assert substrate.claim_generation(prepared["generation_id"],
                                      prepared["execution_token"])["decision"] == "allow"
    name = "gov-substrate-" + prepared["generation_id"]
    container_id = docker_command(
        "compose", "-f", str(LOCAL_COMPOSE), "-p", project,
        "run", "-d", "-i", "-T", "--no-deps", "--name", name,
        "--label", "gov.substrate.managed=true",
        "--label", f"gov.substrate.generation_id={prepared['generation_id']}",
        "--label", f"gov.substrate.owner={project}", "generator", env=env).strip()
    assert inspect(container_id, env)["State"]["Running"]
    try:
        stopped = substrate.set_circuit("control-token", "global", "*", True,
                                        "environment acceptance stop")
        assert stopped["shutdown_confirmed"] is True
        for attempt in (["docker", "exec", container_id, "true"],
                        ["docker", "container", "start", container_id]):
            result = subprocess.run(attempt, cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=15)
            print(json.dumps({"attempt": " ".join(attempt[1:]), "allowed":
                              result.returncode == 0,
                              "result": result.stderr.strip()[:160]}))
            assert result.returncode != 0
        assert substrate.complete_generation(prepared["generation_id"],
                                             "late text")["decision"] == "deny"
        assert substrate.propose("agent", session,
                                 {"kind": "generation.prepare", "input_ids": [source]}
                                 )["decision"] == "deny"
        assert any(event["action"]["kind"] == "circuit.shutdown" and
                   event["decision"] == "succeeded" for event in substrate.audit())
    finally:
        subprocess.run(["docker", "container", "rm", "-f", name], cwd=ROOT,
                       env=env, capture_output=True, timeout=20)
