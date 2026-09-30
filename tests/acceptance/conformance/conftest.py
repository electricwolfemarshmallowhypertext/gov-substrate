"""Real Docker implementation of the backend-neutral conformance fixture."""

import json
import os
import http.server
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from docker_runtime_supervisor import DockerRuntimeSupervisor
from podman_runtime_supervisor import PodmanRuntimeSupervisor
from runtime_conformance import ReachableTarget, RuntimeIdentity
from wasmtime_runtime_supervisor import WasmtimeRuntimeSupervisor


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "compose.runtime-conformance.yaml"
GVISOR_COMPOSE = ROOT / "compose.runtime-conformance-gvisor.yaml"


def clean_environment():
    return {
        name: value for name, value in os.environ.items()
        if not any(word in name.upper() for word in
                   ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
        and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))
    }


def docker_command(*args, env=None, input_text=None, timeout=1200):
    result = subprocess.run(
        ["docker", *args], cwd=ROOT, env=clean_environment() if env is None else env,
        input=input_text, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=timeout,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def podman_command(*args, env=None, input_text=None, timeout=1200):
    result = subprocess.run(
        ["podman", *args], cwd=ROOT,
        env=clean_environment() if env is None else env, input=input_text,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


@pytest.fixture(scope="session")
def conformance_image(acceptance_enabled):
    backend = os.environ.get("RUNTIME_CONFORMANCE_BACKEND", "docker")
    assert backend in (
        "docker", "gvisor", "podman", "wasmtime"
    ), "unsupported conformance backend"
    if backend == "wasmtime":
        yield {
            "backend": backend,
            "wasmtime": Path(os.environ["WASMTIME_BIN"]).resolve(strict=True),
            "module": Path(os.environ["WASMTIME_MODULE"]).resolve(strict=True),
        }
        return
    compose = GVISOR_COMPOSE if backend == "gvisor" else COMPOSE
    previous_tag = os.environ.get("LAB_IMAGE_TAG")
    tag = "conformance" + uuid.uuid4().hex[:10]
    os.environ["LAB_IMAGE_TAG"] = tag
    env = clean_environment()
    env["LAB_IMAGE_TAG"] = tag
    image = f"gov-substrate-runtime-probe:{tag}"
    try:
        if backend in ("docker", "gvisor"):
            docker_command("compose", "-f", str(compose), "build", "probe", env=env)
        else:
            image = f"localhost/{image}"
            info = json.loads(
                podman_command("info", "--format", "json", env=env)
            )
            assert info["host"]["security"]["rootless"] is True
            assert info["host"].get("serviceIsRemote", False) is False
            podman_command(
                "build", "--file", str(ROOT / "Dockerfile.conformance"),
                "--tag", image, str(ROOT), env=env,
            )
        yield {
            "backend": backend, "compose": compose, "env": env,
            "image": image,
        }
    finally:
        if previous_tag is None:
            os.environ.pop("LAB_IMAGE_TAG", None)
        else:
            os.environ["LAB_IMAGE_TAG"] = previous_tag
        executable = "podman" if backend == "podman" else "docker"
        subprocess.run(
            [executable, "image", "rm", image], cwd=ROOT, env=env,
            capture_output=True, timeout=60,
        )


class DockerConformanceBackend:
    def __init__(self, artifact):
        self.name = artifact["backend"]
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.env = artifact["env"]
        self.compose = artifact["compose"]
        self.supervisor = DockerRuntimeSupervisor(
            self.compose, None, self.project, service="probe",
            runtime_name=self.name,
        )
        self._targets = []
        self.probe_target = "linux"
        self.granted_attempts = {
            "sealed_context_stdin", "private_ipc_namespace",
            "private_mount_namespace", "private_storage:/tmp",
            "private_storage:/dev/shm",
        }

    def new_supervisor(self):
        return DockerRuntimeSupervisor(
            self.compose, None, self.project, service="probe",
            runtime_name=self.name,
        )

    def _inspect(self, identity):
        result = subprocess.run(
            ["docker", "container", "inspect", identity], cwd=ROOT, env=self.env,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=15,
        )
        if result.returncode:
            return None
        return json.loads(result.stdout)[0]

    @staticmethod
    def _name(generation_id):
        return f"gov-substrate-{generation_id}"

    def _assert_runtime_shape(self, info):
        assert info["Config"]["Image"].startswith("gov-substrate-runtime-probe:")
        assert info["Config"]["User"] == "65534:65534"
        assert info["Config"]["Entrypoint"][:2] == ["/usr/bin/env", "-i"]
        assert info["HostConfig"]["NetworkMode"] == "none"
        assert info["HostConfig"]["ReadonlyRootfs"] is True
        assert info["HostConfig"]["Privileged"] is False
        assert info["HostConfig"]["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in info["HostConfig"]["SecurityOpt"]
        assert info["HostConfig"]["PidsLimit"] == 32
        assert info["HostConfig"]["RestartPolicy"]["Name"] in ("", "no")
        assert info["Mounts"] == []
        if self.name == "gvisor":
            assert info["HostConfig"]["Runtime"] == "runsc"

    def wait_running(self, generation_id):
        name = self._name(generation_id)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = self._inspect(name)
            if info is not None and info["State"]["Running"]:
                self._assert_runtime_shape(info)
                return RuntimeIdentity(info["Id"], True)
            time.sleep(0.1)
        raise AssertionError("conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        name = self._name(generation_id)
        container_id = docker_command(
            "compose", "-f", str(self.compose), "-p", self.project,
            "run", "-d", "-i", "-T", "--no-deps", "--name", name,
            "--label", "gov.substrate.managed=true",
            "--label", f"gov.substrate.generation_id={generation_id}",
            "--label", f"gov.substrate.owner={self.project}", "probe",
            env=self.env, input_text=sealed_context,
        )
        identity = self.wait_running(generation_id)
        assert identity.runtime_id == container_id
        return identity

    def assert_terminated(self, runtime_id):
        assert self._inspect(runtime_id) is None, "runtime still exists"

    def start_reachable_target(self):
        name = "gov-conformance-target-" + uuid.uuid4().hex[:10]
        container_id = docker_command(
            "run", "-d", "--name", name, "--network", "bridge",
            "python:3.12-slim", "python", "-m", "http.server", "8002",
            "--bind", "0.0.0.0", env=self.env,
        )
        self._targets.append(container_id)
        address = docker_command(
            "inspect", "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_id, env=self.env,
        )
        gateway = docker_command(
            "network", "inspect", "bridge", "-f",
            "{{(index .IPAM.Config 0).Gateway}}", env=self.env,
        )
        for _ in range(40):
            control = subprocess.run(
                ["docker", "run", "--rm", "--network", "bridge",
                 "python:3.12-slim", "python", "-c",
                 "import urllib.request; "
                 f"assert urllib.request.urlopen('http://{address}:8002/', timeout=2).status == 200"],
                cwd=ROOT, env=self.env, capture_output=True, timeout=10,
            )
            if control.returncode == 0:
                return ReachableTarget(address, gateway)
            time.sleep(0.2)
        raise AssertionError("control container could not reach conformance target")

    def cleanup(self):
        for target in self._targets:
            subprocess.run(
                ["docker", "container", "rm", "-f", target], cwd=ROOT,
                env=self.env, capture_output=True, timeout=20,
            )
        subprocess.run(
            ["docker", "compose", "-f", str(self.compose), "-p", self.project,
             "down", "--volumes", "--remove-orphans"],
            cwd=ROOT, env=self.env, capture_output=True, timeout=60,
        )


class PodmanConformanceBackend:
    name = "podman"

    def __init__(self, artifact):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.env = artifact["env"]
        self.image = artifact["image"]
        self.supervisor = PodmanRuntimeSupervisor(self.image, self.project)
        self._targets = []
        self._networks = []
        self.probe_target = "linux"
        self.granted_attempts = {
            "sealed_context_stdin", "private_ipc_namespace",
            "private_mount_namespace", "private_storage:/tmp",
            "private_storage:/dev/shm",
        }

    def new_supervisor(self):
        return PodmanRuntimeSupervisor(self.image, self.project)

    def _inspect(self, identity):
        result = subprocess.run(
            ["podman", "container", "inspect", identity], cwd=ROOT,
            env=self.env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=15,
        )
        if result.returncode:
            return None
        return json.loads(result.stdout)[0]

    @staticmethod
    def _name(generation_id):
        return f"gov-substrate-{generation_id}"

    def _assert_runtime_shape(self, info):
        assert info["ImageName"] == self.image
        assert info["Config"]["User"] == "65534:65534"
        assert info["Path"] == "/usr/bin/env"
        assert info["Args"] == [
            "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp",
            "/usr/local/bin/gov-runtime-probe",
        ]
        host = info["HostConfig"]
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["Privileged"] is False
        assert info.get("BoundingCaps") in (None, [])
        assert any(
            option in ("no-new-privileges", "no-new-privileges=true")
            for option in host.get("SecurityOpt", [])
        )
        assert host["PidsLimit"] == 32
        assert host["RestartPolicy"]["Name"] in ("", "no")
        pid = info["State"]["Pid"]
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        capability_masks = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:",
                                "CapBnd:", "CapAmb:"))
        }
        assert set(capability_masks) == {
            "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
        }
        assert all(int(mask, 16) == 0 for mask in capability_masks.values())
        uid_map = Path(f"/proc/{pid}/uid_map").read_text(encoding="utf-8")
        first_mapping = [int(value) for value in uid_map.splitlines()[0].split()]
        container_uid, host_uid, uid_count = first_mapping
        assert container_uid == 0, uid_map
        assert host_uid != 0, uid_map
        assert uid_count > 65534, uid_map

    def wait_running(self, generation_id):
        name = self._name(generation_id)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = self._inspect(name)
            if info is not None and info["State"]["Running"]:
                self._assert_runtime_shape(info)
                return RuntimeIdentity(info["Id"], True)
            time.sleep(0.1)
        raise AssertionError("conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        command = self.supervisor._run_command(generation_id, detached=True)
        result = subprocess.run(
            command, cwd=ROOT, env=self.env, input=sealed_context,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=30,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        container_id = result.stdout.strip()
        identity = self.wait_running(generation_id)
        assert identity.runtime_id == container_id
        return identity

    def assert_terminated(self, runtime_id):
        assert self._inspect(runtime_id) is None, "runtime still exists"

    def start_reachable_target(self):
        network = "gov-conformance-net-" + uuid.uuid4().hex[:10]
        target = "gov-conformance-target-" + uuid.uuid4().hex[:10]
        podman_command("network", "create", network, env=self.env)
        self._networks.append(network)
        container_id = podman_command(
            "run", "-d", "--name", target, "--network", network,
            "docker.io/library/python:3.12-slim", "python", "-m",
            "http.server", "8002", "--bind", "0.0.0.0", env=self.env,
        )
        self._targets.append(container_id)
        info = json.loads(
            podman_command("container", "inspect", container_id, env=self.env)
        )[0]
        networks = info["NetworkSettings"]["Networks"]
        address = next(iter(networks.values()))["IPAddress"]
        network_info = json.loads(
            podman_command("network", "inspect", network, env=self.env)
        )[0]
        gateway = network_info["subnets"][0]["gateway"]
        for _ in range(40):
            control = subprocess.run(
                ["podman", "run", "--rm", "--network", network,
                 "docker.io/library/python:3.12-slim", "python", "-c",
                 "import urllib.request; "
                 f"assert urllib.request.urlopen('http://{target}:8002/', timeout=2).status == 200"],
                cwd=ROOT, env=self.env, capture_output=True, timeout=10,
            )
            if control.returncode == 0:
                return ReachableTarget(address, gateway)
            time.sleep(0.2)
        raise AssertionError("control container could not reach conformance target")

    def cleanup(self):
        for target in self._targets:
            subprocess.run(
                ["podman", "container", "rm", "-f", target], cwd=ROOT,
                env=self.env, capture_output=True, timeout=20,
            )
        for network in self._networks:
            subprocess.run(
                ["podman", "network", "rm", "-f", network], cwd=ROOT,
                env=self.env, capture_output=True, timeout=20,
            )
        ids = subprocess.run(
            ["podman", "container", "ls", "-aq", "--filter",
             f"label=gov.substrate.owner={self.project}"], cwd=ROOT,
            env=self.env, capture_output=True, text=True, timeout=20,
        ).stdout.splitlines()
        if ids:
            subprocess.run(
                ["podman", "container", "rm", "-f", *ids], cwd=ROOT,
                env=self.env, capture_output=True, timeout=30,
            )


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"reachable")

    def log_message(self, *_args):
        pass


class WasmtimeConformanceBackend:
    name = "wasmtime"
    probe_target = "wasi"
    granted_attempts = {
        "sealed_context_stdin", "private_storage:/tmp",
        "private_storage:/dev/shm",
    }

    def __init__(self, artifact, state_dir):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.wasmtime = artifact["wasmtime"]
        self.module = artifact["module"]
        self.state_dir = state_dir
        self.supervisor = self.new_supervisor()
        self._orphans = []
        self._identities = {}
        self._server = None
        self._server_thread = None

    def new_supervisor(self):
        return WasmtimeRuntimeSupervisor(
            self.wasmtime, self.module, self.state_dir, self.project,
        )

    def wait_running(self, generation_id):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            runtime_id = self.supervisor.runtime_identity(generation_id)
            if runtime_id is not None:
                self._identities[runtime_id] = generation_id
                return RuntimeIdentity(runtime_id, True)
            time.sleep(0.05)
        raise AssertionError("conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        process, runtime_id = self.supervisor._spawn(generation_id)
        process.stdin.write(sealed_context)
        process.stdin.close()
        self._orphans.append(process)
        self._identities[runtime_id] = generation_id
        assert self.supervisor.runtime_exists(runtime_id)
        return RuntimeIdentity(runtime_id, True)

    def assert_terminated(self, runtime_id):
        for process in self._orphans:
            if process.pid == int(runtime_id.split(":", 1)[0]):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        assert not self.supervisor.runtime_exists(runtime_id), "runtime still exists"
        generation_id = self._identities[runtime_id]
        assert self.supervisor._read_record(generation_id) is None
        assert not self.supervisor._execution_dir(generation_id).exists()

    def start_reachable_target(self):
        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 8002), _QuietHandler
        )
        self._server_thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._server_thread.start()
        with urllib.request.urlopen("http://127.0.0.1:8002/", timeout=2) as response:
            assert response.status == 200
        return ReachableTarget("127.0.0.1", "127.0.0.1")

    def cleanup(self):
        self.supervisor.reconcile()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._server_thread is not None:
            self._server_thread.join(timeout=5)


@pytest.fixture
def conformance_backend(conformance_image, tmp_path):
    if conformance_image["backend"] == "podman":
        backend = PodmanConformanceBackend(conformance_image)
    elif conformance_image["backend"] == "wasmtime":
        backend = WasmtimeConformanceBackend(conformance_image, tmp_path / "wasmtime")
    else:
        backend = DockerConformanceBackend(conformance_image)
    try:
        yield backend
    finally:
        backend.cleanup()
