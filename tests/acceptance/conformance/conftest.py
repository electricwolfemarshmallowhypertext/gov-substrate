"""Real Docker implementation of the backend-neutral conformance fixture."""

import json
import os
import http.server
import socket
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

from docker_runtime_supervisor import DockerRuntimeSupervisor
from kubernetes_runtime_supervisor import KubernetesRuntimeSupervisor
from native_linux_runtime_supervisor import NativeLinuxRuntimeSupervisor
from native_windows_runtime_supervisor import NativeWindowsRuntimeSupervisor
from openshell_runtime_supervisor import OpenShellRuntimeSupervisor
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
        "docker", "gvisor", "podman", "wasmtime", "native-linux",
        "native-windows", "kubernetes", "openshell",
    ), "unsupported conformance backend"
    if backend == "kubernetes":
        yield {
            "backend": backend,
            "namespace": os.environ["KUBERNETES_NAMESPACE"],
            "image": os.environ["KUBERNETES_PROBE_IMAGE"],
            "kubeconfig": Path(os.environ["KUBECONFIG"]).resolve(strict=True),
            "context": os.environ["KUBERNETES_CONTEXT"],
            "kubectl": os.environ.get("KUBECTL_BIN", "kubectl"),
        }
        return
    if backend == "native-linux":
        assert os.name == "posix", "native-linux requires a Linux host"
        yield {
            "backend": backend,
            "launcher": Path(os.environ["NATIVE_LINUX_LAUNCHER"]).resolve(strict=True),
            "worker": Path(os.environ["NATIVE_PROBE"]).resolve(strict=True),
            "cgroup_root": Path(os.environ["NATIVE_CGROUP_ROOT"]).resolve(strict=True),
        }
        return
    if backend == "native-windows":
        assert os.name == "nt", "native-windows requires a Windows host"
        yield {
            "backend": backend,
            "worker": Path(os.environ["NATIVE_PROBE"]).resolve(strict=True),
        }
        return
    if backend == "wasmtime":
        yield {
            "backend": backend,
            "wasmtime": Path(os.environ["WASMTIME_BIN"]).resolve(strict=True),
            "module": Path(os.environ["WASMTIME_MODULE"]).resolve(strict=True),
        }
        return
    if backend == "openshell":
        yield {
            "backend": backend,
            "cli": os.environ.get("OPENSHELL_CLI", "openshell"),
            "gateway": os.environ["OPENSHELL_GATEWAY_NAME"],
            "image": os.environ["OPENSHELL_PROBE_IMAGE"],
            "policy": Path(os.environ["OPENSHELL_POLICY"]).resolve(strict=True),
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


class _NativeTargetMixin:
    def _init_target(self):
        self._server = None
        self._server_thread = None

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

    def _cleanup_target(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._server_thread is not None:
            self._server_thread.join(timeout=5)


class NativeLinuxConformanceBackend(_NativeTargetMixin):
    name = "native-linux"
    probe_target = "linux"
    granted_attempts = {
        "sealed_context_stdin", "private_ipc_namespace",
        "private_mount_namespace", "private_storage:/tmp",
        "private_storage:/dev/shm",
    }

    def __init__(self, artifact, state_dir):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.launcher = artifact["launcher"]
        self.worker = artifact["worker"]
        self.cgroup_root = artifact["cgroup_root"]
        self.state_dir = state_dir
        self.supervisor = self.new_supervisor()
        self._orphans = []
        self._identities = {}
        self._init_target()

    def new_supervisor(self):
        return NativeLinuxRuntimeSupervisor(
            self.launcher, self.worker, self.state_dir, self.cgroup_root,
            self.project,
        )

    @staticmethod
    def _status(pid):
        return {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in Path(f"/proc/{pid}/status").read_text(
                encoding="utf-8"
            ).splitlines()
        }

    def _assert_runtime_shape(self, generation_id):
        record = self.supervisor._read_record(generation_id)
        assert record is not None
        status = self._status(record["worker_pid"])
        assert status["NoNewPrivs"] == "1"
        assert status["Seccomp"] == "2"
        assert all(
            int(status[name], 16) == 0
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        assert {int(value) for value in status["Uid"].split()} == {65534}
        for namespace in ("net", "mnt", "ipc", "uts", "pid"):
            assert os.readlink(f"/proc/{record['worker_pid']}/ns/{namespace}") != os.readlink(
                f"/proc/self/ns/{namespace}"
            )
        cgroup = Path(record["cgroup"])
        assert (cgroup / "memory.max").read_text(encoding="ascii").strip() == "134217728"
        assert (cgroup / "pids.max").read_text(encoding="ascii").strip() == "16"
        assert (cgroup / "cpu.max").read_text(encoding="ascii").strip() == "50000 100000"
        members = {
            int(value) for value in
            (cgroup / "cgroup.procs").read_text(encoding="ascii").split()
        }
        assert record["launcher_pid"] in members
        assert record["worker_pid"] in members
        return record

    def wait_running(self, generation_id):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            runtime_id = self.supervisor.runtime_identity(generation_id)
            if runtime_id is not None:
                self._assert_runtime_shape(generation_id)
                self._identities[runtime_id] = generation_id
                return RuntimeIdentity(runtime_id, True)
            time.sleep(0.05)
        raise AssertionError("native Linux conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        process, runtime_id = self.supervisor._spawn(generation_id)
        process.stdin.write(sealed_context)
        process.stdin.close()
        self._orphans.append(process)
        self._identities[runtime_id] = generation_id
        identity = self.wait_running(generation_id)
        assert identity.runtime_id == runtime_id
        return identity

    def assert_terminated(self, runtime_id):
        for process in self._orphans:
            if str(process.pid) == runtime_id.split(":", 1)[0]:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        assert not self.supervisor.runtime_exists(runtime_id), "runtime still exists"
        generation_id = self._identities[runtime_id]
        assert self.supervisor._read_record(generation_id) is None
        assert not self.supervisor._execution_dir(generation_id).exists()
        assert not self.supervisor._cgroup_dir(generation_id).exists()

    def cleanup(self):
        self.supervisor.cleanup_project()
        self._cleanup_target()


class NativeWindowsConformanceBackend(_NativeTargetMixin):
    name = "native-windows"
    probe_target = "windows"
    granted_attempts = {
        "sealed_context_stdin", "private_storage:/tmp",
        "private_storage:/dev/shm", "windows_job_object",
        "windows_zero_capabilities", "windows_appcontainer",
    }

    def __init__(self, artifact, state_dir):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.worker = artifact["worker"]
        self.state_dir = state_dir
        self.supervisor = self.new_supervisor()
        self._orphans = []
        self._identities = {}
        self._init_target()

    def new_supervisor(self):
        return NativeWindowsRuntimeSupervisor(
            self.worker, self.state_dir, self.project,
        )

    def wait_running(self, generation_id):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            runtime_id = self.supervisor.runtime_identity(generation_id)
            if runtime_id is not None:
                security = self.supervisor.security_state(generation_id)
                assert security["appcontainer"] is True
                assert security["capability_count"] == 0
                assert security["integrity_rid"] <= 0x1000
                assert security["job_required_limits"] is True
                assert security["active_process_limit"] == 1
                assert security["process_memory_limit"] == 134217728
                self._identities[runtime_id] = generation_id
                return RuntimeIdentity(runtime_id, True)
            time.sleep(0.05)
        raise AssertionError("native Windows conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        process, runtime_id = self.supervisor._spawn(generation_id)
        process._write_all(sealed_context.encode("utf-8"))
        process.api.close(process.stdin_write)
        process.stdin_write = None
        self._orphans.append(process)
        self._identities[runtime_id] = generation_id
        identity = self.wait_running(generation_id)
        assert identity.runtime_id == runtime_id
        return identity

    def assert_terminated(self, runtime_id):
        assert not self.supervisor.runtime_exists(runtime_id), "runtime still exists"
        generation_id = self._identities[runtime_id]
        assert self.supervisor._read_record(generation_id) is None

    def cleanup(self):
        self.supervisor.reconcile()
        for process in self._orphans:
            process.close()
        self._cleanup_target()


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


class KubernetesConformanceBackend:
    name = "kubernetes"
    probe_target = "linux"
    granted_attempts = {
        "sealed_context_stdin", "private_ipc_namespace",
        "private_mount_namespace", "private_storage:/tmp",
        "private_storage:/dev/shm",
    }

    def __init__(self, artifact):
        self.namespace = artifact["namespace"]
        self.image = artifact["image"]
        self.kubeconfig = artifact["kubeconfig"]
        self.context = artifact["context"]
        self.kubectl = artifact["kubectl"]
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.supervisor = self.new_supervisor()
        self._identities = {}
        self._orphans = []
        self._port_forwards = []
        self._fixtures = []

    def new_supervisor(self):
        return KubernetesRuntimeSupervisor(
            self.namespace,
            self.image,
            self.project,
            kubeconfig=self.kubeconfig,
            context=self.context,
            kubectl=self.kubectl,
        )

    def _command(self, *args):
        return [
            self.kubectl, "--context", self.context,
            "--namespace", self.namespace, *args,
        ]

    def _kubectl(self, *args, input_text=None, timeout=60):
        result = subprocess.run(
            self._command(*args), cwd=ROOT, env=clean_environment(),
            input=input_text, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        return result.stdout.strip()

    def wait_running(self, generation_id):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            identity = self.supervisor.runtime_identity(generation_id)
            if identity is not None:
                pod = self.supervisor._inspect(generation_id)
                statuses = pod.get("status", {}).get("containerStatuses") or []
                if (
                    pod.get("status", {}).get("phase") == "Running"
                    and statuses
                    and statuses[0].get("state", {}).get("running")
                ):
                    self._identities[identity] = generation_id
                    return RuntimeIdentity(identity, True)
            time.sleep(0.1)
        raise AssertionError("Kubernetes conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        created = self.supervisor._create_pod(generation_id)
        self.supervisor._wait_running(generation_id)
        process = subprocess.Popen(
            self.supervisor._attach_command(generation_id),
            cwd=ROOT,
            env=self.supervisor._environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        process.stdin.write(sealed_context)
        process.stdin.close()
        self._orphans.append(process)
        identity = self.wait_running(generation_id)
        assert identity.runtime_id == created["metadata"]["uid"]
        return identity

    def assert_terminated(self, runtime_id):
        generation_id = self._identities[runtime_id]
        assert self.supervisor._inspect(generation_id) is None, "runtime still exists"
        for process in self._orphans:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    @staticmethod
    def _free_port():
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    def start_reachable_target(self):
        target_name = "environment-target"
        target = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": target_name,
                "namespace": self.namespace,
                "labels": {"gov.substrate/fixture": "reachable-target"},
            },
            "spec": {
                "automountServiceAccountToken": False,
                "enableServiceLinks": False,
                "restartPolicy": "Never",
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "target",
                    "image": self.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["/usr/local/bin/gov-runtime-probe", "--serve"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "runAsGroup": 65534,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "resources": {
                        "requests": {"cpu": "5m", "memory": "8Mi"},
                        "limits": {"cpu": "100m", "memory": "32Mi"},
                    },
                }],
            },
        }
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": target_name, "namespace": self.namespace},
            "spec": {
                "selector": {"gov.substrate/fixture": "reachable-target"},
                "ports": [{"port": 8002, "targetPort": 8002}],
            },
        }
        self._kubectl(
            "create", "-f", "-", input_text=json.dumps({
                "apiVersion": "v1", "kind": "List", "items": [target, service],
            }),
        )
        self._fixtures.extend(("pod/environment-target", "service/environment-target"))
        self._kubectl("wait", "--for=condition=Ready", "pod/environment-target",
                      "--timeout=90s", timeout=100)
        service_info = json.loads(self._kubectl("get", "service/environment-target", "-o", "json"))
        address = service_info["spec"]["clusterIP"]

        port = self._free_port()
        forward = subprocess.Popen(
            self._command(
                "port-forward", "pod/environment-target", f"{port}:8002",
                "--address=127.0.0.1",
            ),
            cwd=ROOT,
            env=clean_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._port_forwards.append(forward)
        for _ in range(80):
            if forward.poll() is not None:
                raise AssertionError("Kubernetes target port-forward stopped")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/", timeout=1
                ) as response:
                    if response.status == 200 and response.read() == b"reachable":
                        return ReachableTarget(address, address)
            except OSError:
                time.sleep(0.1)
        raise AssertionError("substrate control path could not reach Kubernetes target")

    def cleanup(self):
        self.supervisor.reconcile()
        for process in self._port_forwards:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        for resource in reversed(self._fixtures):
            subprocess.run(
                self._command("delete", resource, "--ignore-not-found=true", "--wait=true"),
                cwd=ROOT, env=clean_environment(), capture_output=True, timeout=60,
            )
        for process in self._orphans:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


class OpenShellConformanceBackend:
    name = "openshell"
    probe_target = "linux"
    granted_attempts = {
        "sealed_context_stdin", "private_ipc_namespace",
        "private_mount_namespace", "private_storage:/tmp",
        "private_storage:/dev/shm",
    }

    def __init__(self, artifact):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.cli = artifact["cli"]
        self.gateway = artifact["gateway"]
        self.image = artifact["image"]
        self.policy = artifact["policy"]
        self.supervisor = self.new_supervisor()
        self._targets = []
        self._processes = []
        self._identities = {}

    def new_supervisor(self):
        return OpenShellRuntimeSupervisor(
            self.image, self.policy, self.project, self.gateway, self.cli
        )

    def wait_running(self, generation_id):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            item = self.supervisor._inspect_generation(generation_id)
            if item is not None and item.get("phase") == "Ready":
                runtime_id = item["id"]
                status = self.supervisor.security_state(generation_id)
                assert {int(value) for value in status["Uid"].split()} == {65534}
                assert status["NoNewPrivs"] == "1"
                assert status["Seccomp"] == "2"
                assert all(
                    int(status[name], 16) == 0
                    for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
                )
                self._identities[runtime_id] = generation_id
                return RuntimeIdentity(runtime_id, True)
            time.sleep(0.2)
        raise AssertionError("OpenShell conformance worker did not start")

    def launch_orphan(self, generation_id, sealed_context):
        process = subprocess.Popen(
            self.supervisor._create_command(generation_id), cwd=ROOT,
            env=self.supervisor._environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        )
        process.stdin.write(sealed_context)
        process.stdin.close()
        self._processes.append(process)
        return self.wait_running(generation_id)

    def assert_terminated(self, runtime_id):
        generation_id = self._identities[runtime_id]
        assert self.supervisor.runtime_identity(generation_id) is None

    def start_reachable_target(self):
        name = "gov-openshell-target-" + uuid.uuid4().hex[:10]
        container_id = docker_command(
            "run", "-d", "--name", name, "--network", "bridge",
            "python:3.12-slim", "python", "-m", "http.server", "8002",
            "--bind", "0.0.0.0",
        )
        self._targets.append(container_id)
        address = docker_command(
            "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_id,
        )
        gateway = docker_command(
            "network", "inspect", "bridge", "-f",
            "{{(index .IPAM.Config 0).Gateway}}",
        )
        return ReachableTarget(address, gateway)

    def cleanup(self):
        self.supervisor.reconcile()
        for process in self._processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        for target in self._targets:
            subprocess.run(
                ["docker", "container", "rm", "-f", target], cwd=ROOT,
                env=clean_environment(), capture_output=True, timeout=20,
            )


@pytest.fixture
def conformance_backend(conformance_image, tmp_path):
    if conformance_image["backend"] == "podman":
        backend = PodmanConformanceBackend(conformance_image)
    elif conformance_image["backend"] == "wasmtime":
        backend = WasmtimeConformanceBackend(conformance_image, tmp_path / "wasmtime")
    elif conformance_image["backend"] == "native-linux":
        backend = NativeLinuxConformanceBackend(
            conformance_image, tmp_path / "native-linux"
        )
    elif conformance_image["backend"] == "native-windows":
        backend = NativeWindowsConformanceBackend(
            conformance_image, tmp_path / "native-windows"
        )
    elif conformance_image["backend"] == "kubernetes":
        backend = KubernetesConformanceBackend(conformance_image)
    elif conformance_image["backend"] == "openshell":
        backend = OpenShellConformanceBackend(conformance_image)
    else:
        backend = DockerConformanceBackend(conformance_image)
    try:
        yield backend
    finally:
        backend.cleanup()
