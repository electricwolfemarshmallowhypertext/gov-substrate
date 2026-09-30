"""Real Docker implementation of the backend-neutral conformance fixture."""

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from docker_runtime_supervisor import DockerRuntimeSupervisor
from runtime_conformance import ReachableTarget, RuntimeIdentity


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "compose.runtime-conformance.yaml"


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


@pytest.fixture(scope="session")
def conformance_image(acceptance_enabled):
    previous_tag = os.environ.get("LAB_IMAGE_TAG")
    tag = "conformance" + uuid.uuid4().hex[:10]
    os.environ["LAB_IMAGE_TAG"] = tag
    env = clean_environment()
    env["LAB_IMAGE_TAG"] = tag
    try:
        docker_command("compose", "-f", str(COMPOSE), "build", "probe", env=env)
        yield env
    finally:
        if previous_tag is None:
            os.environ.pop("LAB_IMAGE_TAG", None)
        else:
            os.environ["LAB_IMAGE_TAG"] = previous_tag
        subprocess.run(
            ["docker", "image", "rm", f"gov-substrate-runtime-probe:{tag}"],
            cwd=ROOT, env=env, capture_output=True, timeout=60,
        )


class DockerConformanceBackend:
    name = "docker"

    def __init__(self, env):
        self.project = "govconformance" + uuid.uuid4().hex[:10]
        self.env = env
        self.supervisor = DockerRuntimeSupervisor(
            COMPOSE, None, self.project, service="probe"
        )
        self._targets = []

    def new_supervisor(self):
        return DockerRuntimeSupervisor(COMPOSE, None, self.project, service="probe")

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
            "compose", "-f", str(COMPOSE), "-p", self.project,
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
            ["docker", "compose", "-f", str(COMPOSE), "-p", self.project,
             "down", "--volumes", "--remove-orphans"],
            cwd=ROOT, env=self.env, capture_output=True, timeout=60,
        )


@pytest.fixture
def conformance_backend(conformance_image):
    backend = DockerConformanceBackend(conformance_image)
    try:
        yield backend
    finally:
        backend.cleanup()
