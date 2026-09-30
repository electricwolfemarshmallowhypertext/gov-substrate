"""Deterministic Docker control tests; no daemon or model is required."""

import json
import threading
from types import SimpleNamespace

import pytest

from docker_runtime_supervisor import DockerRuntimeSupervisor


def supervisor(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}")
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUFfixture")
    return DockerRuntimeSupervisor(compose, model, "testproject")


class FakeEngine:
    def __init__(self):
        self.containers = {}
        self.commands = []

    def add(self, generation_id, running=True, owner="testproject"):
        name = f"gov-substrate-{generation_id}"
        self.containers[name] = {
            "Id": f"container-{generation_id}", "Name": f"/{name}",
            "Config": {"Labels": {"gov.substrate.managed": "true",
                                  "gov.substrate.generation_id": generation_id,
                                  "gov.substrate.owner": owner}},
            "State": {"Running": running}}

    def inspect(self, name):
        info = self.containers.get(name)
        return json.loads(json.dumps(info)) if info else None

    def docker(self, *args, timeout=15):
        self.commands.append(args)
        if args[:2] == ("container", "ls"):
            return "\n".join(info["Id"] for info in self.containers.values()
                             if info["Config"]["Labels"]["gov.substrate.owner"] == "testproject")
        if args[:2] == ("container", "inspect"):
            info = next(info for info in self.containers.values() if info["Id"] == args[2])
            return json.dumps([info])
        runtime_id = args[-1]
        name = next(name for name, info in self.containers.items()
                    if info["Id"] == runtime_id)
        if args[1] in ("stop", "kill"):
            self.containers[name]["State"]["Running"] = False
        elif args[1] == "rm":
            del self.containers[name]
        return "0"


def test_stop_targets_container_id_and_verifies_removal(tmp_path):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    first, other = "a" * 32, "b" * 32
    engine.add(first)
    engine.add(other)
    runtime._inspect = engine.inspect
    runtime._docker = engine.docker
    result = runtime.stop((first,))[0]
    assert result.confirmed and result.runtime_id == f"container-{first}"
    assert result.state == "stopped"
    assert f"gov-substrate-{first}" not in engine.containers
    assert engine.containers[f"gov-substrate-{other}"]["State"]["Running"]
    assert ("container", "stop", "--time", "1", f"container-{first}") in engine.commands
    assert ("container", "rm", f"container-{first}") in engine.commands


def test_concurrent_shutdowns_share_one_verified_cleanup(tmp_path):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    generation_id = "3" * 32
    engine.add(generation_id)
    runtime._inspect = engine.inspect
    entered = threading.Event()
    release = threading.Event()
    original_docker = engine.docker

    def delayed_docker(*args, **kwargs):
        if args[:2] == ("container", "stop"):
            entered.set()
            assert release.wait(5)
        return original_docker(*args, **kwargs)

    runtime._docker = delayed_docker
    results = []
    first = threading.Thread(target=lambda: results.append(runtime.stop((generation_id,))[0]))
    second = threading.Thread(target=lambda: results.append(runtime.stop((generation_id,))[0]))
    first.start()
    assert entered.wait(5)
    second.start()
    release.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive() and not second.is_alive()
    assert len(results) == 2 and all(result.confirmed for result in results)
    assert {result.state for result in results} == {"stopped", "absent"}
    assert engine.containers == {}


def test_circuit_cleanup_and_adapter_cleanup_do_not_race(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    generation_id = "4" * 32
    runtime._inspect = engine.inspect
    runtime._docker = engine.docker
    started = threading.Event()
    killed = threading.Event()
    errors = []

    class Process:
        returncode = None

        def __init__(self, command, **kwargs):
            engine.add(generation_id)
            started.set()

        def communicate(self, input, timeout):
            assert killed.wait(5)
            return "", ""

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9
            killed.set()

    monkeypatch.setattr("docker_runtime_supervisor.subprocess.Popen", Process)

    def run():
        try:
            runtime.run(generation_id, '{"inputs": []}')
        except RuntimeError as exc:
            errors.append(str(exc))

    worker = threading.Thread(target=run)
    worker.start()
    assert started.wait(5)
    stop = runtime.stop((generation_id,))[0]
    worker.join(5)
    assert stop.confirmed and stop.state == "stopped"
    assert not worker.is_alive() and errors
    assert engine.containers == {}


def test_unverified_exit_is_not_reported_as_shutdown(tmp_path):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    generation_id = "c" * 32
    engine.add(generation_id)
    runtime._inspect = engine.inspect

    def failed_docker(*args, **kwargs):
        raise RuntimeError("daemon unavailable")

    runtime._docker = failed_docker
    result = runtime.stop((generation_id,))[0]
    assert not result.confirmed and result.state == "stop_unconfirmed"


def test_creation_race_is_unconfirmed_until_reconciliation(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "d" * 32
    process = SimpleNamespace(killed=False, poll=lambda: None)
    process.kill = lambda: setattr(process, "killed", True)
    process.wait = lambda timeout: 1
    runtime._running[generation_id] = process
    runtime._inspect = lambda name: None
    result = runtime.stop((generation_id,))[0]
    assert process.killed and not result.confirmed
    assert result.state == "creation_unconfirmed"


def test_reconcile_stops_orphaned_container(tmp_path):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    generation_id = "e" * 32
    engine.add(generation_id)
    engine.add("9" * 32, owner="another-deployment")
    runtime._inspect = engine.inspect
    runtime._docker = engine.docker
    results = runtime.reconcile()
    assert len(results) == 1 and results[0].confirmed
    assert list(engine.containers) == ["gov-substrate-" + "9" * 32]


def test_launch_names_and_labels_container_before_accepting_output(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path)
    engine = FakeEngine()
    generation_id = "f" * 32
    runtime._inspect = engine.inspect
    runtime._docker = engine.docker
    commands = []

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            commands.append(command)
            engine.add(generation_id)

        def communicate(self, input, timeout):
            assert input == '{"inputs": []}'
            engine.containers[f"gov-substrate-{generation_id}"]["State"]["Running"] = False
            return '{"text":"Answer"}', ""

    monkeypatch.setattr("docker_runtime_supervisor.subprocess.Popen", Process)
    assert runtime.run(generation_id, '{"inputs": []}') == '{"text":"Answer"}'
    assert commands and "--rm" not in commands[0]
    assert ["--name", f"gov-substrate-{generation_id}"] == commands[0][
        commands[0].index("--name"):commands[0].index("--name") + 2]
    assert "gov.substrate.managed=true" in commands[0]
    assert "gov.substrate.owner=testproject" in commands[0]
    assert not engine.containers


def test_model_free_service_uses_same_supervisor_contract(tmp_path, monkeypatch):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}")
    runtime = DockerRuntimeSupervisor(compose, None, "testproject", service="probe")
    engine = FakeEngine()
    generation_id = "8" * 32
    runtime._inspect = engine.inspect
    runtime._docker = engine.docker
    commands = []

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            commands.append(command)
            engine.add(generation_id)

        def communicate(self, input, timeout):
            engine.containers[f"gov-substrate-{generation_id}"]["State"]["Running"] = False
            return '{"text":"probe result"}', ""

    monkeypatch.setattr("docker_runtime_supervisor.subprocess.Popen", Process)
    assert runtime.run(generation_id, '{"inputs": []}') == '{"text":"probe result"}'
    assert commands[0][-1] == "probe"
    assert "GENERATION_MODEL_BLOB" not in runtime._environment


def test_inspect_rejects_other_deployment_identity(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path)
    generation_id = "1" * 32
    engine = FakeEngine()
    engine.add(generation_id, owner="another-deployment")
    info = engine.inspect(f"gov-substrate-{generation_id}")
    monkeypatch.setattr("docker_runtime_supervisor.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps([info]), stderr=""))
    with pytest.raises(RuntimeError, match="identity mismatch"):
        runtime._inspect(f"gov-substrate-{generation_id}")


def test_inspect_rejects_restarting_worker(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path)
    generation_id = "2" * 32
    engine = FakeEngine()
    engine.add(generation_id)
    info = engine.inspect(f"gov-substrate-{generation_id}")
    info["HostConfig"] = {"RestartPolicy": {"Name": "always"}}
    monkeypatch.setattr("docker_runtime_supervisor.subprocess.run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps([info]), stderr=""))
    with pytest.raises(RuntimeError, match="must not restart"):
        runtime._inspect(f"gov-substrate-{generation_id}")
