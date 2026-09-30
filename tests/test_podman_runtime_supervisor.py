"""Deterministic Podman control tests; no runtime daemon is required."""

import json
from types import SimpleNamespace

import pytest

from podman_runtime_supervisor import PodmanRuntimeSupervisor


def supervisor():
    return PodmanRuntimeSupervisor(
        "gov-substrate-runtime-probe:test", "testproject"
    )


class FakeEngine:
    def __init__(self):
        self.containers = {}
        self.commands = []

    def add(self, generation_id, running=True, owner="testproject"):
        name = f"gov-substrate-{generation_id}"
        self.containers[name] = {
            "Id": f"container-{generation_id}", "Name": name,
            "Config": {"Labels": {"gov.substrate.managed": "true",
                                  "gov.substrate.generation_id": generation_id,
                                  "gov.substrate.owner": owner}},
            "State": {"Running": running},
        }

    def inspect(self, name):
        info = self.containers.get(name)
        return json.loads(json.dumps(info)) if info else None

    def podman(self, *args, timeout=15):
        self.commands.append(args)
        if args[:2] == ("container", "ls"):
            return "\n".join(
                info["Id"] for info in self.containers.values()
                if info["Config"]["Labels"]["gov.substrate.owner"] == "testproject"
            )
        if args[:2] == ("container", "inspect"):
            info = next(
                info for info in self.containers.values()
                if info["Id"] == args[2]
            )
            return json.dumps([info])
        runtime_id = args[-1]
        name = next(
            name for name, info in self.containers.items()
            if info["Id"] == runtime_id
        )
        if args[1] in ("stop", "kill"):
            self.containers[name]["State"]["Running"] = False
        elif args[1] == "rm":
            del self.containers[name]
        return "0"


def test_run_uses_fixed_rootless_isolation_shape(monkeypatch):
    runtime = supervisor()
    engine = FakeEngine()
    generation_id = "a" * 32
    runtime._inspect = engine.inspect
    runtime._podman = engine.podman
    commands = []

    class Process:
        returncode = 0

        def __init__(self, command, **kwargs):
            commands.append(command)
            engine.add(generation_id)

        def communicate(self, input, timeout):
            assert input == '{"inputs": []}'
            engine.containers[f"gov-substrate-{generation_id}"]["State"]["Running"] = False
            return '{"text":"probe"}', ""

    monkeypatch.setattr("podman_runtime_supervisor.subprocess.Popen", Process)
    assert runtime.run(generation_id, '{"inputs": []}') == '{"text":"probe"}'
    command = commands[0]
    for option in (
        "--network=none", "--restart=no", "--userns=auto",
        "--user=65534:65534", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--pids-limit=32",
    ):
        assert option in command
    assert command[-1] == "gov-substrate-runtime-probe:test"
    assert not engine.containers


def test_stop_targets_exact_container_and_reports_podman():
    runtime = supervisor()
    engine = FakeEngine()
    first, other = "b" * 32, "c" * 32
    engine.add(first)
    engine.add(other)
    runtime._inspect = engine.inspect
    runtime._podman = engine.podman

    result = runtime.stop((first,))[0]

    assert result.runtime == "podman"
    assert result.confirmed and result.runtime_id == f"container-{first}"
    assert result.state == "stopped"
    assert f"gov-substrate-{first}" not in engine.containers
    assert engine.containers[f"gov-substrate-{other}"]["State"]["Running"]


def test_reconcile_stops_only_owned_orphan():
    runtime = supervisor()
    engine = FakeEngine()
    generation_id = "d" * 32
    engine.add(generation_id)
    engine.add("e" * 32, owner="another-deployment")
    runtime._inspect = engine.inspect
    runtime._podman = engine.podman

    results = runtime.reconcile()

    assert len(results) == 1 and results[0].confirmed
    assert list(engine.containers) == ["gov-substrate-" + "e" * 32]


def test_unverified_exit_is_not_reported_as_shutdown():
    runtime = supervisor()
    engine = FakeEngine()
    generation_id = "f" * 32
    engine.add(generation_id)
    runtime._inspect = engine.inspect
    runtime._podman = lambda *args, **kwargs: (_ for _ in ()).throw(
        RuntimeError("runtime unavailable")
    )

    result = runtime.stop((generation_id,))[0]

    assert not result.confirmed
    assert result.state == "stop_unconfirmed"


def test_inspect_rejects_other_deployment_identity(monkeypatch):
    runtime = supervisor()
    generation_id = "1" * 32
    engine = FakeEngine()
    engine.add(generation_id, owner="another-deployment")
    info = engine.inspect(f"gov-substrate-{generation_id}")
    monkeypatch.setattr(
        "podman_runtime_supervisor.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps([info]), stderr=""
        ),
    )

    with pytest.raises(RuntimeError, match="identity mismatch"):
        runtime._inspect(f"gov-substrate-{generation_id}")


def test_inspect_rejects_restarting_worker(monkeypatch):
    runtime = supervisor()
    generation_id = "2" * 32
    engine = FakeEngine()
    engine.add(generation_id)
    info = engine.inspect(f"gov-substrate-{generation_id}")
    info["HostConfig"] = {"RestartPolicy": {"Name": "always"}}
    monkeypatch.setattr(
        "podman_runtime_supervisor.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps([info]), stderr=""
        ),
    )

    with pytest.raises(RuntimeError, match="must not restart"):
        runtime._inspect(f"gov-substrate-{generation_id}")
