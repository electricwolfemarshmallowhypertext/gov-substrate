import json
import os

import pytest

from wasmtime_runtime_supervisor import (
    WasmtimeRuntimeSupervisor,
    _process_birth,
)


def supervisor(tmp_path, monkeypatch):
    executable = tmp_path / ("wasmtime.exe" if os.name == "nt" else "wasmtime")
    executable.write_bytes(b"runtime")
    module = tmp_path / "probe.wasm"
    module.write_bytes(b"\0asm\x01\0\0\0")
    monkeypatch.setenv("HOST_API_KEY", "must-not-cross-host-boundary")
    return WasmtimeRuntimeSupervisor(
        executable, module, tmp_path / "state", "testproject"
    )


def test_command_denies_ambient_authority_and_bounds_execution(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path, monkeypatch)
    command = runtime._command("a" * 32)
    joined = " ".join(command)

    assert set(runtime._environment) <= {"SYSTEMROOT", "WINDIR"}
    for required in (
        "cache=n", "fuel=500000000", "timeout=120s",
        "max-memory-size=67108864", "inherit-network=n",
        "allow-ip-name-lookup=n", "tcp=n", "udp=n", "inherit-env=n",
    ):
        assert required in command
    assert "::/tmp" in joined
    assert "::/dev/shm" in joined
    assert command[-1] == str(runtime.module)


def test_identity_uses_pid_and_process_birth():
    birth = _process_birth(os.getpid())
    assert birth is not None
    assert WasmtimeRuntimeSupervisor.runtime_exists(f"{os.getpid()}:{birth}")
    assert not WasmtimeRuntimeSupervisor.runtime_exists(f"{os.getpid()}:{birth}x")


def test_reconcile_fails_closed_on_altered_metadata(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path, monkeypatch)
    generation_id = "b" * 32
    runtime._record_path(generation_id).write_text(json.dumps({
        "schema": 1,
        "project": runtime.project,
        "generation_id": generation_id,
        "pid": os.getpid(),
        "birth": _process_birth(os.getpid()),
        "runtime_id": "altered",
        "module_sha256": runtime.module_sha256,
    }), encoding="utf-8")

    with pytest.raises(RuntimeError, match="identity mismatch"):
        runtime.reconcile()


def test_invalid_identity_inputs_fail_closed(tmp_path, monkeypatch):
    runtime = supervisor(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="generation ID"):
        runtime.run("../escape", "{}")
    with pytest.raises(ValueError, match="runtime name"):
        WasmtimeRuntimeSupervisor(
            runtime.wasmtime, runtime.module, tmp_path / "other", "project",
            runtime_name="invalid runtime",
        )
