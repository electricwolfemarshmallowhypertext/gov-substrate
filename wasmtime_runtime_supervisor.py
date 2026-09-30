"""Wasmtime/WASI backend for supervised, one-shot workers."""

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
_RUNTIME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}\Z")


def _windows_process_birth(pid: int) -> str | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        exit_code = wintypes.DWORD()
        if (not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or
                exit_code.value != 259):
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
    finally:
        kernel32.CloseHandle(handle)


def _process_birth(pid: int) -> str | None:
    if os.name == "nt":
        return _windows_process_birth(pid)
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    closing = stat.rfind(")")
    fields = stat[closing + 2:].split()
    return fields[19] if closing >= 0 and len(fields) > 19 else None


def _terminate_windows(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x0001 | 0x00100000, False, pid)
    if not handle:
        return _process_birth(pid) is None
    try:
        if not kernel32.TerminateProcess(handle, 1):
            return False
        return kernel32.WaitForSingleObject(handle, 5000) == 0
    finally:
        kernel32.CloseHandle(handle)


class WasmtimeRuntimeSupervisor:
    """Run one WASI module instance per sealed generation."""

    def __init__(self, wasmtime: str | Path, module: str | Path,
                 state_dir: str | Path, project: str,
                 runtime_name: str = "wasmtime"):
        self.wasmtime = Path(wasmtime).resolve(strict=True)
        self.module = Path(module).resolve(strict=True)
        if not self.wasmtime.is_file():
            raise ValueError("Wasmtime executable must be one file")
        if not self.module.is_file() or self.module.read_bytes()[:4] != b"\0asm":
            raise ValueError("WASI module must be WebAssembly")
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("unique lowercase runtime project required")
        if (not isinstance(runtime_name, str) or
                not _RUNTIME_NAME.fullmatch(runtime_name)):
            raise ValueError("valid lowercase runtime name required")
        self.project = project
        self.runtime_name = runtime_name
        self.module_sha256 = hashlib.sha256(self.module.read_bytes()).hexdigest()
        self.state_dir = Path(state_dir).resolve() / project
        self.worker_dir = self.state_dir / "workers"
        self.run_dir = self.state_dir / "runs"
        self.worker_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()
        self._environment = {}
        if os.name == "nt":
            for name in ("SYSTEMROOT", "WINDIR"):
                if name in os.environ:
                    self._environment[name] = os.environ[name]

    @staticmethod
    def _validate_generation(generation_id: str) -> None:
        if not isinstance(generation_id, str) or not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")

    def _record_path(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.worker_dir / f"{generation_id}.json"

    def _execution_dir(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.run_dir / generation_id

    def _command(self, generation_id: str) -> list[str]:
        execution = self._execution_dir(generation_id)
        private_tmp = execution / "tmp"
        private_shm = execution / "shm"
        private_tmp.mkdir(parents=True, exist_ok=False, mode=0o700)
        private_shm.mkdir(mode=0o700)
        return [
            str(self.wasmtime), "run", "-C", "cache=n",
            "-W", "fuel=500000000", "-W", "timeout=120s",
            "-W", "max-memory-size=67108864", "-W", "max-instances=1",
            "-W", "max-memories=2", "-W", "max-tables=2",
            "-S", "cli=y", "-S", "max-resources=256",
            "-S", "hostcall-fuel=1000000", "-S", "max-random-size=65536",
            "-S", "inherit-network=n", "-S", "allow-ip-name-lookup=n",
            "-S", "tcp=n", "-S", "udp=n", "-S", "inherit-env=n",
            "-S", "inherit-stdin=y", "-S", "inherit-stdout=y",
            "-S", "inherit-stderr=y",
            "--dir", f"{private_tmp}::/tmp",
            "--dir", f"{private_shm}::/dev/shm",
            str(self.module),
        ]

    def _write_record(self, generation_id: str, process: subprocess.Popen,
                      birth: str) -> str:
        runtime_id = f"{process.pid}:{birth}"
        record = {
            "schema": 1,
            "project": self.project,
            "generation_id": generation_id,
            "pid": process.pid,
            "birth": birth,
            "runtime_id": runtime_id,
            "module_sha256": self.module_sha256,
        }
        destination = self._record_path(generation_id)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return runtime_id

    def _read_record(self, generation_id: str) -> dict | None:
        path = self._record_path(generation_id)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        expected = {
            "schema", "project", "generation_id", "pid", "birth",
            "runtime_id", "module_sha256",
        }
        if (type(record) is not dict or set(record) != expected or
                record["schema"] != 1 or record["project"] != self.project or
                record["generation_id"] != generation_id or
                record["module_sha256"] != self.module_sha256 or
                type(record["pid"]) is not int or record["pid"] <= 0 or
                type(record["birth"]) is not str or not record["birth"] or
                type(record["runtime_id"]) is not str or
                record["runtime_id"] != f"{record['pid']}:{record['birth']}"):
            raise RuntimeError("Wasmtime worker identity mismatch")
        return record

    @staticmethod
    def _record_running(record: dict) -> bool:
        return _process_birth(record["pid"]) == record["birth"]

    def _spawn(self, generation_id: str) -> tuple[subprocess.Popen, str]:
        with self._lock:
            self._validate_generation(generation_id)
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            command = self._command(generation_id)
            process = None
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    errors="replace", env=self._environment,
                    start_new_session=os.name != "nt",
                )
                birth = _process_birth(process.pid)
                if birth is None:
                    process.kill()
                    process.wait(timeout=5)
                    raise RuntimeError("Wasmtime process identity unavailable")
                runtime_id = self._write_record(generation_id, process, birth)
                self._running[generation_id] = process
                return process, runtime_id
            except Exception:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                self._remove_state(generation_id)
                raise

    def runtime_identity(self, generation_id: str) -> str | None:
        with self._lock:
            record = self._read_record(generation_id)
            if record is None or not self._record_running(record):
                return None
            return record["runtime_id"]

    @staticmethod
    def runtime_exists(runtime_id: str) -> bool:
        try:
            pid_text, birth = runtime_id.split(":", 1)
            pid = int(pid_text)
        except (AttributeError, ValueError):
            return False
        return _process_birth(pid) == birth

    def run(self, generation_id: str, sealed_context: str) -> str:
        process, _ = self._spawn(generation_id)
        try:
            try:
                stdout, _ = process.communicate(input=sealed_context, timeout=130)
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("local generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    raise RuntimeError("local generation stopped or failed")
                record = self._read_record(generation_id)
                if record is None or self._record_running(record):
                    self.stop((generation_id,))
                    raise RuntimeError("local worker exit could not be verified")
                self._remove_state(generation_id)
                return stdout
        finally:
            with self._lock:
                self._running.pop(generation_id, None)

    def _remove_state(self, generation_id: str) -> None:
        self._record_path(generation_id).unlink(missing_ok=True)
        execution = self._execution_dir(generation_id)
        if execution.parent == self.run_dir and execution.exists():
            shutil.rmtree(execution)

    @staticmethod
    def _wait_gone(record: dict, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not WasmtimeRuntimeSupervisor._record_running(record):
                return True
            if os.name != "nt":
                try:
                    os.waitpid(record["pid"], os.WNOHANG)
                except ChildProcessError:
                    pass
            time.sleep(0.05)
        return not WasmtimeRuntimeSupervisor._record_running(record)

    @staticmethod
    def _terminate(record: dict) -> bool:
        if not WasmtimeRuntimeSupervisor._record_running(record):
            return True
        if os.name == "nt":
            return _terminate_windows(record["pid"])
        try:
            os.kill(record["pid"], signal.SIGTERM)
        except ProcessLookupError:
            return True
        if WasmtimeRuntimeSupervisor._wait_gone(record, 1.0):
            return True
        try:
            os.kill(record["pid"], signal.SIGKILL)
        except ProcessLookupError:
            return True
        return WasmtimeRuntimeSupervisor._wait_gone(record)

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]:
        with self._lock:
            return tuple(self._stop_one(generation_id) for generation_id in generation_ids)

    def _stop_one(self, generation_id: str) -> StopResult:
        self._validate_generation(generation_id)
        self._cancelled.add(generation_id)
        process = self._running.get(generation_id)
        runtime_id = None
        try:
            record = self._read_record(generation_id)
            if record is None:
                return StopResult(
                    generation_id, self.runtime_name, None, True, "absent")
            runtime_id = record["runtime_id"]
            was_running = self._record_running(record)
            if not self._terminate(record):
                raise RuntimeError("worker exit unverified")
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("worker exit unverified") from None
            self._remove_state(generation_id)
            return StopResult(
                generation_id, self.runtime_name, runtime_id, True,
                "stopped" if was_running else "absent",
            )
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
            return StopResult(
                generation_id, self.runtime_name, runtime_id, False,
                "stop_unconfirmed",
            )

    def reconcile(self) -> tuple[StopResult, ...]:
        generations = []
        for path in sorted(self.worker_dir.glob("*.json")):
            generation_id = path.stem
            self._validate_generation(generation_id)
            self._read_record(generation_id)
            generations.append(generation_id)
        return self.stop(tuple(generations))
