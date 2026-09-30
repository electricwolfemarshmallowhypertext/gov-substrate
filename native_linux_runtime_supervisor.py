"""Native Linux backend using kernel isolation rather than a container engine."""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
_RUNTIME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}\Z")
_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})


def _process_birth(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    closing = stat.rfind(")")
    fields = stat[closing + 2:].split()
    if closing < 0 or len(fields) <= 19 or fields[0] in {"Z", "X"}:
        return None
    return fields[19]


class NativeLinuxRuntimeSupervisor:
    """Run one hostile worker in a fresh native Linux sandbox."""

    def __init__(self, launcher: str | Path, worker: str | Path,
                 state_dir: str | Path, cgroup_root: str | Path, project: str,
                 runtime_name: str = "native-linux"):
        if sys.platform != "linux":
            raise RuntimeError("native Linux supervisor requires Linux")
        self.launcher = Path(launcher).resolve(strict=True)
        self.worker = Path(worker).resolve(strict=True)
        if not self.launcher.is_file() or not os.access(self.launcher, os.X_OK):
            raise ValueError("native Linux launcher must be executable")
        if not self.worker.is_file() or not os.access(self.worker, os.X_OK):
            raise ValueError("native Linux worker must be executable")
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("unique lowercase runtime project required")
        if (not isinstance(runtime_name, str) or
                not _RUNTIME_NAME.fullmatch(runtime_name)):
            raise ValueError("valid lowercase runtime name required")
        self.project = project
        self.runtime_name = runtime_name
        self.worker_sha256 = hashlib.sha256(self.worker.read_bytes()).hexdigest()
        self.state_dir = Path(state_dir).resolve() / project
        self.worker_dir = self.state_dir / "workers"
        self.run_dir = self.state_dir / "runs"
        self.worker_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        root = Path(cgroup_root).resolve(strict=True)
        system_root = Path("/sys/fs/cgroup").resolve(strict=True)
        if root != system_root and system_root not in root.parents:
            raise RuntimeError("cgroup root must be beneath /sys/fs/cgroup")
        if not (root / "cgroup.controllers").is_file():
            raise RuntimeError("cgroup v2 is required")
        self.cgroup_root = root
        self.project_cgroup = root / project
        self.project_cgroup.mkdir(mode=0o700, exist_ok=True)
        self._enable_controllers(root)
        self._enable_controllers(self.project_cgroup)
        self._lock = threading.RLock()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()

    @staticmethod
    def _validate_generation(generation_id: str) -> None:
        if not isinstance(generation_id, str) or not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")

    @staticmethod
    def _enable_controllers(path: Path) -> None:
        available = set((path / "cgroup.controllers").read_text(
            encoding="utf-8").split())
        if not _REQUIRED_CONTROLLERS <= available:
            missing = sorted(_REQUIRED_CONTROLLERS - available)
            raise RuntimeError(f"required cgroup v2 controllers unavailable: {missing}")
        enabled_path = path / "cgroup.subtree_control"
        enabled = set(enabled_path.read_text(encoding="utf-8").split())
        missing = sorted(_REQUIRED_CONTROLLERS - enabled)
        if missing:
            enabled_path.write_text(
                " ".join(f"+{name}" for name in missing), encoding="utf-8"
            )
        enabled = set(enabled_path.read_text(encoding="utf-8").split())
        if not _REQUIRED_CONTROLLERS <= enabled:
            raise RuntimeError("cgroup v2 controller delegation failed")

    def _record_path(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.worker_dir / f"{generation_id}.json"

    def _execution_dir(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.run_dir / generation_id

    def _cgroup_dir(self, generation_id: str) -> Path:
        self._validate_generation(generation_id)
        return self.project_cgroup / generation_id

    def _create_cgroup(self, generation_id: str) -> Path:
        cgroup = self._cgroup_dir(generation_id)
        cgroup.mkdir(mode=0o700)
        (cgroup / "memory.max").write_text("134217728", encoding="utf-8")
        swap = cgroup / "memory.swap.max"
        if swap.exists():
            swap.write_text("0", encoding="utf-8")
        (cgroup / "pids.max").write_text("16", encoding="utf-8")
        (cgroup / "cpu.max").write_text("50000 100000", encoding="utf-8")
        return cgroup

    def _write_record(self, generation_id: str, launcher_pid: int,
                      launcher_birth: str, worker_pid: int,
                      worker_birth: str, pgid: int, cgroup: Path) -> str:
        runtime_id = (
            f"{launcher_pid}:{launcher_birth}:{worker_pid}:{worker_birth}"
        )
        record = {
            "schema": 1,
            "project": self.project,
            "generation_id": generation_id,
            "launcher_pid": launcher_pid,
            "launcher_birth": launcher_birth,
            "worker_pid": worker_pid,
            "worker_birth": worker_birth,
            "pgid": pgid,
            "runtime_id": runtime_id,
            "worker_sha256": self.worker_sha256,
            "cgroup": str(cgroup),
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
            "schema", "project", "generation_id", "launcher_pid",
            "launcher_birth", "worker_pid", "worker_birth", "pgid",
            "runtime_id", "worker_sha256", "cgroup",
        }
        cgroup = self._cgroup_dir(generation_id)
        if (type(record) is not dict or set(record) != expected or
                record["schema"] != 1 or record["project"] != self.project or
                record["generation_id"] != generation_id or
                record["worker_sha256"] != self.worker_sha256 or
                type(record["launcher_pid"]) is not int or
                type(record["worker_pid"]) is not int or
                type(record["pgid"]) is not int or
                min(record["launcher_pid"], record["worker_pid"],
                    record["pgid"]) <= 0 or
                type(record["launcher_birth"]) is not str or
                type(record["worker_birth"]) is not str or
                record["runtime_id"] != (
                    f"{record['launcher_pid']}:{record['launcher_birth']}:"
                    f"{record['worker_pid']}:{record['worker_birth']}"
                ) or record["cgroup"] != str(cgroup)):
            raise RuntimeError("native Linux worker identity mismatch")
        return record

    @staticmethod
    def _record_running(record: dict) -> bool:
        return (
            _process_birth(record["launcher_pid"]) == record["launcher_birth"]
            and _process_birth(record["worker_pid"]) == record["worker_birth"]
        )

    @staticmethod
    def runtime_exists(runtime_id: str) -> bool:
        try:
            launcher_text, launcher_birth, worker_text, worker_birth = (
                runtime_id.split(":", 3)
            )
            launcher_pid = int(launcher_text)
            worker_pid = int(worker_text)
        except (AttributeError, ValueError):
            return False
        return (
            _process_birth(launcher_pid) == launcher_birth and
            _process_birth(worker_pid) == worker_birth
        )

    def runtime_identity(self, generation_id: str) -> str | None:
        with self._lock:
            record = self._read_record(generation_id)
            if record is None or not self._record_running(record):
                return None
            return record["runtime_id"]

    @staticmethod
    def _wait_ready(path: Path, process: subprocess.Popen,
                    timeout: float = 15.0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = path.read_text(encoding="ascii").strip()
                pid = int(value)
                if pid > 0:
                    return pid
            except (FileNotFoundError, ValueError):
                pass
            if process.poll() is not None:
                _, stderr = process.communicate(timeout=1)
                raise RuntimeError(
                    "native Linux sandbox setup failed: " + stderr.strip()
                )
            time.sleep(0.02)
        raise RuntimeError("native Linux sandbox readiness timed out")

    def _spawn(self, generation_id: str) -> tuple[subprocess.Popen, str]:
        with self._lock:
            self._validate_generation(generation_id)
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            execution = self._execution_dir(generation_id)
            execution.mkdir(parents=True, exist_ok=False, mode=0o700)
            ready_file = execution / "ready"
            cgroup = self._create_cgroup(generation_id)
            control_read, control_write = os.pipe()
            process = None
            try:
                command = [
                    str(self.launcher), "--worker", str(self.worker),
                    "--control-fd", str(control_read),
                    "--ready-file", str(ready_file),
                ]
                process = subprocess.Popen(
                    command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    errors="replace", env={}, start_new_session=True,
                    close_fds=True, pass_fds=(control_read,),
                )
                os.close(control_read)
                control_read = -1
                (cgroup / "cgroup.procs").write_text(
                    str(process.pid), encoding="ascii"
                )
                members = {
                    int(value) for value in
                    (cgroup / "cgroup.procs").read_text(encoding="ascii").split()
                }
                if process.pid not in members:
                    raise RuntimeError("native Linux cgroup assignment failed")
                os.write(control_write, b"1")
                os.close(control_write)
                control_write = -1
                worker_pid = self._wait_ready(ready_file, process)
                launcher_birth = _process_birth(process.pid)
                worker_birth = _process_birth(worker_pid)
                pgid = os.getpgid(process.pid)
                if launcher_birth is None or worker_birth is None or pgid != process.pid:
                    raise RuntimeError("native Linux process identity unavailable")
                runtime_id = self._write_record(
                    generation_id, process.pid, launcher_birth, worker_pid,
                    worker_birth, pgid, cgroup,
                )
                self._running[generation_id] = process
                return process, runtime_id
            except Exception:
                if control_read >= 0:
                    os.close(control_read)
                if control_write >= 0:
                    os.close(control_write)
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                self._kill_cgroup(cgroup)
                self._remove_state(generation_id)
                raise

    def run(self, generation_id: str, sealed_context: str) -> str:
        process, _ = self._spawn(generation_id)
        try:
            try:
                stdout, stderr = process.communicate(
                    input=sealed_context, timeout=130
                )
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("local generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    detail = stderr.strip()
                    message = "local generation stopped or failed"
                    if detail and generation_id not in self._cancelled:
                        message += f": {detail}"
                    raise RuntimeError(message)
                record = self._read_record(generation_id)
                if record is None or self._any_record_process_running(record):
                    self.stop((generation_id,))
                    raise RuntimeError("local worker exit could not be verified")
                self._remove_state(generation_id)
                return stdout
        finally:
            with self._lock:
                self._running.pop(generation_id, None)

    @staticmethod
    def _any_record_process_running(record: dict) -> bool:
        return (
            _process_birth(record["launcher_pid"]) == record["launcher_birth"] or
            _process_birth(record["worker_pid"]) == record["worker_birth"]
        )

    @staticmethod
    def _kill_cgroup(cgroup: Path) -> None:
        kill = cgroup / "cgroup.kill"
        if kill.exists():
            try:
                kill.write_text("1", encoding="ascii")
            except OSError:
                pass

    @staticmethod
    def _wait_gone(record: dict, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not NativeLinuxRuntimeSupervisor._any_record_process_running(record):
                return True
            time.sleep(0.05)
        return not NativeLinuxRuntimeSupervisor._any_record_process_running(record)

    def _terminate(self, record: dict) -> bool:
        if not self._any_record_process_running(record):
            return True
        if _process_birth(record["launcher_pid"]) == record["launcher_birth"]:
            try:
                os.killpg(record["pgid"], signal.SIGTERM)
            except ProcessLookupError:
                pass
        if self._wait_gone(record, 1.0):
            return True
        self._kill_cgroup(Path(record["cgroup"]))
        if _process_birth(record["launcher_pid"]) == record["launcher_birth"]:
            try:
                os.killpg(record["pgid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if (_process_birth(record["worker_pid"]) == record["worker_birth"]):
            try:
                os.kill(record["worker_pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        return self._wait_gone(record)

    def _remove_state(self, generation_id: str) -> None:
        self._record_path(generation_id).unlink(missing_ok=True)
        execution = self._execution_dir(generation_id)
        if execution.parent == self.run_dir and execution.exists():
            shutil.rmtree(execution)
        cgroup = self._cgroup_dir(generation_id)
        if cgroup.parent == self.project_cgroup and cgroup.exists():
            try:
                cgroup.rmdir()
            except OSError as error:
                raise RuntimeError("native Linux cgroup cleanup failed") from error

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
                    generation_id, self.runtime_name, None, True, "absent"
                )
            runtime_id = record["runtime_id"]
            was_running = self._any_record_process_running(record)
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

    def cleanup_project(self) -> None:
        self.reconcile()
        if self.project_cgroup.exists():
            self.project_cgroup.rmdir()
