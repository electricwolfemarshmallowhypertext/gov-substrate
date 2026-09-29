"""Docker/OCI backend for supervised, one-shot local generation."""

import json
import os
import re
import subprocess
import threading
from pathlib import Path

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_MANAGED_LABEL = "gov.substrate.managed"
_GENERATION_LABEL = "gov.substrate.generation_id"
_OWNER_LABEL = "gov.substrate.owner"


class DockerRuntimeSupervisor:
    def __init__(self, compose_file: str | Path, model_blob: str | Path,
                 project: str):
        self.compose_file = Path(compose_file).resolve(strict=True)
        self.model_blob = Path(model_blob).resolve(strict=True)
        if not self.model_blob.is_file():
            raise ValueError("local model artifact must be one file")
        with self.model_blob.open("rb") as model_file:
            if model_file.read(4) != b"GGUF":
                raise ValueError("local model artifact must be GGUF")
        if not isinstance(project, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
            raise ValueError("unique lowercase runtime project required")
        self.project = project
        self._lock = threading.RLock()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()
        self._environment = {name: value for name, value in os.environ.items()
                             if not any(word in name.upper() for word in
                                        ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
                             and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
        self._environment["GENERATION_MODEL_BLOB"] = str(self.model_blob)

    @staticmethod
    def _name(generation_id: str) -> str:
        if not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")
        return f"gov-substrate-{generation_id}"

    def _docker(self, *args: str, timeout: int = 15) -> str:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                env=self._environment)
        if result.returncode:
            raise RuntimeError("Docker control command failed")
        return result.stdout.strip()

    def _inspect(self, name: str) -> dict | None:
        result = subprocess.run(["docker", "container", "inspect", name],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=15, env=self._environment)
        if result.returncode:
            if "No such container" in result.stderr or "No such object" in result.stderr:
                return None
            raise RuntimeError("Docker container inspection failed")
        info = json.loads(result.stdout)[0]
        generation_id = name.removeprefix("gov-substrate-")
        labels = info["Config"]["Labels"] or {}
        if (info["Name"].lstrip("/") != name or
                labels.get(_MANAGED_LABEL) != "true" or
                labels.get(_GENERATION_LABEL) != generation_id or
                labels.get(_OWNER_LABEL) != self.project):
            raise RuntimeError("Docker worker identity mismatch")
        restart = info.get("HostConfig", {}).get("RestartPolicy", {}).get("Name", "no")
        if restart not in ("", "no"):
            raise RuntimeError("Docker worker must not restart")
        return info

    def run(self, generation_id: str, sealed_context: str) -> str:
        name = self._name(generation_id)
        with self._lock:
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            command = ["docker", "compose", "-f", str(self.compose_file),
                       "-p", self.project]
            command.extend(["run", "--name", name,
                            "--label", f"{_MANAGED_LABEL}=true",
                            "--label", f"{_GENERATION_LABEL}={generation_id}",
                            "--label", f"{_OWNER_LABEL}={self.project}",
                            "-T", "--no-deps", "generator"])
            process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding="utf-8", errors="replace",
                                       env=self._environment)
            self._running[generation_id] = process
        try:
            try:
                stdout, _ = process.communicate(input=sealed_context, timeout=120)
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("local generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    raise RuntimeError("local generation stopped or failed")
                info = self._inspect(name)
                if info is None or info["State"]["Running"]:
                    self.stop((generation_id,))
                    raise RuntimeError("local worker exit could not be verified")
                self._docker("container", "rm", info["Id"])
                if self._inspect(name) is not None:
                    raise RuntimeError("local worker removal could not be verified")
                return stdout
        finally:
            with self._lock:
                self._running.pop(generation_id, None)

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]:
        with self._lock:
            return tuple(self._stop_one(generation_id) for generation_id in generation_ids)

    def _stop_one(self, generation_id: str) -> StopResult:
        name = self._name(generation_id)
        self._cancelled.add(generation_id)
        process = self._running.get(generation_id)
        runtime_id = None
        try:
            info = self._inspect(name)
            if info is None and process is not None and process.poll() is None:
                # A creation race cannot be certified merely by killing the CLI.
                process.kill()
                process.wait(timeout=5)
                info = self._inspect(name)
                if info is None:
                    return StopResult(generation_id, "docker", None,
                                      False, "creation_unconfirmed")
            if info is None:
                return StopResult(generation_id, "docker", None, True, "absent")
            runtime_id = info["Id"]
            if info["State"]["Running"]:
                try:
                    self._docker("container", "stop", "--time", "1", runtime_id,
                                 timeout=8)
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                info = self._inspect(name)
                if info is not None and info["State"]["Running"]:
                    self._docker("container", "kill", runtime_id, timeout=8)
            self._docker("container", "wait", runtime_id, timeout=8)
            info = self._inspect(name)
            if info is None or info["State"]["Running"]:
                raise RuntimeError("worker exit unverified")
            self._docker("container", "rm", runtime_id)
            if self._inspect(name) is not None:
                raise RuntimeError("worker removal unverified")
            return StopResult(generation_id, "docker", runtime_id, True, "stopped")
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            return StopResult(generation_id, "docker", runtime_id,
                              False, "stop_unconfirmed")
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

    def reconcile(self) -> tuple[StopResult, ...]:
        ids = self._docker("container", "ls", "-aq", "--filter",
                           f"label={_MANAGED_LABEL}=true", "--filter",
                           f"label={_OWNER_LABEL}={self.project}")
        generations = []
        for runtime_id in ids.splitlines():
            info = json.loads(self._docker("container", "inspect", runtime_id))[0]
            generation_id = (info["Config"]["Labels"] or {}).get(_GENERATION_LABEL)
            self._name(generation_id)
            if (info["Config"]["Labels"] or {}).get(_OWNER_LABEL) != self.project:
                raise RuntimeError("Docker reconciliation owner mismatch")
            generations.append(generation_id)
        return self.stop(tuple(generations))
