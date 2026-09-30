"""Rootless Podman backend for supervised, one-shot workers."""

import json
import os
import re
import subprocess
import threading

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]{0,254}\Z")
_MANAGED_LABEL = "gov.substrate.managed"
_GENERATION_LABEL = "gov.substrate.generation_id"
_OWNER_LABEL = "gov.substrate.owner"


class PodmanRuntimeSupervisor:
    def __init__(self, image: str, project: str):
        if not isinstance(image, str) or not _IMAGE.fullmatch(image):
            raise ValueError("valid Podman image reference required")
        if not isinstance(project, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9_-]{0,62}", project):
            raise ValueError("unique lowercase runtime project required")
        self.image = image
        self.project = project
        self._lock = threading.RLock()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()
        self._environment = {
            name: value for name, value in os.environ.items()
            if not any(word in name.upper() for word in
                       ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
            and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))
        }

    @staticmethod
    def _name(generation_id: str) -> str:
        if not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")
        return f"gov-substrate-{generation_id}"

    def _podman(self, *args: str, timeout: int = 15) -> str:
        result = subprocess.run(
            ["podman", *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            env=self._environment,
        )
        if result.returncode:
            raise RuntimeError("Podman control command failed")
        return result.stdout.strip()

    def _inspect(self, name: str) -> dict | None:
        result = subprocess.run(
            ["podman", "container", "inspect", name], capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=15,
            env=self._environment,
        )
        if result.returncode:
            missing = ("no such container", "no container with name or id")
            if any(message in result.stderr.lower() for message in missing):
                return None
            raise RuntimeError("Podman container inspection failed")
        info = json.loads(result.stdout)[0]
        generation_id = name.removeprefix("gov-substrate-")
        labels = info["Config"].get("Labels") or {}
        if (info["Name"].lstrip("/") != name or
                labels.get(_MANAGED_LABEL) != "true" or
                labels.get(_GENERATION_LABEL) != generation_id or
                labels.get(_OWNER_LABEL) != self.project):
            raise RuntimeError("Podman worker identity mismatch")
        restart = info.get("HostConfig", {}).get(
            "RestartPolicy", {}).get("Name", "no")
        if restart not in ("", "no"):
            raise RuntimeError("Podman worker must not restart")
        return info

    def _run_command(self, generation_id: str) -> list[str]:
        name = self._name(generation_id)
        return [
            "podman", "run", "--name", name,
            "--label", f"{_MANAGED_LABEL}=true",
            "--label", f"{_GENERATION_LABEL}={generation_id}",
            "--label", f"{_OWNER_LABEL}={self.project}",
            "--network=none", "--restart=no", "--userns=auto",
            "--user=65534:65534", "--read-only",
            "--read-only-tmpfs=false", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=32",
            "--tmpfs", "/tmp:rw,nodev,nosuid,noexec,size=16m",
            "--shm-size=16m", "-i", self.image,
        ]

    def run(self, generation_id: str, sealed_context: str) -> str:
        with self._lock:
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            process = subprocess.Popen(
                self._run_command(generation_id), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", errors="replace", env=self._environment,
            )
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
                name = self._name(generation_id)
                info = self._inspect(name)
                if info is None or info["State"]["Running"]:
                    self.stop((generation_id,))
                    raise RuntimeError("local worker exit could not be verified")
                self._podman("container", "rm", info["Id"])
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
                process.kill()
                process.wait(timeout=5)
                info = self._inspect(name)
                if info is None:
                    return StopResult(
                        generation_id, "podman", None, False,
                        "creation_unconfirmed",
                    )
            if info is None:
                return StopResult(generation_id, "podman", None, True, "absent")
            runtime_id = info["Id"]
            if info["State"]["Running"]:
                try:
                    self._podman(
                        "container", "stop", "--time", "1", runtime_id,
                        timeout=8,
                    )
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                info = self._inspect(name)
                if info is not None and info["State"]["Running"]:
                    self._podman("container", "kill", runtime_id, timeout=8)
            self._podman("container", "wait", runtime_id, timeout=8)
            info = self._inspect(name)
            if info is None or info["State"]["Running"]:
                raise RuntimeError("worker exit unverified")
            self._podman("container", "rm", runtime_id)
            if self._inspect(name) is not None:
                raise RuntimeError("worker removal unverified")
            return StopResult(
                generation_id, "podman", runtime_id, True, "stopped"
            )
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            return StopResult(
                generation_id, "podman", runtime_id, False,
                "stop_unconfirmed",
            )
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

    def reconcile(self) -> tuple[StopResult, ...]:
        ids = self._podman(
            "container", "ls", "-aq", "--filter",
            f"label={_MANAGED_LABEL}=true", "--filter",
            f"label={_OWNER_LABEL}={self.project}",
        )
        generations = []
        for runtime_id in ids.splitlines():
            info = json.loads(
                self._podman("container", "inspect", runtime_id)
            )[0]
            labels = info["Config"].get("Labels") or {}
            generation_id = labels.get(_GENERATION_LABEL)
            self._name(generation_id)
            if labels.get(_OWNER_LABEL) != self.project:
                raise RuntimeError("Podman reconciliation owner mismatch")
            generations.append(generation_id)
        return self.stop(tuple(generations))
