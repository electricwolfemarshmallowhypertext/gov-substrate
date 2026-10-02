"""NVIDIA OpenShell backend for supervised, one-shot generation workers."""

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
_MANAGED_LABEL = "gov.substrate.managed"
_GENERATION_LABEL = "gov.substrate.generation_id"
_OWNER_LABEL = "gov.substrate.owner"


class OpenShellRuntimeSupervisor:
    def __init__(self, image: str, policy: str | Path, project: str,
                 gateway: str, cli: str = "openshell"):
        if not isinstance(image, str) or not image.strip():
            raise ValueError("OpenShell worker image required")
        self.policy = Path(policy).resolve(strict=True)
        if not self.policy.is_file():
            raise ValueError("OpenShell policy must be one file")
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("valid lowercase OpenShell owner required")
        if not isinstance(gateway, str) or not gateway.strip():
            raise ValueError("OpenShell gateway name required")
        self.image = image
        self.project = project
        self.gateway = gateway
        self.cli = cli
        self.runtime_name = "openshell"
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
        self._environment["NO_COLOR"] = "1"

    @staticmethod
    def _name(generation_id: str) -> str:
        if not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")
        return f"gs-{generation_id[:16]}"

    def _command(self, *args: str) -> list[str]:
        return [self.cli, "--gateway", self.gateway, "--color", "never", *args]

    def _openshell(self, *args: str, timeout: int = 30) -> str:
        result = subprocess.run(
            self._command(*args), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            env=self._environment,
        )
        if result.returncode:
            raise RuntimeError("OpenShell control command failed")
        return result.stdout.strip()

    @staticmethod
    def _items(output: str) -> list[dict]:
        value = json.loads(output or "[]")
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and isinstance(value.get("items"), list):
            return value["items"]
        if isinstance(value, dict) and isinstance(value.get("sandboxes"), list):
            return value["sandboxes"]
        raise RuntimeError("unexpected OpenShell list response")

    def _list(self, selector: str) -> list[dict]:
        return self._items(self._openshell(
            "sandbox", "list", "--selector", selector, "--output", "json"
        ))

    def _inspect_generation(self, generation_id: str) -> dict | None:
        name = self._name(generation_id)
        items = self._list(
            f"{_OWNER_LABEL}={self.project},{_GENERATION_LABEL}={generation_id}"
        )
        if not items:
            return None
        if len(items) != 1:
            raise RuntimeError("OpenShell generation identity is ambiguous")
        item = items[0]
        labels = item.get("labels") or {}
        if (item.get("name") != name or labels.get(_MANAGED_LABEL) != "true" or
                labels.get(_GENERATION_LABEL) != generation_id or
                labels.get(_OWNER_LABEL) != self.project or not item.get("id")):
            raise RuntimeError("OpenShell sandbox identity mismatch")
        return item

    def _create_command(self, generation_id: str) -> list[str]:
        name = self._name(generation_id)
        return self._command(
            "sandbox", "create", "--name", name,
            "--from", self.image, "--policy", str(self.policy),
            "--no-auto-providers", "--no-keep", "--no-tty",
            "--label", f"{_MANAGED_LABEL}=true",
            "--label", f"{_GENERATION_LABEL}={generation_id}",
            "--label", f"{_OWNER_LABEL}={self.project}", "--",
            "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
            "HOME=/tmp", "/usr/local/bin/gov-runtime-probe",
        )

    def runtime_identity(self, generation_id: str) -> str | None:
        item = self._inspect_generation(generation_id)
        return None if item is None else item["id"]

    def security_state(self, generation_id: str) -> dict[str, str]:
        name = self._name(generation_id)
        output = self._openshell(
            "sandbox", "exec", "--name", name, "--no-login-shell", "--no-tty",
            "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
            "HOME=/tmp", "/bin/cat", "/proc/self/status",
        )
        return {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in output.splitlines() if ":" in line
        }

    def run(self, generation_id: str, sealed_context: str) -> str:
        self._name(generation_id)
        with self._lock:
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            process = subprocess.Popen(
                self._create_command(generation_id), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", errors="replace", env=self._environment,
            )
            self._running[generation_id] = process
        try:
            try:
                stdout, _ = process.communicate(input=sealed_context, timeout=180)
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("OpenShell generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    raise RuntimeError("local generation stopped or failed")
            self._wait_absent(generation_id)
            return stdout
        finally:
            with self._lock:
                self._running.pop(generation_id, None)

    def _wait_absent(self, generation_id: str, timeout: float = 45) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._inspect_generation(generation_id) is None:
                return
            time.sleep(0.2)
        raise RuntimeError("OpenShell sandbox removal could not be verified")

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]:
        with self._lock:
            return tuple(self._stop_one(item) for item in generation_ids)

    def _stop_one(self, generation_id: str) -> StopResult:
        name = self._name(generation_id)
        self._cancelled.add(generation_id)
        process = self._running.get(generation_id)
        runtime_id = None
        try:
            item = self._inspect_generation(generation_id)
            if item is None:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                    return StopResult(generation_id, self.runtime_name, None,
                                      False, "creation_unconfirmed")
                return StopResult(generation_id, self.runtime_name, None,
                                  True, "absent")
            runtime_id = item["id"]
            self._openshell("sandbox", "delete", name, timeout=30)
            self._wait_absent(generation_id)
            return StopResult(generation_id, self.runtime_name, runtime_id,
                              True, "stopped")
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            return StopResult(generation_id, self.runtime_name, runtime_id,
                              False, "stop_unconfirmed")
        finally:
            if process is not None and process.poll() is None:
                process.kill()

    def reconcile(self) -> tuple[StopResult, ...]:
        generations = []
        for item in self._list(f"{_OWNER_LABEL}={self.project}"):
            labels = item.get("labels") or {}
            generation_id = labels.get(_GENERATION_LABEL)
            self._name(generation_id)
            if (labels.get(_MANAGED_LABEL) != "true" or
                    labels.get(_OWNER_LABEL) != self.project):
                raise RuntimeError("OpenShell reconciliation identity mismatch")
            generations.append(generation_id)
        return self.stop(tuple(generations))
