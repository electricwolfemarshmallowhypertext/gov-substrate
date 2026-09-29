"""Trusted host-side bridge from a sealed generation to a one-shot worker."""

import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Protocol

from runtime_supervisor import RuntimeSupervisor


@dataclass(frozen=True)
class SealedInput:
    media_type: str
    content: bytes


class GenerationAdapter(Protocol):
    service_id: str | None
    def generate(self, inputs: tuple[SealedInput, ...]) -> str: ...


def claim_sealed_inputs(client, generation_id: str,
                        operator_token: str, execution_token: str,
                        service_id: str | None = None) -> tuple[SealedInput, ...]:
    headers = {"Authorization": f"Bearer {operator_token}"}
    request = {"generation_id": generation_id, "execution_token": execution_token}
    if service_id is not None:
        request["provider"] = service_id
    claim = client.post("/generations/claim", headers=headers,
                        json=request)
    if claim.status_code != 200 or claim.json().get("decision") != "allow":
        raise RuntimeError("Sealed generation context could not be claimed")
    if claim.json().get("provider") != service_id:
        raise RuntimeError("Sealed generation provider mismatch")

    inputs: list[SealedInput] = []
    for source in claim.json()["inputs"]:
        payload = base64.b64decode(source["content_base64"], validate=True)
        if hashlib.sha256(payload).hexdigest() != source["sha256"]:
            raise RuntimeError("Sealed generation input hash mismatch")
        inputs.append(SealedInput(source["media_type"], payload))
    return tuple(inputs)


def complete_generated_text(client, generation_id: str,
                            operator_token: str, text: str) -> dict:
    if type(text) is not str or not text.strip():
        raise RuntimeError("Generation adapter returned no text")
    headers = {"Authorization": f"Bearer {operator_token}"}
    completion = client.post("/generations/complete", headers=headers,
                             json={"generation_id": generation_id, "text": text})
    if completion.status_code != 200 or completion.json().get("decision") != "succeeded":
        raise RuntimeError("Sealed generation completion was denied")
    return completion.json()


def run_with_adapter(client, generation_id: str, operator_token: str,
                     adapter: GenerationAdapter, execution_token: str) -> dict:
    if not hasattr(adapter, "service_id"):
        raise RuntimeError("Generation adapter must declare its service")
    inputs = claim_sealed_inputs(client, generation_id, operator_token, execution_token,
                                 adapter.service_id)
    return complete_generated_text(client, generation_id, operator_token,
                                   adapter.generate(inputs))


class SubprocessGenerationAdapter:
    service_id = None
    def __init__(self, worker_command: list[str], worker_environment=None):
        self.worker_command = worker_command
        self.worker_environment = worker_environment

    def _run(self, envelope: str, worker_env: dict) -> tuple[int, str]:
        process = subprocess.Popen(self.worker_command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace",
                                   env=worker_env)
        try:
            stdout, _ = process.communicate(input=envelope, timeout=120)
            return process.returncode, stdout
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("Isolated generation worker timed out") from None

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        source_environment = (os.environ if self.worker_environment is None
                              else self.worker_environment)
        worker_env = {name: value for name, value in source_environment.items()
                      if not any(word in name.upper() for word in
                                 ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
                      and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
        envelope = {"inputs": [{"media_type": source.media_type,
                                "content_base64": base64.b64encode(source.content).decode()}
                               for source in inputs]}
        returncode, stdout = self._run(json.dumps(envelope), worker_env)
        if returncode:
            raise RuntimeError("Isolated generation worker failed")
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Isolated generation worker returned invalid JSON") from exc
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise RuntimeError("Isolated generation worker returned extra or missing fields")
        return result["text"]


class SupervisedGenerationAdapter:
    service_id = None

    def __init__(self, generation_id: str, runtime: RuntimeSupervisor):
        self.generation_id = generation_id
        self.runtime = runtime

    def generate(self, inputs: tuple[SealedInput, ...]) -> str:
        envelope = {"inputs": [{"media_type": source.media_type,
                                "content_base64": base64.b64encode(source.content).decode()}
                               for source in inputs]}
        stdout = self.runtime.run(self.generation_id, json.dumps(envelope))
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Isolated generation worker returned invalid JSON") from exc
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise RuntimeError("Isolated generation worker returned extra or missing fields")
        return result["text"]


def run_generation(client, generation_id: str, operator_token: str,
                   worker_command: list[str], execution_token: str,
                   worker_environment=None) -> dict:
    return run_with_adapter(client, generation_id, operator_token,
                            SubprocessGenerationAdapter(worker_command, worker_environment),
                            execution_token)


def run_local_generation(client, generation_id: str, operator_token: str,
                         execution_token: str, runtime: RuntimeSupervisor) -> dict:
    """Run one claimed manifest through the fixed, networkless local worker."""
    if runtime is None:
        raise ValueError("local generation requires a runtime supervisor")
    return run_with_adapter(client, generation_id, operator_token,
                            SupervisedGenerationAdapter(generation_id, runtime),
                            execution_token)
