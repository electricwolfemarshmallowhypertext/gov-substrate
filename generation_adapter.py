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


@dataclass(frozen=True)
class SealedGeneration:
    generation_id: str
    provider: str | None
    inputs: tuple[SealedInput, ...]
    input_ids: tuple[str, ...]
    input_hashes: tuple[str, ...]
    provider_request: dict | None
    request_hash: str | None
    gateway_credential: str | None


class GenerationAdapter(Protocol):
    service_id: str | None
    def generate(self, inputs: tuple[SealedInput, ...]) -> str: ...


class GatewayGenerationAdapter(Protocol):
    service_id: str
    def generate_gateway(self, claim: SealedGeneration) -> tuple[str, dict]: ...


def claim_generation_context(client, generation_id: str,
                             operator_token: str, execution_token: str,
                             service_id: str | None = None) -> SealedGeneration:
    headers = {"Authorization": f"Bearer {operator_token}"}
    request = {"generation_id": generation_id, "execution_token": execution_token}
    if service_id is not None:
        request["provider"] = service_id
    response = client.post("/generations/claim", headers=headers, json=request)
    if response.status_code != 200 or response.json().get("decision") != "allow":
        raise RuntimeError("Sealed generation context could not be claimed")
    claim = response.json()
    if claim.get("provider") != service_id:
        raise RuntimeError("Sealed generation provider mismatch")

    inputs: list[SealedInput] = []
    ids: list[str] = []
    hashes: list[str] = []
    for source in claim["inputs"]:
        payload = base64.b64decode(source["content_base64"], validate=True)
        if hashlib.sha256(payload).hexdigest() != source["sha256"]:
            raise RuntimeError("Sealed generation input hash mismatch")
        inputs.append(SealedInput(source["media_type"], payload))
        ids.append(source["id"])
        hashes.append(source["sha256"])
    return SealedGeneration(
        generation_id, service_id, tuple(inputs), tuple(ids), tuple(hashes),
        claim.get("provider_request"), claim.get("request_hash"),
        claim.get("gateway_credential"))


def claim_sealed_inputs(client, generation_id: str,
                        operator_token: str, execution_token: str,
                        service_id: str | None = None) -> tuple[SealedInput, ...]:
    return claim_generation_context(client, generation_id, operator_token,
                                    execution_token, service_id).inputs


def complete_generated_text(client, generation_id: str,
                            operator_token: str, text: str,
                            receipt: dict | None = None) -> dict:
    if type(text) is not str or not text.strip():
        raise RuntimeError("Generation adapter returned no text")
    headers = {"Authorization": f"Bearer {operator_token}"}
    request = {"generation_id": generation_id, "text": text}
    if receipt is not None:
        request["receipt"] = receipt
    completion = client.post("/generations/complete", headers=headers, json=request)
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


def run_with_gateway(client, generation_id: str, operator_token: str,
                     adapter: GatewayGenerationAdapter, execution_token: str) -> dict:
    claim = claim_generation_context(client, generation_id, operator_token,
                                     execution_token, adapter.service_id)
    if claim.gateway_credential is None or claim.request_hash is None:
        raise RuntimeError("Generation did not require the provider gateway")
    text, receipt = adapter.generate_gateway(claim)
    return complete_generated_text(client, generation_id, operator_token, text, receipt)


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
