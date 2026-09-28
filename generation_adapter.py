"""Trusted host-side bridge from a sealed generation to a one-shot worker."""

import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class SealedInput:
    media_type: str
    content: bytes


class GenerationAdapter(Protocol):
    def generate(self, inputs: tuple[SealedInput, ...]) -> str: ...


def claim_sealed_inputs(client, generation_id: str,
                        operator_token: str) -> tuple[SealedInput, ...]:
    headers = {"Authorization": f"Bearer {operator_token}"}
    claim = client.post("/generations/claim", headers=headers,
                        json={"generation_id": generation_id})
    if claim.status_code != 200 or claim.json().get("decision") != "allow":
        raise RuntimeError("Sealed generation context could not be claimed")

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
                     adapter: GenerationAdapter) -> dict:
    inputs = claim_sealed_inputs(client, generation_id, operator_token)
    return complete_generated_text(client, generation_id, operator_token,
                                   adapter.generate(inputs))


class SubprocessGenerationAdapter:
    def __init__(self, worker_command: list[str], worker_environment=None):
        self.worker_command = worker_command
        self.worker_environment = worker_environment

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
        process = subprocess.run(self.worker_command, input=json.dumps(envelope),
                                 text=True, capture_output=True, encoding="utf-8",
                                 errors="replace", timeout=120, env=worker_env)
        if process.returncode:
            raise RuntimeError("Isolated generation worker failed")
        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Isolated generation worker returned invalid JSON") from exc
        if (type(result) is not dict or set(result) != {"text"}
                or type(result["text"]) is not str):
            raise RuntimeError("Isolated generation worker returned extra or missing fields")
        return result["text"]


def run_generation(client, generation_id: str, operator_token: str,
                   worker_command: list[str], worker_environment=None) -> dict:
    return run_with_adapter(client, generation_id, operator_token,
                            SubprocessGenerationAdapter(worker_command, worker_environment))


def run_local_generation(client, generation_id: str, operator_token: str,
                         model_blob: str | Path, project: str | None = None) -> dict:
    """Run one claimed manifest through the fixed, networkless local worker."""
    model_path = Path(model_blob).resolve(strict=True)
    if not model_path.is_file():
        raise ValueError("local model artifact must be one file")
    with model_path.open("rb") as model_file:
        if model_file.read(4) != b"GGUF":
            raise ValueError("local model artifact must be GGUF")

    compose_file = Path(__file__).with_name("compose.local-generation.yaml")
    command = ["docker", "compose", "-f", str(compose_file)]
    if project is not None:
        command.extend(["-p", project])
    command.extend(["run", "--rm", "-T", "--no-deps", "generator"])
    worker_environment = dict(os.environ)
    worker_environment["GENERATION_MODEL_BLOB"] = str(model_path)
    return run_generation(client, generation_id, operator_token, command,
                          worker_environment=worker_environment)
