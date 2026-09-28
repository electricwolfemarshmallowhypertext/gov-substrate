"""Trusted host-side bridge from a sealed generation to a one-shot worker."""

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path


def run_generation(client, generation_id: str, operator_token: str,
                   worker_command: list[str], worker_environment=None) -> dict:
    headers = {"Authorization": f"Bearer {operator_token}"}
    claim = client.post("/generations/claim", headers=headers,
                        json={"generation_id": generation_id})
    if claim.status_code != 200 or claim.json().get("decision") != "allow":
        raise RuntimeError("Sealed generation context could not be claimed")

    inputs = []
    for source in claim.json()["inputs"]:
        payload = base64.b64decode(source["content_base64"], validate=True)
        if hashlib.sha256(payload).hexdigest() != source["sha256"]:
            raise RuntimeError("Sealed generation input hash mismatch")
        inputs.append({"media_type": source["media_type"],
                       "content_base64": source["content_base64"]})

    source_environment = os.environ if worker_environment is None else worker_environment
    worker_env = {name: value for name, value in source_environment.items()
                  if not any(word in name.upper() for word in
                             ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
                  and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
    process = subprocess.run(worker_command, input=json.dumps({"inputs": inputs}),
                             text=True, capture_output=True, encoding="utf-8",
                             errors="replace", timeout=120, env=worker_env)
    if process.returncode:
        raise RuntimeError("Isolated generation worker failed")
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Isolated generation worker returned invalid JSON") from exc
    if type(result) is not dict or set(result) != {"text"} or not isinstance(result["text"], str):
        raise RuntimeError("Isolated generation worker returned extra or missing fields")

    completion = client.post("/generations/complete", headers=headers,
                             json={"generation_id": generation_id, "text": result["text"]})
    if completion.status_code != 200 or completion.json().get("decision") != "succeeded":
        raise RuntimeError("Sealed generation completion was denied")
    return completion.json()


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
