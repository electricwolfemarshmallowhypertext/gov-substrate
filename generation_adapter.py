"""Trusted host-side bridge from a sealed generation to a one-shot worker."""

import base64
import hashlib
import json
import os
import subprocess


def run_generation(client, generation_id: str, operator_token: str,
                   worker_command: list[str]) -> dict:
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

    worker_env = {name: value for name, value in os.environ.items()
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
