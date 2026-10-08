"""Opt-in Docker replay of sealed context through a fresh isolated worker."""

import base64
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from governance_substrate.generation_adapter import run_generation
from governance_substrate.substrate import Substrate, create_app


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose/compose.generation.yaml"


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_fresh_worker_receives_only_sealed_context(tmp_path, monkeypatch):
    project = "govsubstrategen" + uuid.uuid4().hex[:10]
    monkeypatch.setenv("LAB_IMAGE_TAG", project)
    env = {name: value for name, value in os.environ.items()
           if not any(word in name.upper() for word in
                      ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
           and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
    prefix = ["docker", "compose", "-p", project, "-f", str(COMPOSE)]

    def docker(*args):
        result = subprocess.run([*prefix, *args], cwd=ROOT, env=env,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=240)
        assert result.returncode == 0, result.stderr
        return result.stdout

    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "generation-docker.db", {
        "actors": {"agent-a": actor}, "tokens": {"agent-token": "agent-a"},
        "operator_token": "operator-token"})
    client = TestClient(create_app(substrate))
    operator = {"Authorization": "Bearer operator-token"}
    agent = {"Authorization": "Bearer agent-token"}

    def imported(classification, content):
        response = client.post("/objects/import", headers=operator, json={
            "classification": classification, "media_type": "text/plain",
            "content_base64": base64.b64encode(content.encode()).decode(),
            "readers": ["agent-a"], "source": "trusted-fixture"})
        assert response.status_code == 200
        return response.json()["object_id"]

    prompt_id = imported("public", "Use only the supplied context.")
    private_id = imported("private", "Private fixture.")
    public_id = imported("public", "Public fixture.")
    agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]

    def generate(input_ids):
        prepared = client.post("/proposals", headers=agent, json={"action": {
            "kind": "generation.prepare", "input_ids": input_ids}}).json()
        assert prepared["decision"] == "allow", prepared
        return run_generation(client, prepared["generation_id"], "operator-token",
                              [*prefix, "run", "--rm", "-T", "--no-deps", "generator"],
                              prepared["execution_token"])

    try:
        config = json.loads(docker("config", "--format", "json"))["services"]["generator"]
        assert config["network_mode"] == "none"
        assert not config.get("volumes") and not config.get("environment")
        assert config["read_only"] is True and config["cap_drop"] == ["ALL"]
        docker("build", "generator")
        private = generate([prompt_id, private_id])
        assert private["classification"] == "private"
        assert private["parents"] == [prompt_id, private_id]
        public = generate([prompt_id, public_id])
        assert public["classification"] == "public"
        assert public["parents"] == [prompt_id, public_id]
        read = client.post("/proposals", headers=agent, json={"action": {
            "kind": "object.read", "object_id": public["object_id"]}}).json()
        assert base64.b64decode(read["content_base64"]) == (
            b"Use only the supplied context. | Public fixture.")
        assert b"Private fixture" not in base64.b64decode(read["content_base64"])
        unmediated = subprocess.run([*prefix, "run", "--rm", "-T", "--no-deps", "generator"],
                                    cwd=ROOT, env=env, input=json.dumps({"inputs": [
                                        {"media_type": "text/plain", "content_base64":
                                         base64.b64encode(b"Public fixture.").decode()}],
                                        "prompt": "Unmediated instruction"}),
                                    capture_output=True, text=True, timeout=120)
        assert unmediated.returncode != 0
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
