"""Opt-in real local inference in the networkless, one-shot worker."""

import base64
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from generation_adapter import run_local_generation
from substrate import Substrate, create_app


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.local-generation.yaml"


@pytest.mark.skipif(os.getenv("RUN_LOCAL_MODEL_TESTS") != "1",
                    reason="set RUN_LOCAL_MODEL_TESTS=1 with GENERATION_MODEL_BLOB")
def test_real_model_receives_only_sealed_context(tmp_path, monkeypatch):
    model_blob = Path(os.environ["GENERATION_MODEL_BLOB"]).resolve(strict=True)
    project = "govsubstratelocal" + uuid.uuid4().hex[:10]
    monkeypatch.setenv("LAB_IMAGE_TAG", project)
    env = {name: value for name, value in os.environ.items()
           if not any(word in name.upper() for word in
                      ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
           and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
    prefix = ["docker", "compose", "-p", project, "-f", str(COMPOSE)]

    def docker(*args, input_text=None):
        result = subprocess.run([*prefix, *args], cwd=ROOT, env=env,
                                input=input_text, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=240)
        assert result.returncode == 0, result.stderr
        return result.stdout

    actor = {"network": {"allowed": False},
             "filesystem": {"read": False, "write": False},
             "tools": {}, "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "local-generation.db", {
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

    def generate(input_ids):
        prepared = client.post("/proposals", headers=agent, json={"action": {
            "kind": "generation.prepare", "input_ids": input_ids}}).json()
        assert prepared["decision"] == "allow", prepared
        return run_local_generation(client, prepared["generation_id"],
                                    "operator-token", model_blob, project)

    try:
        config = json.loads(docker("config", "--format", "json"))["services"]["generator"]
        assert config["network_mode"] == "none"
        assert config["read_only"] is True and config["cap_drop"] == ["ALL"]
        assert config["security_opt"] == ["no-new-privileges:true"]
        assert config["entrypoint"][:2] == ["/usr/bin/env", "-i"]
        assert not config.get("environment")
        volumes = config["volumes"]
        assert len(volumes) == 1 and volumes[0]["target"] == "/model/model.gguf"
        assert volumes[0]["read_only"] is True
        assert Path(volumes[0]["source"]).resolve() == model_blob
        docker("build", "generator")

        # Direct worker requests cannot append prompt text or conversation history.
        sealed = {"inputs": [{"media_type": "text/plain",
                              "content_base64": base64.b64encode(b"Governed prompt.").decode()}]}
        for extra in ({"prompt": "outside instruction"},
                      {"history": [{"role": "user", "content": "prior turn"}]},
                      {"file_path": "/workspace/.hidden"}):
            attempted = subprocess.run([*prefix, "run", "--rm", "-T", "--no-deps",
                                        "generator"], cwd=ROOT, env=env,
                                       input=json.dumps({**sealed, **extra}),
                                       capture_output=True, text=True, timeout=120)
            assert attempted.returncode != 0

        # Production entrypoint clears even explicitly injected Docker env context.
        probe = docker("run", "--rm", "-T", "--no-deps", "-e",
                       "EXTRA_CONTEXT=host-sentinel", "--entrypoint", "/usr/bin/env",
                       "generator", "-i", "PATH=/usr/local/bin:/usr/bin:/bin",
                       "HOME=/tmp", "PYTHONDONTWRITEBYTECODE=1", "OMP_NUM_THREADS=2",
                       "OPENBLAS_NUM_THREADS=1", "python", "-c",
                       "import os; assert 'EXTRA_CONTEXT' not in os.environ")
        assert probe == ""

        # The only host bind is the model file; hidden workspace files do not exist.
        hidden = tmp_path / ".hidden-context"
        hidden.write_text("host-only sentinel")
        docker("run", "--rm", "-T", "--no-deps", "--entrypoint", "python",
               "generator", "-c", "from pathlib import Path; "
               "assert not Path('/workspace').exists(); "
               "assert not Path('/ipc').exists(); "
               "assert not Path('/run/secrets').exists(); "
               "assert [p.name for p in Path('/model').iterdir()] == ['model.gguf']")

        prompt = imported("public", "Complete this sentence: The garden is")
        private_input = imported("private", "A private note says blue windows.")
        public_input = imported("public", "A public note says green trees.")
        agent["X-Session-Token"] = client.post("/sessions", headers=agent).json()["session_token"]
        private = generate([prompt, private_input])
        assert private["classification"] == "private"
        assert private["parents"] == [prompt, private_input]
        assert private["object_id"]
        public = generate([prompt, public_input])
        assert public["classification"] == "public"
        assert public["parents"] == [prompt, public_input]
        assert public["object_id"] != private["object_id"]
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-local-generator:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
