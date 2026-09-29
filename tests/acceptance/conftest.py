"""Real-runtime acceptance prerequisites. Missing prerequisites fail when enabled."""

import os
import subprocess
import hashlib
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
LOCAL_COMPOSE = ROOT / "compose.local-generation.yaml"
QWEN_Q8_SHA256 = "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031"


def docker_environment():
    return {name: value for name, value in os.environ.items()
            if not any(word in name.upper() for word in
                       ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
            and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}


def docker_command(*args, env=None, timeout=1200):
    result = subprocess.run(["docker", *args], cwd=ROOT,
                            env=docker_environment() if env is None else env,
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout


@pytest.fixture(scope="session", autouse=True)
def acceptance_enabled():
    if os.getenv("RUN_ACCEPTANCE_TESTS") != "1":
        pytest.skip("set RUN_ACCEPTANCE_TESTS=1 for real Docker acceptance")
    docker_command("info", "--format", "{{.ServerVersion}}", timeout=20)


@pytest.fixture(scope="session")
def local_model_blob(acceptance_enabled):
    configured = os.getenv("GENERATION_MODEL_BLOB")
    assert configured, "GENERATION_MODEL_BLOB must name the official Qwen3-0.6B-Q8_0.gguf"
    path = Path(configured).resolve(strict=True)
    assert path.is_file()
    digest = hashlib.sha256()
    with path.open("rb") as model:
        assert model.read(4) == b"GGUF"
        model.seek(0)
        for chunk in iter(lambda: model.read(1024 * 1024), b""):
            digest.update(chunk)
    assert digest.hexdigest() == QWEN_Q8_SHA256, "official Qwen Q8_0 SHA-256 mismatch"
    return path


@pytest.fixture(scope="session")
def local_generator_image(local_model_blob):
    previous_tag = os.environ.get("LAB_IMAGE_TAG")
    os.environ["LAB_IMAGE_TAG"] = "acceptance" + uuid.uuid4().hex[:10]
    env = docker_environment()
    env["GENERATION_MODEL_BLOB"] = str(local_model_blob)
    try:
        docker_command("compose", "-f", str(LOCAL_COMPOSE), "build", "generator",
                       env=env)
        yield env
    finally:
        if previous_tag is None:
            os.environ.pop("LAB_IMAGE_TAG", None)
        else:
            os.environ["LAB_IMAGE_TAG"] = previous_tag
        subprocess.run(["docker", "image", "rm",
                        f"gov-substrate-local-generator:{env['LAB_IMAGE_TAG']}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
