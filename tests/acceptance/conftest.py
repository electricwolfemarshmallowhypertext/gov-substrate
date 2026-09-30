"""Real-runtime acceptance prerequisites. Missing prerequisites fail when enabled."""

import os
import subprocess
import hashlib
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
LOCAL_COMPOSE = ROOT / "compose.local-generation.yaml"
MODEL_ARTIFACTS = {
    "Qwen3-0.6B-Q8_0.gguf": (
        804753088, "12fae8b8f78f0360b498d04c8db7d33aff29ab7d8080231f93a17c18119e6735"),
    "Phi-4-mini-instruct-Q8_0.gguf": (
        4084611392, "3e81a3ad900b6d67df011d42ef14bad63354a3516fbd229b9bf29755363b25ee"),
}


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
        pytest.skip("set RUN_ACCEPTANCE_TESTS=1 for real runtime acceptance")
    backend = os.getenv("RUNTIME_CONFORMANCE_BACKEND")
    if backend == "wasmtime":
        executable = os.getenv("WASMTIME_BIN")
        module = os.getenv("WASMTIME_MODULE")
        assert executable and Path(executable).resolve(strict=True).is_file()
        module_path = Path(module).resolve(strict=True) if module else None
        assert module_path is not None and module_path.is_file()
        assert module_path.read_bytes()[:4] == b"\0asm"
    elif backend == "podman":
        result = subprocess.run(
            ["podman", "info", "--format", "json"], capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=20,
            env=docker_environment(),
        )
        assert result.returncode == 0, result.stderr or result.stdout
    elif backend == "native-linux":
        launcher = os.getenv("NATIVE_LINUX_LAUNCHER")
        worker = os.getenv("NATIVE_PROBE")
        cgroup_root = os.getenv("NATIVE_CGROUP_ROOT")
        assert launcher and os.access(Path(launcher).resolve(strict=True), os.X_OK)
        assert worker and os.access(Path(worker).resolve(strict=True), os.X_OK)
        root = Path(cgroup_root).resolve(strict=True) if cgroup_root else None
        assert root is not None and (root / "cgroup.controllers").is_file()
    elif backend == "native-windows":
        worker = os.getenv("NATIVE_PROBE")
        path = Path(worker).resolve(strict=True) if worker else None
        assert path is not None and path.is_file() and path.suffix.lower() == ".exe"
    else:
        docker_command("info", "--format", "{{.ServerVersion}}", timeout=20)


@pytest.fixture(scope="session")
def local_model_blob(acceptance_enabled):
    configured = os.getenv("GENERATION_MODEL_BLOB")
    assert configured, "GENERATION_MODEL_BLOB must name a pinned local acceptance model"
    path = Path(configured).resolve(strict=True)
    assert path.is_file()
    assert path.name in MODEL_ARTIFACTS, "unrecognized local acceptance model"
    expected_size, expected_sha256 = MODEL_ARTIFACTS[path.name]
    assert path.stat().st_size == expected_size, "local model size mismatch"
    digest = hashlib.sha256()
    with path.open("rb") as model:
        assert model.read(4) == b"GGUF"
        model.seek(0)
        for chunk in iter(lambda: model.read(1024 * 1024), b""):
            digest.update(chunk)
    assert digest.hexdigest() == expected_sha256, "local model SHA-256 mismatch"
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
