"""Opt-in Docker test for mediated file access and workspace integrity."""

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = ROOT / "compose.network.yaml"
FILESYSTEM_COMPOSE = ROOT / "compose.filesystem.yaml"
FIXTURE_REGISTRY = ROOT / "tests" / "fixtures" / "filesystem_registry.yaml"


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_filesystem_authority_and_integrity(tmp_path):
    registry = tmp_path / "filesystem_registry.yaml"
    original_policy = FIXTURE_REGISTRY.read_text(encoding="utf-8")
    registry.write_text(original_policy, encoding="utf-8")
    project = "govsubstratefs" + uuid.uuid4().hex[:10]
    volume = f"{project}_workspace"
    env = {key: value for key, value in os.environ.items() if not key.endswith("_API_KEY")}
    env.update(LAB_REGISTRY_PATH=str(registry), LAB_IMAGE_TAG=project,
               LAB_WORKSPACE_VOLUME=volume)
    prefix = ["docker", "compose", "-p", project, "-f", str(BASE_COMPOSE),
              "-f", str(FILESYSTEM_COMPOSE)]

    def run(*args):
        result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=240)
        assert result.returncode == 0, f"{' '.join(args)}\n{result.stdout}\n{result.stderr}"
        return result.stdout

    def compose(*args):
        return run(*prefix, *args)

    def probe(phase, old_token=None):
        args = ["run", "--rm", "--no-deps"]
        if old_token:
            args.extend(["-e", f"OLD_SESSION_TOKEN={old_token}"])
        args.extend(["agent", "python", "/app/filesystem_probe.py", phase])
        return json.loads(compose(*args).strip().splitlines()[-1])

    try:
        run("docker", "volume", "create", volume)
        seed = ("from pathlib import Path; p=Path('/workspace'); "
                "(p/'permitted.txt').write_text('permitted seed\\n'); "
                "(p/'protected.txt').write_text('protected seed\\n'); "
                "(p/'escape').symlink_to('/etc',target_is_directory=True)")
        run("docker", "run", "--rm", "-v", f"{volume}:/workspace", "python:3.12-slim",
            "python", "-c", seed)
        compose("build", "substrate")
        compose("up", "-d", "substrate")
        bridged = subprocess.run(
            [*prefix, "run", "--rm", "-T", "--no-deps", "agent",
             "python", "/app/filesystem_tool.py"],
            input=json.dumps({"kind": "filesystem.read", "path": "permitted.txt"}),
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=240,
        )
        assert bridged.returncode == 0, bridged.stderr
        assert json.loads(bridged.stdout.strip().splitlines()[-1])["outcome"] == "succeeded"
        first = probe("first")
        assert first["direct_blocked"] is True

        inspect = ("import json,sqlite3; from pathlib import Path; "
                   "db=sqlite3.connect('/data/substrate.db'); "
                   "print(json.dumps({'draft':Path('/workspace/draft.txt').read_text(),"
                   "'protected':Path('/workspace/protected.txt').read_text(),"
                   "'events':db.execute('SELECT id,decision,action FROM events ORDER BY id').fetchall()}))")
        observed = json.loads(compose("exec", "-T", "substrate", "python", "-c", inspect).strip())
        assert observed["draft"] == "admitted content\n"
        assert observed["protected"] == "protected seed\n"
        audit = {row[0]: row for row in observed["events"]}
        assert audit[first["read_event"]][1] == "allow"
        assert audit[first["read_outcome"]][1] == "succeeded"
        assert audit[first["write_event"]][1] == "allow"
        assert audit[first["write_outcome"]][1] == "succeeded"
        assert audit[first["protected_event"]][1] == "deny"
        assert "content" not in json.loads(audit[first["write_event"]][2])

        registry.write_text(original_policy.replace("      protected:\n        - protected.txt",
                                                    "      protected: []"), encoding="utf-8")
        second = probe("yaml_changed", first["session_token"])
        assert second["direct_blocked"] is True
        compose("restart", "substrate")
        third = probe("changed_registry_restart")
        assert third["registry_failed_closed"] is True

        registry.write_text(original_policy, encoding="utf-8")
        compose("restart", "substrate")
        compose("exec", "-T", "substrate", "python", "-c",
                "from pathlib import Path; Path('/workspace/draft.txt').write_text('tampered')")
        fourth = probe("corruption", second["session_token"])
        assert fourth["direct_blocked"] is True
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "volume", "rm", volume],
                       capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       capture_output=True, timeout=60)
