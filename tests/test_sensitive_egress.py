"""Opt-in Docker test for private-data publication authority."""

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from substrate import Substrate


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "fixtures" / "egress_registry.yaml"
COMPOSE_FILES = ("compose.network.yaml", "compose.filesystem.yaml", "compose.egress.yaml")
SECRET = "PRIVATE_EGRESS_SENTINEL_4e8d7b"


def test_sensitive_actor_rejects_legacy_workspace(tmp_path):
    actor = {"data": {"sensitive_access": True},
             "network": {"allowed": False, "services": []},
             "filesystem": {"read": True, "write": "workspace_only"},
             "tools": {}, "persistence": {}, "shared_channels": []}
    with pytest.raises(ValueError, match="scoped filesystem authority"):
        Substrate(tmp_path / "legacy.db", {
            "actors": {"agent-a": actor}, "tokens": {"actor-token": "agent-a"},
            "operator_token": "operator-token"})


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_sensitive_publication_and_shared_channel_denial(tmp_path):
    registry = tmp_path / "registry.yaml"
    registry.write_text(REGISTRY.read_text(encoding="utf-8"), encoding="utf-8")
    project = "govsubstrateeg" + uuid.uuid4().hex[:10]
    volume = project + "_workspace"
    env = {name: value for name, value in os.environ.items()
           if not any(word in name.upper() for word in
                      ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
           and not name.startswith(("OPENAI_", "ANTHROPIC_", "OPENROUTER_"))}
    env.update(LAB_REGISTRY_PATH=str(registry), LAB_IMAGE_TAG=project,
               LAB_WORKSPACE_VOLUME=volume)
    prefix = ["docker", "compose", "-p", project,
              *(part for filename in COMPOSE_FILES for part in ("-f", str(ROOT / filename)))]

    def run(*args, timeout=240):
        result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=timeout)
        assert result.returncode == 0, f"{' '.join(args)}\n{result.stdout}\n{result.stderr}"
        return result.stdout

    def compose(*args):
        return run(*prefix, *args)

    def probe(phase, actor, publisher_ip):
        output = compose("run", "--rm", "-T", "--no-deps", "-e",
                         f"RESEARCH_AGENT_TOKEN=lab-agent-{actor}-token",
                         "-e", f"PUBLISHER_IP={publisher_ip}", "agent",
                         "python", "/app/egress_probe.py", phase)
        return json.loads(output.strip().splitlines()[-1])

    try:
        run("docker", "volume", "create", volume)
        seed = ("import hashlib; from pathlib import Path; "
                "root=Path('/workspace/.substrate-scoped/actor')/"
                "hashlib.sha256(b'agent-a').hexdigest(); "
                "root.mkdir(parents=True); "
                f"(root/'private.txt').write_text({SECRET!r}, encoding='utf-8')")
        run("docker", "run", "--rm", "-v", f"{volume}:/workspace",
            "python:3.12-slim", "python", "-c", seed)
        compose("build", "substrate")
        compose("up", "-d", "publisher", "substrate")
        for _ in range(30):
            ready = subprocess.run([*prefix, "exec", "-T", "publisher", "python", "-c",
                                    "import socket; socket.create_connection(('127.0.0.1',8003),1).close()"],
                                   cwd=ROOT, env=env, capture_output=True, timeout=10)
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("publisher fixture unavailable")
        container = compose("ps", "-q", "publisher").strip()
        publisher_ip = run("docker", "inspect", "-f",
                           "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).strip()

        first = probe("private_actor", "a", publisher_ip)
        reset = probe("reset_private_actor", "a", publisher_ip)
        public = probe("public_actor", "b", publisher_ip)

        published = compose("exec", "-T", "publisher", "python", "-c",
                            "from pathlib import Path; print(Path('/tmp/published.jsonl').read_text())")
        assert [json.loads(line)["data"] for line in published.splitlines() if line] == ["public-summary"]
        audit_json = compose("exec", "-T", "substrate", "python", "-c",
                             "import json,sqlite3; db=sqlite3.connect('/data/substrate.db'); "
                             "print(json.dumps(db.execute('SELECT id,actor,decision,action,"
                             "state_before,state_after FROM events ORDER BY id').fetchall()))")
        assert SECRET not in audit_json
        audit = {row[0]: row for row in json.loads(audit_json.strip())}
        for event_id in (*first["events"].values(), reset["event"]):
            assert audit[event_id][2] == "deny"
            assert not any(json.loads(row[3]).get("request_event_id") == event_id
                           for row in audit.values())
        assert audit[public["publication"]][2] == "allow"
        assert any(row[2] == "succeeded" and
                   json.loads(row[3]).get("request_event_id") == public["publication"]
                   for row in audit.values())
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "volume", "rm", volume],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
