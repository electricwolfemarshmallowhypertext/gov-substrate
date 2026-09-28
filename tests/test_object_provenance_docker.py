"""Opt-in Docker replay for classified objects and local publication."""

import base64
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "fixtures" / "egress_registry.yaml"
COMPOSE_FILES = ("compose.network.yaml", "compose.filesystem.yaml", "compose.egress.yaml")
IMAGE = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlFE0YAAAAASUVORK5CYII=")


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_object_publication_from_networkless_actor(tmp_path):
    registry = tmp_path / "registry.yaml"
    registry.write_text(REGISTRY.read_text(encoding="utf-8"), encoding="utf-8")
    project = "govsubstrateobj" + uuid.uuid4().hex[:10]
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

    try:
        run("docker", "volume", "create", volume)
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
        cases = [
            {"classification": "private", "media_type": "image/png",
             "content_base64": base64.b64encode(IMAGE).decode(),
             "readers": ["agent-a"], "source": "trusted-private-image"},
            {"classification": "public", "media_type": "text/plain",
             "content_base64": base64.b64encode(b"The sky is blue. This is public context.").decode(),
             "readers": ["agent-a"], "source": "trusted-public-text"},
        ]
        import_script = (
            "import json,os\nfrom network_probe import request\n"
            "token=os.environ['GOV_SUBSTRATE_OPERATOR_TOKEN']\n"
            f"cases=json.loads({json.dumps(json.dumps(cases))})\n"
            "created=[]\nfor body in cases:\n"
            "    status,result=request('POST','/objects/import',token,body)\n"
            "    assert status==200 and result['decision']=='allow',(status,result)\n"
            "    created.append(result['object_id'])\nprint(json.dumps(created))")
        ids = json.loads(compose("exec", "-T", "substrate", "python", "-c",
                                 import_script).strip().splitlines()[-1])
        container = compose("ps", "-q", "publisher").strip()
        publisher_ip = run("docker", "inspect", "-f",
                           "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).strip()
        raw = compose("run", "--rm", "-T", "--no-deps", "-e",
                      "RESEARCH_AGENT_TOKEN=lab-agent-a-token", "-e",
                      f"PUBLISHER_IP={publisher_ip}", "-e", f"PRIVATE_IMAGE_ID={ids[0]}",
                      "-e", f"PUBLIC_SOURCE_ID={ids[1]}", "agent", "python", "/app/object_probe.py")
        result = json.loads(raw.strip().splitlines()[-1])
        published = compose("exec", "-T", "publisher", "python", "-c",
                            "from pathlib import Path; print(Path('/tmp/published.jsonl').read_text())")
        assert [json.loads(line)["data"] for line in published.splitlines() if line] == [
            "The sky is blue."]
        audit_json = compose("exec", "-T", "substrate", "python", "-c",
                             "import json,sqlite3; db=sqlite3.connect('/data/substrate.db'); "
                             "print(json.dumps(db.execute('SELECT id,decision,action "
                             "FROM events ORDER BY id').fetchall()))")
        audit = {row[0]: row for row in json.loads(audit_json.strip())}
        assert audit[result["private_event"]][1] == "deny"
        assert audit[result["encoded_event"]][1] == "deny"
        assert audit[result["raw_event"]][1] == "deny"
        assert audit[result["public_event"]][1] == "allow"
        assert any(row[1] == "succeeded" and
                   json.loads(row[2]).get("request_event_id") == result["public_event"]
                   for row in audit.values())
        assert base64.b64encode(IMAGE).decode() not in audit_json
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "volume", "rm", volume],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
