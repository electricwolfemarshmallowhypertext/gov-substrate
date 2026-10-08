"""A real reachable service remains outside the agent's network grant."""

import json
import subprocess
import time
import uuid
from pathlib import Path

from tests.acceptance.conftest import ROOT, docker_command, docker_environment


NETWORK_COMPOSE = ROOT / "deploy/compose/compose.network.yaml"
ACCEPTANCE_COMPOSE = ROOT / "deploy/compose/acceptance.network.yaml"
REGISTRY = ROOT / "tests" / "fixtures" / "network_registry.yaml"


def test_reachable_third_party_is_denied_to_isolated_agent(tmp_path, acceptance_enabled):
    registry = tmp_path / "network_registry.yaml"
    registry.write_bytes(REGISTRY.read_bytes())
    project = "govnetaccept" + uuid.uuid4().hex[:10]
    env = docker_environment()
    env.update(LAB_REGISTRY_PATH=str(registry), LAB_IMAGE_TAG=project)
    prefix = ["compose", "-p", project, "-f", str(NETWORK_COMPOSE),
              "-f", str(ACCEPTANCE_COMPOSE)]

    def compose(*args, timeout=240):
        return docker_command(*prefix, *args, env=env, timeout=timeout)

    try:
        compose("build", "substrate", timeout=1200)
        compose("up", "-d", "fixture", "thirdparty", "substrate")
        thirdparty_id = compose("ps", "-q", "thirdparty").strip()
        fixture_id = compose("ps", "-q", "fixture").strip()
        assert thirdparty_id and fixture_id
        thirdparty_ip = docker_command("inspect", "-f",
                                      "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                                      thirdparty_id, env=env).strip()
        assert thirdparty_ip

        # Real HTTP from the substrate proves that the denied target is reachable.
        for _ in range(40):
            reachable = subprocess.run(
                ["docker", *prefix, "exec", "-T", "substrate", "python", "-c",
                 "import urllib.request; "
                 "print(urllib.request.urlopen('http://thirdparty:8002/', timeout=2).status)"],
                cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
            if reachable.returncode == 0 and reachable.stdout.strip() == "200":
                break
            time.sleep(0.25)
        else:
            raise AssertionError("third party was not reachable by substrate")

        direct = subprocess.run(
            ["docker", *prefix, "run", "--rm", "--no-deps", "agent", "python", "-c",
             "import socket; socket.create_connection((%r, 8002), timeout=2)" % thirdparty_ip],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        assert direct.returncode != 0, "isolated agent reached third party directly"
        assert "OSError" in direct.stderr or "Network is unreachable" in direct.stderr

        agent_output = compose("run", "--rm", "--no-deps", "-e",
                               "TOOL_URL=http://thirdparty:8002/", "agent", "python",
                               "/app/network_probe.py", "tool")
        result = json.loads(agent_output.strip().splitlines()[-1])
        assert result["direct_blocked"] is True
        assert result["proposal"]["decision"] == "deny"
        assert result["proposal"]["reason"] == "destination_not_allowed"
        event_id = result["proposal"]["event_id"]
        audit = json.loads(compose(
            "exec", "-T", "substrate", "python", "-c",
            "import json,sqlite3; d=sqlite3.connect('/data/substrate.db'); "
            "print(json.dumps(d.execute('SELECT id,decision,action FROM events ORDER BY id').fetchall()))"
        ).strip())
        assert any(row[0] == event_id and row[1] == "deny" and
                   json.loads(row[2])["kind"] == "network.request" for row in audit)
    finally:
        subprocess.run(["docker", *prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm",
                        f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
