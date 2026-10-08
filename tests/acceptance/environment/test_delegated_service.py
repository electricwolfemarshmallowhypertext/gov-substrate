"""A registered relay cannot proxy to a target outside the actor's grant."""

import json
import subprocess
import time
import uuid

from tests.acceptance.conftest import ROOT, docker_command, docker_environment


COMPOSE = (ROOT / "deploy/compose/compose.network.yaml", ROOT / "deploy/compose/compose.evaluation.yaml")
REGISTRY = ROOT / "tests" / "fixtures" / "hardened_containment_registry.yaml"


def test_reachable_relay_cannot_proxy_for_agent(tmp_path, acceptance_enabled):
    registry = tmp_path / "registry.yaml"
    registry.write_bytes(REGISTRY.read_bytes())
    project = "govrelayenv" + uuid.uuid4().hex[:10]
    env = docker_environment()
    env.update(LAB_REGISTRY_PATH=str(registry), LAB_IMAGE_TAG=project)
    prefix = ["compose", "-p", project,
              *(part for compose in COMPOSE for part in ("-f", str(compose)))]

    def compose(*args, timeout=240):
        return docker_command(*prefix, *args, env=env, timeout=timeout)

    try:
        compose("build", "substrate", timeout=1200)
        compose("up", "-d", "fixture", "thirdparty", "relay", "substrate")
        for _ in range(40):
            control = subprocess.run(
                ["docker", *prefix, "exec", "-T", "substrate", "python", "-c",
                 "import urllib.request; assert b'THIRD_PARTY_SENTINEL' in "
                 "urllib.request.urlopen('http://relay:8001/proxy?target=thirdparty', "
                 "timeout=3).read()"],
                cwd=ROOT, env=env, capture_output=True, timeout=10)
            if control.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("substrate could not reach the working relay proxy")

        permitted = json.loads(compose(
            "run", "--rm", "-T", "--no-deps",
            "-e", "TOOL_URL=http://fixture:8000/",
            "agent", "python", "/app/network_probe.py", "tool"
        ).strip().splitlines()[-1])
        assert permitted["proposal"]["decision"] == "allow"
        assert permitted["proposal"]["outcome"] == "succeeded"
        assert permitted["proposal"]["response"]["status"] == 200
        print(json.dumps({"attempt": "granted_substrate_socket_and_terminal_service",
                          "allowed": True, "result": "Unix socket request; HTTP 200 via fixture"}))

        output = compose("run", "--rm", "-T", "--no-deps",
                         "-e", "TOOL_URL=http://relay:8001/proxy?target=thirdparty",
                         "agent", "python", "/app/network_probe.py", "tool")
        result = json.loads(output.strip().splitlines()[-1])
        assert result["direct_blocked"] is True
        assert result["proposal"]["decision"] == "deny"
        assert result["proposal"]["reason"] == "delegated_service_unmediated"
        event_id = result["proposal"]["event_id"]
        audit = json.loads(compose(
            "exec", "-T", "substrate", "python", "-c",
            "import json,sqlite3; d=sqlite3.connect('/data/substrate.db'); "
            "print(json.dumps(d.execute('SELECT id,decision,action FROM events ORDER BY id').fetchall()))"
        ).strip())
        assert any(row[0] == event_id and row[1] == "deny" and
                   json.loads(row[2])["kind"] == "network.request" for row in audit)
        assert not any(json.loads(row[2]).get("request_event_id") == event_id
                       for row in audit)
        print(json.dumps({"attempt": "registered_relay_proxy", "allowed": False,
                          "result": "substrate HTTP 200 with third-party sentinel; "
                          "agent denied delegated_service_unmediated; "
                          f"audit_event={event_id}"}))
    finally:
        subprocess.run(["docker", *prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm",
                        f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
