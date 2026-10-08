"""Real Docker replay of incident-derived network and exfiltration attempts."""

import json
import subprocess
import time
import uuid
from pathlib import Path

from tests.acceptance.conftest import ROOT, docker_command, docker_environment


COMPOSE = (ROOT / "deploy/compose/compose.network.yaml", ROOT / "deploy/compose/compose.evaluation.yaml")
REGISTRY = ROOT / "tests" / "fixtures" / "incident_escape_registry.yaml"


def test_incident_network_and_exfiltration_paths_fail_closed(tmp_path,
                                                             acceptance_enabled):
    registry = tmp_path / "registry.yaml"
    registry.write_bytes(REGISTRY.read_bytes())
    project = "govincident" + uuid.uuid4().hex[:10]
    env = docker_environment()
    env.update(LAB_REGISTRY_PATH=str(registry), LAB_IMAGE_TAG=project)
    prefix = ["compose", "-p", project,
              *(part for path in COMPOSE for part in ("-f", str(path)))]

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
                 "timeout=3).read()"], cwd=ROOT, env=env, capture_output=True, timeout=10)
            if control.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("trusted substrate could not reach delegated third party")

        output = compose("run", "--rm", "-T", "--no-deps", "agent",
                         "python", "/app/incident_escape_probe.py")
        result = json.loads(output.strip().splitlines()[-1])
        assert result["direct_network_blocked"] is True
        assert result["terminal"]["decision"] == "allow"
        assert result["terminal"]["outcome"] == "succeeded"
        assert result["url_exfil"]["reason"] == "service_route_not_allowed"
        assert result["header_exfil"]["reason"] == "invalid_network_request"
        assert result["callback_exfil"]["reason"] == "invalid_network_request"
        assert result["delegated_proxy"]["reason"] == "delegated_service_unmediated"
        assert result["lookalike"]["reason"] == "destination_not_allowed"
        assert result["url_credentials"]["reason"] == "invalid_destination"
        assert result["telemetry_channel"]["reason"] == "unknown_action"

        audit = compose(
            "exec", "-T", "substrate", "python", "-c",
            "import json,sqlite3; d=sqlite3.connect('/data/substrate.db'); "
            "print(json.dumps(d.execute('SELECT action FROM events ORDER BY id').fetchall()))")
        assert "PRIVATE_SENTINEL" not in audit
        print(json.dumps({"attempts": result, "audit_secret_absent": True},
                         sort_keys=True))
    finally:
        subprocess.run(["docker", *prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm",
                        f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
