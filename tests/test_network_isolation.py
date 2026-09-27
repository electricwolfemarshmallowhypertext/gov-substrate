"""Opt-in Docker test: an agent with no network reaches only the audited UDS adapter."""

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.network.yaml"
FIXTURE_REGISTRY = ROOT / "tests" / "fixtures" / "network_registry.yaml"


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_agent_network_isolation_and_registry_restart(tmp_path):
    registry = tmp_path / "network_registry.yaml"
    registry.write_text(FIXTURE_REGISTRY.read_text(encoding="utf-8"), encoding="utf-8")
    project = "govsubstratem2" + uuid.uuid4().hex[:10]
    env = {**os.environ, "LAB_REGISTRY_PATH": str(registry), "LAB_IMAGE_TAG": project}
    prefix = ["docker", "compose", "-p", project, "-f", str(COMPOSE)]

    def compose(*args):
        result = subprocess.run([*prefix, *args], cwd=ROOT, env=env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)
        assert result.returncode == 0, f"{' '.join(args)}\n{result.stdout}\n{result.stderr}"
        return result.stdout

    def probe(phase, fixture_ip, old_token=None, url=None):
        args = ["run", "--rm", "--no-deps"]
        args.extend(["-e", f"FIXTURE_IP={fixture_ip}"])
        if old_token:
            args.extend(["-e", f"OLD_SESSION_TOKEN={old_token}"])
        if url:
            args.extend(["-e", f"TOOL_URL={url}"])
        args.extend(["agent", "python", "/app/network_probe.py", phase])
        output = compose(*args)
        return json.loads(output.strip().splitlines()[-1])

    try:
        compose("build", "substrate")
        compose("up", "-d", "fixture", "substrate")
        fixture_id = compose("ps", "-q", "fixture").strip()
        inspected = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", fixture_id],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20, check=True)
        fixture_ip = inspected.stdout.strip()
        assert fixture_ip
        first = probe("first", fixture_ip)
        assert first["direct_blocked"] is True
        assert first["alternate_storage_blocked"] is True

        audit_json = compose("exec", "-T", "substrate", "python", "-c",
                             "import json,sqlite3; db=sqlite3.connect('/data/substrate.db'); "
                             "print(json.dumps(db.execute('SELECT id,decision,action FROM events ORDER BY id').fetchall()))")
        audit = {row[0]: row for row in json.loads(audit_json.strip())}
        assert audit[first["allowed_event"]][1] == "allow"
        assert audit[first["outcome_event"]][1] == "succeeded"
        assert json.loads(audit[first["outcome_event"]][2])["resolved_ip"] == fixture_ip
        assert audit[first["denied_event"]][1] == "deny"
        assert not any(json.loads(row[2]).get("request_event_id") == first["denied_event"]
                       for row in audit.values())

        if os.getenv("RUN_LIVE_NETWORK_TESTS") == "1":
            live = probe("tool", fixture_ip, url="https://example.com/")
            assert live["direct_blocked"] is True
            assert live["proposal"]["decision"] == "allow"
            assert live["proposal"]["outcome"] == "succeeded", live
            assert live["proposal"]["response"]["status"] == 200

        text = registry.read_text(encoding="utf-8")
        registry.write_text(text.replace("        - http://fixture:8000",
                                         "        - http://fixture:8000\n        - http://fixture:8001"),
                            encoding="utf-8")
        second = probe("yaml_changed", fixture_ip, first["session_token"])
        assert second["direct_blocked"] is True
        assert second["alternate_storage_blocked"] is True
        assert second["denied_event"] > first["denied_event"]

        compose("restart", "substrate")
        third = probe("changed_registry_restart", fixture_ip)
        assert third["registry_failed_closed"] is True
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       capture_output=True, text=True, timeout=60)
