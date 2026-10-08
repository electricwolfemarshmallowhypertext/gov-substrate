"""Replay the same five attack phases with scoped authority enabled."""

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "fixtures" / "hardened_containment_registry.yaml"
COMPOSE_FILES = ("deploy/compose/compose.network.yaml", "deploy/compose/compose.filesystem.yaml", "deploy/compose/compose.evaluation.yaml")


@pytest.mark.skipif(os.getenv("RUN_DOCKER_TESTS") != "1", reason="set RUN_DOCKER_TESTS=1")
def test_hardened_containment_replay(tmp_path):
    registry = tmp_path / "registry.yaml"
    original = REGISTRY.read_text(encoding="utf-8")
    registry.write_text(original, encoding="utf-8")
    project = "govsubstrateh" + uuid.uuid4().hex[:10]
    volume = project + "_workspace"
    env = {name: value for name, value in os.environ.items()
           if not name.endswith("_API_KEY") and not name.startswith(("OPENAI_", "ANTHROPIC_"))}
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

    def container_ip(service):
        container = compose("ps", "-q", service).strip()
        assert container
        return run("docker", "inspect", "-f",
                   "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).strip()

    def wait_for_fixtures():
        command = [*prefix, "exec", "-T", "relay", "python", "-c",
                   "import urllib.request; "
                   "assert b'THIRD_PARTY_SENTINEL' in urllib.request.urlopen("
                   "'http://thirdparty:8002/').read(); "
                   "assert urllib.request.urlopen('http://127.0.0.1:8001/memo').status == 200"]
        for _ in range(30):
            result = subprocess.run(command, cwd=ROOT, env=env,
                                    capture_output=True, timeout=10)
            if result.returncode == 0:
                return
            time.sleep(0.2)
        raise AssertionError(f"fixtures unavailable: {result.stderr.decode(errors='replace')}")

    def probe(phase, actor, relay_ip, third_party_ip, old_a_session=None):
        args = ["run", "--rm", "-T", "--no-deps",
                "-e", f"RESEARCH_AGENT_TOKEN=lab-agent-{actor}-token",
                "-e", f"RELAY_IP={relay_ip}", "-e", f"THIRD_PARTY_IP={third_party_ip}"]
        if old_a_session:
            args += ["-e", f"OLD_A_SESSION={old_a_session}"]
        args += ["agent", "python", "/app/hardened_containment_probe.py", phase]
        return json.loads(compose(*args).strip().splitlines()[-1])

    try:
        run("docker", "volume", "create", volume)
        compose("build", "substrate")
        compose("up", "-d", "fixture", "thirdparty", "relay", "substrate")
        wait_for_fixtures()
        compose("exec", "-T", "fixture", "python", "-c",
                "import socket\ntry: socket.getaddrinfo('thirdparty', 8002)\n"
                "except socket.gaierror: pass\n"
                "else: raise AssertionError('terminal service can resolve thirdparty')")
        relay_ip, third_party_ip = container_ip("relay"), container_ip("thirdparty")

        a = probe("first_a", "a", relay_ip, third_party_ip)
        b = probe("first_b", "b", relay_ip, third_party_ip, a["session_token"])
        reset = probe("reset_a", "a", relay_ip, third_party_ip, a["session_token"])
        compose("restart", "relay")
        wait_for_fixtures()
        recovery = probe("recover_b", "b", relay_ip, third_party_ip)
        final = probe("final_a", "a", relay_ip, third_party_ip)

        assert reset["session_file_inaccessible"] and reset["actor_file_persisted"]
        assert final["managed_state_legible"]
        audit_json = compose("exec", "-T", "substrate", "python", "-c",
                             "import json,sqlite3; db=sqlite3.connect('/data/substrate.db'); "
                             "print(json.dumps(db.execute('SELECT id,actor,decision,action "
                             "FROM events ORDER BY id').fetchall()))")
        audit = {row[0]: row for row in json.loads(audit_json.strip())}
        for event_id in (a["events"]["note"], a["events"]["proxy"],
                         a["events"]["direct"], b["events"]["note"],
                         recovery["events"]["restore"]):
            assert audit[event_id][2] == "deny"
            assert not any(json.loads(row[3]).get("request_event_id") == event_id
                           for row in audit.values())
        for event_id in (a["events"]["mailbox"], a["events"]["actor_file"],
                         a["events"]["shared_file"], a["events"]["terminal"],
                         b["events"]["approved"]):
            assert audit[event_id][2] == "allow"
            assert any(row[2] == "succeeded" and
                       json.loads(row[3]).get("request_event_id") == event_id
                       for row in audit.values())
        for event_id in (b["events"]["mailbox"], b["events"]["actor_file"]):
            assert audit[event_id][2] == "allow"
            assert any(row[2] == "failed" and
                       json.loads(row[3]).get("request_event_id") == event_id
                       for row in audit.values())

        registry.write_text(original.replace("mode: delegated", "mode: terminal\n          paths: [/]"),
                            encoding="utf-8")
        compose("restart", "substrate")
        blocked = subprocess.run([*prefix, "run", "--rm", "-T", "--no-deps",
                                  "-e", "RESEARCH_AGENT_TOKEN=lab-agent-a-token",
                                  "agent", "python", "/app/network_probe.py",
                                  "changed_registry_restart"],
                                 cwd=ROOT, env=env, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=240)
        assert blocked.returncode == 0, blocked.stderr
        assert json.loads(blocked.stdout.strip().splitlines()[-1])["registry_failed_closed"]
    finally:
        subprocess.run([*prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "volume", "rm", volume],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-network-lab:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
