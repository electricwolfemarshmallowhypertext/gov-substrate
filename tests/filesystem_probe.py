"""Deterministic file attacker executed in the workspace-less agent container."""

import json
import os
import sys
import time
from pathlib import Path

from network_probe import request


TOKEN = os.environ["RESEARCH_AGENT_TOKEN"]


def proposal(session, kind, path, content=None):
    action = {"kind": kind, "path": path}
    if content is not None:
        action["content"] = content
    return request("POST", "/proposals", TOKEN, {"action": action}, session)


def isolated():
    if Path("/workspace").exists() or Path("/data").exists() or Path("/var/run/docker.sock").exists():
        return False
    try:
        Path("/ipc/hidden-file").write_text("bypass", encoding="utf-8")
        Path("/ipc/hidden-file").unlink()
        return False
    except OSError:
        return True


def main():
    phase = sys.argv[1]
    assert isolated(), "agent has a direct workspace or alternate storage path"
    if phase == "corruption":
        status, result = proposal(os.environ["OLD_SESSION_TOKEN"], "filesystem.read", "draft.txt")
        assert status == 200 and result["reason"] == "state_integrity", (status, result)
        health_status, health = request("GET", "/health", TOKEN)
        assert health_status == 200 and health["legibility"] == 0.0
        print(json.dumps({"phase": phase, "direct_blocked": True, "event_id": result["event_id"]}))
        return

    for _ in range(60):
        try:
            status, created = request("POST", "/sessions", TOKEN)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise AssertionError("substrate socket unavailable")
    if phase == "changed_registry_restart":
        assert status == 503, (status, created)
        print(json.dumps({"phase": phase, "direct_blocked": True, "registry_failed_closed": True}))
        return
    assert status == 200 and created["decision"] == "allow", (status, created)
    session = created["session_token"]

    if phase == "first":
        status, read = proposal(session, "filesystem.read", "permitted.txt")
        assert status == 200 and read["outcome"] == "succeeded" and read["content"] == "permitted seed\n", read
        status, traversal = proposal(session, "filesystem.read", "../outside.txt")
        assert status == 200 and traversal["reason"] == "invalid_path", traversal
        status, absolute = proposal(session, "filesystem.read", "/etc/passwd")
        assert status == 200 and absolute["reason"] == "invalid_path", absolute
        status, write = proposal(session, "filesystem.write", "draft.txt", "admitted content\n")
        assert status == 200 and write["outcome"] == "succeeded", write
        status, protected = proposal(session, "filesystem.write", "protected.txt", "overwrite")
        assert status == 200 and protected["reason"] == "protected_path", protected
        status, symlink = proposal(session, "filesystem.read", "escape/passwd")
        assert status == 200 and symlink["reason"] == "path_escape", symlink
        Path("/tmp/session_marker").write_text("ephemeral", encoding="utf-8")
        print(json.dumps({"phase": phase, "direct_blocked": True,
                          "read_event": read["event_id"], "read_outcome": read["outcome_event_id"],
                          "write_event": write["event_id"], "write_outcome": write["outcome_event_id"],
                          "protected_event": protected["event_id"], "session_token": session}))
        return

    if phase == "yaml_changed":
        assert not Path("/tmp/session_marker").exists(), "prior agent scratch persisted"
        status, protected = proposal(session, "filesystem.write", "protected.txt", "overwrite")
        assert status == 200 and protected["reason"] == "protected_path", protected
        status, stale = proposal(os.environ["OLD_SESSION_TOKEN"], "filesystem.write", "stale.txt", "bypass")
        assert status == 200 and stale["reason"] == "invalid_session", stale
        print(json.dumps({"phase": phase, "direct_blocked": True,
                          "protected_event": protected["event_id"], "session_token": session}))
        return
    raise AssertionError(f"unknown phase: {phase}")


if __name__ == "__main__":
    main()
