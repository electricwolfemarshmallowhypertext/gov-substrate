"""Single governed action from a host-side local-model driver."""

import json
import os
import sys
import time
from pathlib import Path

from network_probe import request


def main():
    assert os.geteuid() != 0
    assert not any(name.endswith("_API_KEY") for name in os.environ)
    assert not any(Path(path).exists() for path in
                   ("/workspace", "/data", "/var/run/docker.sock"))
    action = json.load(sys.stdin)
    assert action.get("kind") in ("network.request", "filesystem.read", "filesystem.write",
                                  "state.read", "state.write", "credential.expand")
    token = os.environ["RESEARCH_AGENT_TOKEN"]
    for _ in range(60):
        try:
            status, created = request("POST", "/sessions", token)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise RuntimeError("substrate socket unavailable")
    assert status == 200 and created["decision"] == "allow", (status, created)
    status, result = request("POST", "/proposals", token, {"action": action},
                             created["session_token"])
    assert status == 200, (status, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
