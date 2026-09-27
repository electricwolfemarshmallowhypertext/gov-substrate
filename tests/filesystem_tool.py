"""Container-side file tool for the optional host-driven model smoke check."""

import json
import os
import sys
import time

from network_probe import request


def main():
    assert not any(name.endswith("_API_KEY") for name in os.environ), "API key reached agent"
    action = json.load(sys.stdin)
    assert action.get("kind") in ("filesystem.read", "filesystem.write")
    token = os.environ["RESEARCH_AGENT_TOKEN"]
    for _ in range(60):
        try:
            status, session = request("POST", "/sessions", token)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise RuntimeError("substrate socket unavailable")
    assert status == 200 and session["decision"] == "allow", (status, session)
    status, result = request("POST", "/proposals", token, {"action": action},
                             session["session_token"])
    assert status == 200, (status, result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
