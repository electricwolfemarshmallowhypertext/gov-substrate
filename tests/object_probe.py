"""One isolated actor exercises classified reads, transforms, and publication."""

import base64
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib.parse import quote

from network_probe import request


TOKEN = os.environ["RESEARCH_AGENT_TOKEN"]
DESTINATION = "http://publisher:8003"


def propose(session, action):
    status, result = request("POST", "/proposals", TOKEN, {"action": action}, session)
    assert status == 200, (status, result)
    return result


def main():
    assert os.geteuid() != 0
    assert not any(name.endswith("_API_KEY") for name in os.environ)
    assert not any(Path(path).exists() for path in
                   ("/workspace", "/data", "/var/run/docker.sock"))
    try:
        with socket.create_connection((os.environ["PUBLISHER_IP"], 8003), timeout=1):
            raise AssertionError("direct publisher route exists")
    except OSError:
        pass
    for _ in range(60):
        try:
            status, created = request("POST", "/sessions", TOKEN)
            break
        except OSError:
            time.sleep(0.25)
    else:
        raise AssertionError("substrate socket unavailable")
    assert status == 200 and created["decision"] == "allow"
    session = created["session_token"]
    image_id = os.environ["PRIVATE_IMAGE_ID"]
    public_id = os.environ["PUBLIC_SOURCE_ID"]

    image = propose(session, {"kind": "object.read", "object_id": image_id})
    assert image["classification"] == "private"
    assert base64.b64decode(image["content_base64"]).startswith(b"\x89PNG")
    private_publish = propose(session, {"kind": "object.publish", "object_id": image_id,
                                        "destination": DESTINATION})
    encoded = propose(session, {"kind": "object.transform", "object_id": image_id,
                                "operation": "base64"})
    encoded_publish = propose(session, {"kind": "object.publish",
                                        "object_id": encoded["object_id"],
                                        "destination": DESTINATION})
    assert encoded["classification"] == "private"
    assert private_publish["reason"] == encoded_publish["reason"] == "object_classification_blocks_egress"

    summary = propose(session, {"kind": "object.transform", "object_id": public_id,
                                "operation": "summary"})
    summary_read = propose(session, {"kind": "object.read", "object_id": summary["object_id"]})
    summary_text = base64.b64decode(summary_read["content_base64"]).decode()
    assert summary["classification"] == "public" and summary_text == "The sky is blue."
    published = propose(session, {"kind": "object.publish", "object_id": summary["object_id"],
                                  "destination": DESTINATION})
    assert published["decision"] == "allow" and published["outcome"] == "succeeded"

    raw = propose(session, {"kind": "network.request", "url":
                            f"{DESTINATION}/publish?data={quote(image['content_base64'])}"})
    assert raw["reason"] == "sensitive_external_egress_disabled"
    operator_status, _ = request("POST", "/objects/declassify", TOKEN,
                                 {"object_id": image_id, "classification": "public",
                                  "reason": "agent override"})
    assert operator_status == 401
    print(json.dumps({"private_event": private_publish["event_id"],
                      "encoded_event": encoded_publish["event_id"],
                      "public_event": published["event_id"],
                      "raw_event": raw["event_id"],
                      "summary_id": summary["object_id"]}))


if __name__ == "__main__":
    main()
