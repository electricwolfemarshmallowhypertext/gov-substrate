"""Deterministic one-shot generator; its stdin is the entire context."""

import base64
import hashlib
import json
import os
import socket
import sys


def main():
    if os.path.exists("/ipc/substrate.sock") or os.path.exists("/workspace"):
        raise RuntimeError("generation worker has a governed mount")
    if any(any(word in name.upper() for word in ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))
           for name in os.environ):
        raise RuntimeError("generation worker has a credential variable")
    try:
        socket.create_connection(("198.51.100.1", 80), timeout=0.2)
    except OSError:
        pass
    else:
        raise RuntimeError("generation worker has an outbound route")

    request = json.load(sys.stdin)
    if type(request) is not dict or set(request) != {"inputs"} or not request["inputs"]:
        raise ValueError("worker accepts only governed inputs")
    parts = []
    for source in request["inputs"]:
        if type(source) is not dict or set(source) != {"media_type", "content_base64"}:
            raise ValueError("worker input contains unmediated context")
        payload = base64.b64decode(source["content_base64"], validate=True)
        if source["media_type"] == "text/plain":
            parts.append(payload.decode("utf-8"))
        elif source["media_type"] == "image/png":
            parts.append("image/png:" + hashlib.sha256(payload).hexdigest()[:12])
        else:
            raise ValueError("unsupported worker input")
    sys.stdout.write(json.dumps({"text": " | ".join(parts)}))


if __name__ == "__main__":
    main()
