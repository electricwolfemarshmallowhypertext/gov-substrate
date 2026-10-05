"""Real networkless worker probe for the Phase 9 gateway boundary."""

import json
import os
import socket


def blocked(host, port):
    try:
        socket.create_connection((host, port), timeout=1).close()
        return False
    except OSError:
        return True


result = {
    "gateway_blocked": blocked(os.environ["GATEWAY_IP"], 8443),
    "provider_blocked": blocked(os.environ["PROVIDER_IP"], 8080),
    "provider_credential_absent": "PROVIDER_CREDENTIAL" not in os.environ,
    "gateway_secret_absent": "GATEWAY_SIGNING_SECRET" not in os.environ,
}
print(json.dumps(result, sort_keys=True))
if not all(result.values()):
    raise SystemExit(1)
