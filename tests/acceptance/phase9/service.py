"""Local Phase 9 provider gateway, provider fixture, and audit witness."""

import base64
import hashlib
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from provider_gateway import create_receipt, request_identity, verify_gateway_credential


def response(handler, status, body):
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class Handler(BaseHTTPRequestHandler):
    server_version = "phase9-fixture"

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/health":
            response(self, 200, {"status": "ok"})
        elif self.path == "/count" and getattr(self.server, "mode", None) == "provider":
            response(self, 200, {"calls": PROVIDER_CALLS})
        else:
            response(self, 404, {"error": "unknown_route"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            response(self, 400, {"error": "invalid_json"})
            return
        getattr(self.server, "handle")(self, self.path, body)


PROVIDER_CALLS = 0


def provider(handler, path, body):
    global PROVIDER_CALLS
    if (path != "/generate" or
            handler.headers.get("Authorization") !=
            "Bearer " + os.environ["PROVIDER_CREDENTIAL"]):
        response(handler, 403, {"error": "provider_denied"})
        return
    profile = body.get("profile")
    if type(profile) is not dict or body.get("inputs") is None:
        response(handler, 400, {"error": "malformed_request"})
        return
    PROVIDER_CALLS += 1
    response(handler, 200, {
        "text": "provider response from sealed context",
        "model": profile.get("model"),
        "upstream": profile.get("upstream"),
        "allow_fallbacks": profile.get("allow_fallbacks"),
        "data_collection": profile.get("data_collection"),
        "zdr": profile.get("zdr"),
        "retention": profile.get("retention"),
    })


USED_CREDENTIALS = set()


def gateway(handler, path, body):
    if path != "/generate":
        response(handler, 404, {"error": "unknown_route"})
        return
    required = {"generation_id", "provider", "request_hash", "provider_request",
                "input_ids", "input_hashes", "inputs", "gateway_credential"}
    if type(body) is not dict or set(body) != required:
        response(handler, 400, {"error": "gateway_fields_invalid"})
        return
    credential_hash = hashlib.sha256(body["gateway_credential"].encode()).hexdigest()
    if credential_hash in USED_CREDENTIALS:
        response(handler, 409, {"error": "gateway_credential_reused"})
        return
    expected = request_identity(body["generation_id"], body["provider"],
                                body["provider_request"], body["input_ids"],
                                body["input_hashes"])
    credential = verify_gateway_credential(
        os.environ["GATEWAY_SIGNING_SECRET"].encode(), body["gateway_credential"])
    if (credential is None or credential["generation_id"] != body["generation_id"] or
            credential["provider"] != body["provider"] or
            credential["request_hash"] != body["request_hash"]):
        response(handler, 403, {"error": "gateway_credential_invalid"})
        return
    decoded = []
    try:
        for encoded, expected_hash in zip(body["inputs"], body["input_hashes"], strict=True):
            content = base64.b64decode(encoded, validate=True)
            if hashlib.sha256(content).hexdigest() != expected_hash:
                raise ValueError
            decoded.append(content.decode("utf-8"))
    except (ValueError, UnicodeError):
        response(handler, 400, {"error": "gateway_manifest_invalid"})
        return
    if expected != body["request_hash"] or len(decoded) != len(body["input_ids"]):
        response(handler, 400, {"error": "gateway_request_identity_mismatch"})
        return
    authorization = Request(
        os.environ["SUBSTRATE_URL"].rstrip("/") + "/generations/provider-call",
        data=json.dumps({"generation_id": body["generation_id"],
                         "provider": body["provider"],
                         "gateway_credential": body["gateway_credential"]}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(authorization, timeout=5) as authorized:
            authorization_result = json.load(authorized)
    except (OSError, ValueError):
        response(handler, 503, {"error": "substrate_authorization_unavailable"})
        return
    if authorization_result.get("decision") != "allow":
        response(handler, 403, {"error": "provider_call_revoked"})
        return
    USED_CREDENTIALS.add(credential_hash)
    outbound = json.dumps({"profile": body["provider_request"], "inputs": decoded},
                          sort_keys=True, separators=(",", ":")).encode()
    request = Request(os.environ["PROVIDER_URL"], data=outbound,
                      headers={"Content-Type": "application/json",
                               "Authorization": "Bearer " +
                               os.environ["PROVIDER_CREDENTIAL"]}, method="POST")
    with urlopen(request, timeout=5) as upstream:
        provider_result = json.load(upstream)
    for field in ("model", "upstream", "allow_fallbacks", "data_collection",
                  "zdr", "retention"):
        if provider_result.get(field) != body["provider_request"].get(field):
            response(handler, 502, {"error": "provider_metadata_mismatch"})
            return
    text = provider_result.get("text")
    if type(text) is not str or not text:
        response(handler, 502, {"error": "provider_response_invalid"})
        return
    receipt = create_receipt(
        os.environ["GATEWAY_SIGNING_SECRET"].encode(), body["generation_id"],
        body["provider"], body["request_hash"], text.encode(),
        body["gateway_credential"]).as_dict()
    response(handler, 200, {"text": text, "receipt": receipt})


def mirror(handler, path, body):
    if path == "/proxy":
        with urlopen(os.environ["TARGET_URL"], timeout=5) as target:
            payload = target.read().decode("utf-8")
        response(handler, 200, {"proxied": payload})
    elif path == "/credentials":
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        response(handler, 200, {"service_account_token_present": token.exists()})
    else:
        response(handler, 404, {"error": "unknown_route"})


class Witness:
    def __init__(self, path):
        self.path = Path(path)
        self.entries = []
        if self.path.exists():
            self.entries = json.loads(self.path.read_text())

    def __call__(self, handler, path, body):
        if path == "/append":
            expected_id = len(self.entries) + 1
            previous = self.entries[-1]["event_hash"] if self.entries else "0" * 64
            if body.get("event_id") != expected_id or body.get("previous_hash") != previous:
                response(handler, 409, {"accepted": False})
                return
            self.entries.append(body)
            self.path.write_text(json.dumps(self.entries, sort_keys=True))
            response(handler, 200, {"accepted": True, "event_id": body["event_id"],
                                    "event_hash": body["event_hash"]})
        elif path == "/verify":
            verified = bool(self.entries and
                            self.entries[-1]["event_id"] == body.get("event_id") and
                            self.entries[-1]["event_hash"] == body.get("event_hash"))
            response(handler, 200, {"verified": verified,
                                    "event_id": body.get("event_id"),
                                    "event_hash": body.get("event_hash")})
        else:
            response(handler, 404, {"error": "unknown_route"})


def serve(mode):
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ["PORT"])), Handler)
    server.mode = mode
    if mode == "provider":
        server.handle = provider
    elif mode == "gateway":
        server.handle = gateway
    elif mode == "witness":
        server.handle = Witness(os.environ["WITNESS_PATH"])
    elif mode == "mirror":
        server.handle = mirror
    else:
        raise ValueError("unknown service mode")
    if mode in ("gateway", "witness"):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain("/certs/server.crt", "/certs/server.key")
        context.load_verify_locations("/certs/ca.crt")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    serve(sys.argv[1])
