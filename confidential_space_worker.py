"""One measured Confidential Space workload for either pinned local GGUF model."""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from confidential_space_protocol import (associated_data, decode, encode,
                                         session_key)
from google_attestation import key_binding
from provider_gateway import canonical, request_identity


MAX_BODY = 65_536
MODEL_HASHES = {
    "Qwen3-0.6B-Q8_0.gguf": "12fae8b8f78f0360b498d04c8db7d33aff29ab7d8080231f93a17c18119e6735",
    "Phi-4-mini-instruct-Q8_0.gguf": "3e81a3ad900b6d67df011d42ef14bad63354a3516fbd229b9bf29755363b25ee",
}


class _LauncherConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect("/run/container_launcher/teeserver.sock")


def google_token(audience: str, nonces: list[str]) -> str:
    connection = _LauncherConnection("localhost", timeout=5)
    try:
        connection.request("POST", "/v1/token", json.dumps({
            "audience": audience, "token_type": "OIDC", "nonces": nonces}),
            {"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(128_001)
        if response.status != 200 or len(raw) > 128_000:
            raise RuntimeError("Confidential Space attestation unavailable")
        token = raw.decode().strip()
        if token.count(".") != 2:
            raise RuntimeError("Confidential Space attestation malformed")
        return token
    finally:
        connection.close()


def infer(model_path: Path, inputs: list[bytes]) -> str:
    from llama_cpp import Llama

    prompt = "\n\n".join(item.decode("utf-8") for item in inputs)
    if not prompt.strip():
        raise ValueError("empty governed context")
    model = Llama(model_path=str(model_path), n_ctx=512, n_threads=2,
                  n_threads_batch=2, n_gpu_layers=0, verbose=False)
    if len(model.tokenize(prompt.encode(), add_bos=True)) > 480:
        raise ValueError("governed context exceeds model window")
    result = model(prompt, max_tokens=32, temperature=0, echo=False)
    text = result["choices"][0]["text"].strip()
    if not text:
        raise RuntimeError("model returned empty text")
    return text


class ConfidentialSpaceWorker:
    def __init__(self, model_path: Path,
                 token_issuer=google_token, inference=infer):
        if model_path.name not in MODEL_HASHES or not model_path.is_file():
            raise ValueError("only the pinned Qwen and Phi artifacts are supported")
        self.model_path = model_path
        self.token_issuer = token_issuer
        self.inference = inference
        digest = hashlib.sha256()
        with model_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        self.model_sha256 = digest.hexdigest()
        if self.model_sha256 != MODEL_HASHES[model_path.name]:
            raise ValueError("model artifact hash mismatch")
        self.pending = {}

    def attest(self, body: dict) -> dict:
        fields = {"generation_id", "request_hash", "model_sha256", "nonce",
                  "audience", "model_id"}
        if (type(body) is not dict or set(body) != fields or
                any(type(body[key]) is not str or not body[key] for key in fields) or
                body["model_sha256"] != self.model_sha256 or
                len(body["nonce"]) != 64):
            raise ValueError("invalid attestation request or model hash")
        if body["generation_id"] in self.pending:
            raise ValueError("generation already attested")
        exchange = x25519.X25519PrivateKey.generate()
        result_key = ed25519.Ed25519PrivateKey.generate()
        exchange_public = encode(exchange.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        result_public = encode(result_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        binding = key_binding(body["request_hash"], self.model_sha256,
                              body["nonce"], exchange_public, result_public)
        token = self.token_issuer(body["audience"], [body["nonce"], binding])
        token_claims = json.loads(decode(token.split(".")[1]))
        image_digest = token_claims["submods"]["container"]["image_digest"]
        self.pending[body["generation_id"]] = {
            "request_hash": body["request_hash"], "model_id": body["model_id"],
            "nonce": body["nonce"], "exchange": exchange,
            "result_key": result_key, "image_digest": image_digest,
            "expires": time.time() + 120,
        }
        return {"token": token, "nonce": body["nonce"],
                "exchange_public_key": exchange_public,
                "result_public_key": result_public,
                "model_sha256": self.model_sha256}

    def execute(self, body: dict) -> dict:
        if type(body) is not dict or set(body) != {
                "generation_id", "client_public_key", "nonce", "ciphertext"}:
            raise ValueError("invalid encrypted generation request")
        session = self.pending.pop(body["generation_id"], None)
        if session is None or session["expires"] <= time.time():
            raise ValueError("attested generation unavailable")
        peer = x25519.X25519PublicKey.from_public_bytes(decode(body["client_public_key"]))
        key = session_key(session["exchange"].exchange(peer), session["request_hash"])
        aad = associated_data(body["generation_id"], session["request_hash"],
                              self.model_sha256)
        plaintext = AESGCM(key).decrypt(decode(body["nonce"]),
                                         decode(body["ciphertext"]), aad)
        request = json.loads(plaintext)
        fields = {"provider", "provider_request", "input_ids", "input_hashes", "inputs"}
        if type(request) is not dict or set(request) != fields:
            raise ValueError("unsealed generation context")
        inputs = [base64.b64decode(item, validate=True) for item in request["inputs"]]
        if (len(inputs) != len(request["input_ids"]) or
                len(inputs) != len(request["input_hashes"]) or
                any(hashlib.sha256(item).hexdigest() != expected
                    for item, expected in zip(inputs, request["input_hashes"])) or
                request["provider_request"].get("model") != session["model_id"] or
                request_identity(body["generation_id"], request["provider"],
                                 request["provider_request"], request["input_ids"],
                                 request["input_hashes"]) != session["request_hash"]):
            raise ValueError("generation manifest mismatch")
        text = self.inference(self.model_path, inputs)
        payload = {"generation_id": body["generation_id"],
                   "request_hash": session["request_hash"],
                   "model_sha256": self.model_sha256,
                   "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
                   "image_digest": session["image_digest"],
                   "nonce": session["nonce"]}
        payload["signature"] = encode(session["result_key"].sign(canonical(payload).encode()))
        response_nonce = secrets.token_bytes(12)
        return {"result": payload, "nonce": encode(response_nonce),
                "ciphertext": encode(AESGCM(key).encrypt(response_nonce, text.encode(), aad))}


def serve() -> None:
    model_path = Path(os.environ["CONFIDENTIAL_MODEL_PATH"])
    worker = ConfidentialSpaceWorker(model_path)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_error(413)
                return
            try:
                body = json.loads(self.rfile.read(length))
                if self.path == "/attest":
                    result = worker.attest(body)
                elif self.path == "/infer":
                    result = worker.execute(body)
                else:
                    self.send_error(404)
                    return
            except (ValueError, TypeError, KeyError, IndexError, AttributeError,
                    OSError, binascii.Error, InvalidTag):
                self.send_error(400)
                return
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(("0.0.0.0", 8080), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(os.environ["CONFIDENTIAL_TLS_CERT"],
                        os.environ["CONFIDENTIAL_TLS_KEY"])
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
