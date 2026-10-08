"""Trusted host bridge; no governed bytes leave before substrate attestation approval."""

from __future__ import annotations

import base64
import json
import secrets
import ssl
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.request import HTTPSHandler

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from confidential_space_protocol import associated_data, decode, encode, session_key
from generation_adapter import claim_generation_context, complete_generated_text
from provider_gateway import create_receipt


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class HTTPSAttestedTransport:
    def __init__(self, origin: str, ca_file: str | None = None):
        if not origin.startswith("https://") or origin.endswith("/"):
            raise ValueError("attested workload requires a fixed HTTPS origin")
        self.origin = origin
        self.opener = build_opener(_NoRedirect,
                                   HTTPSHandler(context=ssl.create_default_context(
                                       cafile=ca_file)))

    def _post(self, path: str, body: dict) -> dict:
        request = Request(self.origin + path, data=json.dumps(body).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        with self.opener.open(request, timeout=120) as response:
            raw = response.read(128_001)
        if len(raw) > 128_000:
            raise RuntimeError("attested workload response too large")
        result = json.loads(raw)
        if type(result) is not dict:
            raise RuntimeError("attested workload response malformed")
        return result

    def attest(self, body: dict) -> dict:
        return self._post("/attest", body)

    def execute(self, body: dict) -> dict:
        return self._post("/infer", body)


def run_attested_generation(client, generation_id: str, operator_token: str,
                            execution_token: str, provider: str, model_sha256: str,
                            audience: str, transport, gateway_secret: bytes) -> dict:
    claim = claim_generation_context(client, generation_id, operator_token,
                                     execution_token, provider)
    if not claim.gateway_credential or not claim.request_hash or not claim.provider_request:
        raise RuntimeError("attested generation lacks a sealed provider request")
    nonce = secrets.token_hex(32)
    preflight = transport.attest({
        "generation_id": generation_id, "request_hash": claim.request_hash,
        "model_sha256": model_sha256, "nonce": nonce,
        "audience": audience, "model_id": claim.provider_request["model"]})
    if type(preflight) is not dict:
        raise RuntimeError("attested workload preflight malformed")
    headers = {"Authorization": f"Bearer {operator_token}"}
    authorization = client.post("/generations/provider-call", headers=headers,
                                json={"generation_id": generation_id,
                                      "provider": provider,
                                      "gateway_credential": claim.gateway_credential,
                                      "attestation": preflight})
    if (authorization.status_code != 200 or
            authorization.json().get("decision") != "allow"):
        raise RuntimeError("attested provider transfer denied before input release")
    exchange = x25519.X25519PrivateKey.generate()
    peer = x25519.X25519PublicKey.from_public_bytes(
        decode(preflight["exchange_public_key"]))
    key = session_key(exchange.exchange(peer), claim.request_hash)
    aad = associated_data(generation_id, claim.request_hash, model_sha256)
    plaintext = json.dumps({
        "provider": provider, "provider_request": claim.provider_request,
        "input_ids": list(claim.input_ids), "input_hashes": list(claim.input_hashes),
        "inputs": [base64.b64encode(source.content).decode() for source in claim.inputs],
    }, sort_keys=True, separators=(",", ":")).encode()
    request_nonce = secrets.token_bytes(12)
    response = transport.execute({
        "generation_id": generation_id,
        "client_public_key": encode(exchange.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)),
        "nonce": encode(request_nonce),
        "ciphertext": encode(AESGCM(key).encrypt(request_nonce, plaintext, aad))})
    if type(response) is not dict or set(response) != {"result", "nonce", "ciphertext"}:
        raise RuntimeError("attested workload result malformed")
    text = AESGCM(key).decrypt(decode(response["nonce"]),
                               decode(response["ciphertext"]), aad).decode()
    evidence = {"preflight": preflight, "result": response["result"]}
    receipt = create_receipt(gateway_secret, generation_id, provider,
                             claim.request_hash, text.encode(),
                             claim.gateway_credential, evidence).as_dict()
    return complete_generated_text(client, generation_id, operator_token,
                                   text, receipt, evidence)
