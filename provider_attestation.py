"""Controlled attestation contract; HMAC signer is for experiments, not remote attestation."""

from __future__ import annotations

import hashlib
import hmac

from provider_gateway import canonical


FIELDS = {"generation_id", "request_hash", "model_id", "runtime_id",
          "measurement", "challenge", "response_hash"}


def create_attestation(secret: bytes, *, generation_id: str, request_hash: str,
                       model_id: str, runtime_id: str, measurement: str,
                       challenge: str, response: bytes) -> dict:
    evidence = {"generation_id": generation_id, "request_hash": request_hash,
                "model_id": model_id, "runtime_id": runtime_id,
                "measurement": measurement, "challenge": challenge,
                "response_hash": hashlib.sha256(response).hexdigest()}
    evidence["signature"] = hmac.new(secret, canonical(evidence).encode(),
                                      hashlib.sha256).hexdigest()
    return evidence


def verify_attestation(secret: bytes, evidence: dict, expected: dict) -> bool:
    if (type(evidence) is not dict or set(evidence) != FIELDS | {"signature"} or
            any(type(evidence[key]) is not str or not evidence[key] for key in evidence) or
            any(evidence[key] != value for key, value in expected.items())):
        return False
    payload = {key: evidence[key] for key in FIELDS}
    signature = hmac.new(secret, canonical(payload).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(evidence["signature"], signature)


class ControlledAttestor:
    """Instrumented test fixture; its observations are not a hosted-provider proof."""

    def __init__(self, secret: bytes, runtime_id: str, measurement: str):
        self._secret = secret
        self.runtime_id = runtime_id
        self.measurement = measurement

    def attest(self, *, generation_id: str, request_hash: str,
               expected_input_hashes: list[str], actual_inputs: list[bytes],
               expected_model: str, actual_model: str, challenge: str,
               response: bytes) -> dict:
        actual_hashes = [hashlib.sha256(item).hexdigest() for item in actual_inputs]
        if actual_hashes != expected_input_hashes:
            raise ValueError("unsealed context reached controlled runtime")
        if actual_model != expected_model:
            raise ValueError("controlled runtime model substitution")
        return create_attestation(
            self._secret, generation_id=generation_id, request_hash=request_hash,
            model_id=actual_model, runtime_id=self.runtime_id,
            measurement=self.measurement, challenge=challenge, response=response)
