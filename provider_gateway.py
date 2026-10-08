"""Trusted gateway receipts for exact hosted-provider requests and responses."""

from __future__ import annotations

import hashlib
import hmac
import json
import base64
import secrets
import time
from dataclasses import dataclass


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_identity(generation_id: str, provider: str, profile: dict,
                     input_ids: list[str], input_hashes: list[str]) -> str:
    return hashlib.sha256(canonical({
        "generation_id": generation_id,
        "provider": provider,
        "profile": profile,
        "input_ids": input_ids,
        "input_hashes": input_hashes,
    }).encode()).hexdigest()


def receipt_payload(generation_id: str, provider: str, request_hash: str,
                    response_hash: str, challenge: str,
                    attestation_hash: str | None = None) -> dict:
    payload = {
        "generation_id": generation_id,
        "provider": provider,
        "request_hash": request_hash,
        "response_hash": response_hash,
        "challenge": challenge,
    }
    if attestation_hash is not None:
        payload["attestation_hash"] = attestation_hash
    return payload


def sign_receipt(secret: bytes, payload: dict) -> str:
    return hmac.new(secret, canonical(payload).encode(), hashlib.sha256).hexdigest()


def issue_gateway_credential(secret: bytes, actor: str, generation_id: str,
                             provider: str, request_hash: str,
                             expires_at: float) -> str:
    payload = canonical({"actor": actor, "generation_id": generation_id,
                         "provider": provider, "request_hash": request_hash,
                         "expires_at": expires_at,
                         "nonce": secrets.token_hex(32)})
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    signature = hmac.new(secret, encoded.encode(), hashlib.sha256).hexdigest()
    return encoded + "." + signature


def verify_gateway_credential(secret: bytes, credential: str,
                              now: float | None = None) -> dict | None:
    if not isinstance(credential, str) or credential.count(".") != 1:
        return None
    encoded, signature = credential.split(".")
    expected = hmac.new(secret, encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(
            encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None
    required = {"actor", "generation_id", "provider", "request_hash",
                "expires_at", "nonce"}
    if (type(payload) is not dict or set(payload) != required or
            any(type(payload[key]) is not str or not payload[key]
                for key in required - {"expires_at"}) or
            not isinstance(payload["expires_at"], (int, float)) or
            payload["expires_at"] <= (time.time() if now is None else now)):
        return None
    return payload


@dataclass(frozen=True)
class GatewayReceipt:
    generation_id: str
    provider: str
    request_hash: str
    response_hash: str
    challenge: str
    signature: str
    attestation_hash: str | None = None

    def as_dict(self) -> dict:
        return {
            **receipt_payload(self.generation_id, self.provider, self.request_hash,
                              self.response_hash, self.challenge,
                              self.attestation_hash),
            "signature": self.signature,
        }


def create_receipt(secret: bytes, generation_id: str, provider: str,
                   request_hash: str, response: bytes, challenge: str,
                   attestation: dict | None = None) -> GatewayReceipt:
    response_hash = hashlib.sha256(response).hexdigest()
    attestation_hash = (hashlib.sha256(canonical(attestation).encode()).hexdigest()
                        if attestation is not None else None)
    payload = receipt_payload(generation_id, provider, request_hash,
                              response_hash, challenge, attestation_hash)
    return GatewayReceipt(generation_id, provider, request_hash, response_hash,
                          challenge, sign_receipt(secret, payload), attestation_hash)


def verify_receipt(secret: bytes, receipt: dict) -> bool:
    required = {"generation_id", "provider", "request_hash", "response_hash",
                "challenge", "signature"}
    if type(receipt) is not dict or set(receipt) not in (required, required | {"attestation_hash"}):
        return False
    if any(type(receipt[key]) is not str or not receipt[key] for key in required):
        return False
    if "attestation_hash" in receipt and (
            type(receipt["attestation_hash"]) is not str or
            len(receipt["attestation_hash"]) != 64):
        return False
    payload = {key: receipt[key] for key in required - {"signature"}}
    if "attestation_hash" in receipt:
        payload["attestation_hash"] = receipt["attestation_hash"]
    return hmac.compare_digest(receipt["signature"], sign_receipt(secret, payload))
