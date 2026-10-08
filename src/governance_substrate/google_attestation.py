"""Verify Google Confidential Space evidence and a measured workload result."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from urllib.request import urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from .provider_gateway import canonical


ISSUER = "https://confidentialcomputing.googleapis.com"
JWKS_URL = ("https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
            "signer@confidentialspace-sign.iam.gserviceaccount.com")
RESULT_FIELDS = {"generation_id", "request_hash", "model_sha256",
                 "output_sha256", "image_digest", "nonce"}


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fetch_google_jwks() -> dict:
    """Fetch only Google's fixed signing-key endpoint; failure denies transfer."""
    with urlopen(JWKS_URL, timeout=5) as response:
        raw = response.read(128_001)
    if len(raw) > 128_000:
        raise ValueError("attestation signing-key response too large")
    return json.loads(raw)


def key_binding(request_hash: str, model_sha256: str, nonce: str,
                exchange_public_key: str, result_public_key: str) -> str:
    return hashlib.sha256(canonical({
        "domain": "gov-substrate-confidential-space-v1",
        "request_hash": request_hash, "model_sha256": model_sha256,
        "nonce": nonce, "exchange_public_key": exchange_public_key,
        "result_public_key": result_public_key,
    }).encode()).hexdigest()


def verify_google_attestation(token: str, jwks: dict, *, audience: str,
                              image_digest: str, project_id: str, zone: str,
                              hwmodel: str, nonce: str, binding: str) -> bool:
    """Verify signature and exact production-workload claims, not provider metadata."""
    try:
        if type(token) is not str or len(token) > 128_000:
            return False
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        header = json.loads(decode(encoded_header))
        claims = json.loads(decode(encoded_claims))
        if (type(header) is not dict or header.get("alg") != "RS256" or
                type(header.get("kid")) is not str or type(jwks) is not dict or
                type(jwks.get("keys")) is not list):
            return False
        keys = [key for key in jwks["keys"] if type(key) is dict and
                key.get("kid") == header["kid"] and key.get("kty") == "RSA" and
                key.get("alg", "RS256") == "RS256"]
        if len(keys) != 1:
            return False
        key = keys[0]
        public_key = rsa.RSAPublicNumbers(int.from_bytes(decode(key["e"]), "big"),
                                          int.from_bytes(decode(key["n"]), "big")
                                          ).public_key()
        public_key.verify(decode(encoded_signature),
                          (encoded_header + "." + encoded_claims).encode(),
                          padding.PKCS1v15(), hashes.SHA256())
        now = time.time()
        if (type(claims) is not dict or claims.get("iss") != ISSUER or
                claims.get("aud") != audience or
                type(claims.get("exp")) is not int or claims["exp"] <= now or
                type(claims.get("iat")) is not int or claims["iat"] > now + 60 or
                claims["iat"] < now - 7200 or
                type(claims.get("nbf")) is not int or claims["nbf"] > now or
                claims.get("eat_nonce") not in ([nonce, binding], [binding, nonce]) or
                claims.get("swname") != "CONFIDENTIAL_SPACE" or
                claims.get("dbgstat") != "disabled-since-boot" or
                claims.get("secboot") is not True or
                claims.get("hwmodel") != hwmodel):
            return False
        submods = claims.get("submods", {})
        container = submods.get("container", {})
        gce = submods.get("gce", {})
        support = submods.get("confidential_space", {}).get("support_attributes", [])
        return (container.get("image_digest") == image_digest and
                gce.get("project_id") == project_id and gce.get("zone") == zone and
                type(support) is list and "STABLE" in support)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError,
            binascii.Error, InvalidSignature):
        return False


def verify_attested_result(public_key_b64: str, result: dict,
                           expected: dict) -> bool:
    if (type(result) is not dict or set(result) != RESULT_FIELDS | {"signature"} or
            any(result.get(key) != value for key, value in expected.items())):
        return False
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(decode(public_key_b64))
        payload = {key: result[key] for key in RESULT_FIELDS}
        public_key.verify(decode(result["signature"]), canonical(payload).encode())
        return True
    except (ValueError, TypeError, KeyError, AttributeError,
            binascii.Error, InvalidSignature):
        return False
