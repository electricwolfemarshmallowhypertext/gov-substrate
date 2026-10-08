"""Encrypted one-use exchange between the trusted driver and attested workload."""

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .provider_gateway import canonical


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def session_key(shared_secret: bytes, request_hash: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=bytes.fromhex(request_hash),
                info=b"gov-substrate-confidential-space-v1").derive(shared_secret)


def associated_data(generation_id: str, request_hash: str,
                    model_sha256: str) -> bytes:
    return canonical({"generation_id": generation_id,
                      "request_hash": request_hash,
                      "model_sha256": model_sha256}).encode()
