"""Unpaid signed-token fixtures; real Google evidence remains the cloud gate."""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from attested_generation_adapter import run_attested_generation
from confidential_space_worker import ConfidentialSpaceWorker
from provider_gateway import canonical
from substrate import Substrate, create_app


IMAGE = "sha256:" + "a" * 64
AUDIENCE = "gov-substrate-attestation"
GATEWAY_KEY = b"synthetic-gateway-secret"
MODELS = ("Qwen3-0.6B-Q8_0.gguf", "Phi-4-mini-instruct-Q8_0.gguf")


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signed_token(key, claims):
    header = encoded(json.dumps({"alg": "RS256", "kid": "fixture-key"}).encode())
    payload = encoded(json.dumps(claims).encode())
    signature = key.sign((header + "." + payload).encode(),
                         padding.PKCS1v15(), hashes.SHA256())
    return header + "." + payload + "." + encoded(signature)


def jwks_for(key):
    public = key.public_key().public_numbers()
    return {"keys": [{"kid": "fixture-key", "kty": "RSA", "alg": "RS256",
                      "n": encoded(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")),
                      "e": encoded(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big"))}]}


def setup(tmp_path, monkeypatch, model_name, mode):
    fake_model = tmp_path / model_name
    fake_model.write_bytes(b"GGUF deterministic model fixture")
    model_hash = hashlib.sha256(fake_model.read_bytes()).hexdigest()
    monkeypatch.setattr("confidential_space_worker.MODEL_HASHES", {model_name: model_hash})
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr("substrate.fetch_google_jwks", lambda: jwks_for(signing_key))
    def issue(audience, nonces):
        now = int(time.time())
        claims = {
            "iss": "https://confidentialcomputing.googleapis.com", "aud": audience,
            "iat": now, "nbf": now, "exp": now + 300,
            "eat_nonce": nonces if mode != "wrong_nonce" else ["wrong-nonce", nonces[1]],
            "swname": "CONFIDENTIAL_SPACE", "dbgstat": "disabled-since-boot",
            "secboot": True, "hwmodel": "GCP_AMD_SEV",
            "submods": {"container": {"image_digest": IMAGE if mode != "wrong_image"
                                       else "sha256:" + "b" * 64},
                        "gce": {"project_id": "fixture-project", "zone": "us-central1-a"},
                        "confidential_space": {"support_attributes": ["STABLE"]}},
        }
        return signed_token(signing_key, claims)
    worker = ConfidentialSpaceWorker(fake_model, token_issuer=issue,
                                     inference=lambda _path, _inputs: "Governed response")

    class Transport:
        execute_calls = 0
        def attest(self, body):
            result = worker.attest(body)
            if mode == "wrong_model":
                result["model_sha256"] = "0" * 64
            return result
        def execute(self, body):
            self.execute_calls += 1
            result = worker.execute(body)
            if mode == "wrong_result":
                result["result"]["output_sha256"] = "0" * 64
            return result
    transport = Transport()
    profile = {"model": model_name, "upstream": "google-confidential-space",
               "allow_fallbacks": False, "data_collection": "deny",
               "zdr": True, "retention": "none"}
    actor = {
        "data": {"sensitive_access": False},
        "network": {"allowed": True, "publication": True, "services": [
            {"origin": "http://127.0.0.1:9", "mode": "publication",
             "egress": "external", "paths": ["/publish"]}]},
        "filesystem": {"read": False, "write": False}, "tools": {},
        "persistence": {"session": True, "cross_session": False},
        "shared_channels": [],
    }
    substrate = Substrate(tmp_path / "attested.db", {
        "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
        "operator_token": "operator-token", "providers": {"fixture": {
            "max_classification": "public", "request": profile,
            "gateway_required": True, "assurance": "hosted_attested",
            "attestation": {"kind": "google_confidential_space",
                            "audience": AUDIENCE, "image_digest": IMAGE,
                            "model_sha256": model_hash, "project_id": "fixture-project",
                            "zone": "us-central1-a", "hwmodel": "GCP_AMD_SEV"}}},
    }, gateway_secrets={"fixture": GATEWAY_KEY})
    published = []
    def fake_fetch(url, origins):
        published.append(url)
        return {"status": 200, "bytes": 1, "body_sha256": "0" * 64,
                "origin": origins[0], "resolved_ip": "127.0.0.1"}
    monkeypatch.setattr("substrate.fetch", fake_fetch)
    source = substrate.import_object("public", "text/plain",
        base64.b64encode(b"Public governed context").decode(),
        ["agent"], "fixture")["object_id"]
    session = substrate.create_session("agent")["session_token"]
    prepared = substrate.propose("agent", session, {"kind": "generation.prepare",
        "input_ids": [source], "provider": "fixture", "provider_request": profile})
    assert prepared["decision"] == "allow"
    return substrate, TestClient(create_app(substrate)), session, prepared, transport, model_hash, published


@pytest.mark.parametrize("model_name", MODELS)
@pytest.mark.parametrize("mode", ["valid", "wrong_nonce", "wrong_image",
                                  "wrong_model", "wrong_result"])
def test_shared_attested_path_and_fail_closed_cases(tmp_path, monkeypatch, model_name, mode):
    substrate, client, session, prepared, transport, model_hash, published = setup(
        tmp_path, monkeypatch, model_name, mode)
    invoke = lambda: run_attested_generation(
        client, prepared["generation_id"], "operator-token",
        prepared["execution_token"], "fixture", model_hash,
        AUDIENCE, transport, GATEWAY_KEY)
    if mode == "valid":
        result = invoke()
        assert result["decision"] == "succeeded"
        assert result["classification"] == "public"
        assert substrate.propose("agent", session, {"kind": "object.publish",
            "object_id": result["object_id"],
            "destination": "http://127.0.0.1:9"})["outcome"] == "succeeded"
        assert transport.execute_calls == 1 and len(published) == 1
    else:
        with pytest.raises(RuntimeError):
            invoke()
        assert not published
        assert transport.execute_calls == (1 if mode == "wrong_result" else 0)
        if mode != "wrong_result":
            assert any(event["action"]["kind"] == "provider.call.authorize" and
                       event["decision"] == "deny" for event in substrate.audit())
        assert not any(event["action"]["kind"] == "generation.complete" and
                       event["decision"] == "succeeded" for event in substrate.audit())


def test_documented_pinned_artifacts_unchanged():
    from confidential_space_worker import MODEL_HASHES
    assert MODEL_HASHES == {
        "Qwen3-0.6B-Q8_0.gguf": "12fae8b8f78f0360b498d04c8db7d33aff29ab7d8080231f93a17c18119e6735",
        "Phi-4-mini-instruct-Q8_0.gguf": "3e81a3ad900b6d67df011d42ef14bad63354a3516fbd229b9bf29755363b25ee",
    }
