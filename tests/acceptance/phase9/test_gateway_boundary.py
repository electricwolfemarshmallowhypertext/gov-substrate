"""Real mTLS gateway, independent witness, and networkless worker acceptance."""

import base64
import datetime
import ipaddress
import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from audit_witness import MTLSAuditWitness
from substrate import IntegrityError, Substrate


ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "compose.phase9.yaml"
PROFILE = {"model": "fixed-model", "upstream": "fixed-upstream",
           "allow_fallbacks": False, "data_collection": "deny",
           "zdr": True, "retention": "none"}
SECRET = b"phase-9-test-gateway-secret"


def command(prefix, *args, env, timeout=300):
    result = subprocess.run(["docker", *prefix, *args], cwd=ROOT, env=env,
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=timeout)
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))


def certificates(root):
    root.mkdir()
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 9 test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (root / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def issued(name, client=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=1))
                   .not_valid_after(now + datetime.timedelta(hours=1))
                   .add_extension(x509.ExtendedKeyUsage([
                       ExtendedKeyUsageOID.CLIENT_AUTH if client else
                       ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        if not client:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            ]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        (root / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        write_key(root / f"{name}.key", key)

    issued("server")
    issued("client", client=True)


def post(url, body, certs):
    context = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    context.load_cert_chain(str(certs / "client.crt"), str(certs / "client.key"))
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        return json.load(response)


@pytest.mark.runtime_enforcement
def test_only_mtls_gateway_has_provider_egress_and_witness_is_independent(
        tmp_path, acceptance_enabled):
    certs = tmp_path / "certs"
    certificates(certs)
    project = "govphase9" + uuid.uuid4().hex[:10]
    prefix = ["compose", "-p", project, "-f", str(COMPOSE)]
    env = {name: value for name, value in os.environ.items()
           if not any(word in name.upper() for word in
                      ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))}
    env.update(PHASE9_CERTS=str(certs), LAB_IMAGE_TAG=project)
    try:
        command(prefix, "build", "provider", env=env, timeout=1200)
        command(prefix, "up", "-d", "provider", "gateway", "witness", env=env)
        gateway_port = command(prefix, "port", "gateway", "8443", env=env).rsplit(":", 1)[1]
        witness_port = command(prefix, "port", "witness", "8444", env=env).rsplit(":", 1)[1]
        gateway_ip = command(prefix, "exec", "-T", "gateway", "hostname", "-i", env=env).split()[0]
        provider_ip = command(prefix, "exec", "-T", "provider", "hostname", "-i", env=env).split()[0]

        for _ in range(50):
            try:
                post(f"https://localhost:{witness_port}/verify",
                     {"event_id": 0, "event_hash": "0" * 64}, certs)
                post(f"https://localhost:{gateway_port}/unknown", {}, certs)
            except urllib.error.HTTPError:
                break
            except (OSError, TimeoutError):
                time.sleep(.1)
        else:
            raise AssertionError("mTLS services did not start")

        witness = MTLSAuditWitness(
            f"https://localhost:{witness_port}", str(certs / "ca.crt"),
            str(certs / "client.crt"), str(certs / "client.key"))
        actor = {"network": {"allowed": False},
                 "filesystem": {"read": False, "write": False}, "tools": {},
                 "persistence": {"session": True, "cross_session": False},
                 "shared_channels": []}
        substrate = Substrate(tmp_path / "phase9.db", {
            "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
            "operator_token": "operator-token", "providers": {
                "strict-provider": {"max_classification": "public",
                                    "request": PROFILE,
                                    "gateway_required": True}}},
            audit_witness=witness,
            gateway_secrets={"strict-provider": SECRET})
        session = substrate.create_session("agent")["session_token"]
        source = substrate.import_object(
            "public", "text/plain", base64.b64encode(b"sealed context").decode(),
            ["agent"], "phase9-acceptance")["object_id"]
        admitted = substrate.propose("agent", session, {
            "kind": "generation.prepare", "input_ids": [source],
            "provider": "strict-provider", "provider_request": PROFILE})
        claim = substrate.claim_generation(admitted["generation_id"],
                                           admitted["execution_token"], "strict-provider")
        payload = {
            "generation_id": admitted["generation_id"], "provider": "strict-provider",
            "request_hash": claim["request_hash"],
            "provider_request": claim["provider_request"],
            "input_ids": [item["id"] for item in claim["inputs"]],
            "input_hashes": [item["sha256"] for item in claim["inputs"]],
            "inputs": [item["content_base64"] for item in claim["inputs"]],
            "gateway_credential": claim["gateway_credential"],
        }
        with pytest.raises(urllib.error.HTTPError) as forged:
            post(f"https://localhost:{gateway_port}/generate",
                 dict(payload, gateway_credential="invented"), certs)
        assert forged.value.code == 403
        gateway_result = post(f"https://localhost:{gateway_port}/generate", payload, certs)
        completion = substrate.complete_generation(
            admitted["generation_id"], gateway_result["text"], gateway_result["receipt"])
        assert completion["decision"] == "succeeded"

        with pytest.raises(urllib.error.HTTPError) as replay:
            post(f"https://localhost:{gateway_port}/generate", payload, certs)
        assert replay.value.code == 409

        probe = json.loads(command(
            prefix, "run", "--rm", "-e", f"GATEWAY_IP={gateway_ip}",
            "-e", f"PROVIDER_IP={provider_ip}", "worker", env=env))
        assert probe == {"gateway_blocked": True, "provider_blocked": True,
                         "provider_credential_absent": True,
                         "gateway_secret_absent": True}

        command(prefix, "stop", "witness", env=env)
        with pytest.raises(IntegrityError, match="witness unavailable"):
            substrate.audit()
    finally:
        subprocess.run(["docker", *prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=180)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-phase9:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
