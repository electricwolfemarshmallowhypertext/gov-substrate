"""Real mTLS gateway, independent witness, and networkless worker acceptance."""

import base64
import datetime
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from audit_witness import MTLSAuditWitness
from substrate import IntegrityError, Substrate, canonical, create_app, digest


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


def free_port():
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 0))
        return listener.getsockname()[1]


@pytest.mark.runtime_enforcement
def test_only_mtls_gateway_has_provider_egress_and_witness_is_independent(
        tmp_path, acceptance_enabled):
    certs = tmp_path / "certs"
    certificates(certs)
    project = "govphase9" + uuid.uuid4().hex[:10]
    substrate_port = free_port()
    prefix = ["compose", "-p", project, "-f", str(COMPOSE)]
    env = {name: value for name, value in os.environ.items()
           if not any(word in name.upper() for word in
                      ("API_KEY", "TOKEN", "SECRET", "PASSWORD"))}
    env.update(PHASE9_CERTS=str(certs), LAB_IMAGE_TAG=project,
               PHASE9_SUBSTRATE_URL=f"http://host.docker.internal:{substrate_port}")
    server = None
    server_thread = None
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
        db_path = tmp_path / "phase9.db"
        substrate = Substrate(db_path, {
            "actors": {"agent": actor}, "tokens": {"agent-token": "agent"},
            "operator_token": "operator-token", "circuit_operator_token": "control-token",
            "providers": {
                "strict-provider": {"max_classification": "public",
                                    "request": PROFILE,
                                    "gateway_required": True}}},
            audit_witness=witness,
            gateway_secrets={"strict-provider": SECRET},
            require_audit_witness=True)
        server = uvicorn.Server(uvicorn.Config(
            create_app(substrate), host="0.0.0.0", port=substrate_port,
            log_level="error"))
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(.05)
        else:
            raise AssertionError("substrate callback did not start")
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

        state = substrate.propose("agent", session, {
            "kind": "state.write", "scope": "session", "key": "integrity",
            "value": "trusted"})
        assert state["decision"] == "allow"
        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone()
            original = (row["state_after"], row["event_hash"])
            db.execute("DROP TRIGGER events_no_update")
            db.execute("UPDATE state SET value=? WHERE key='integrity'",
                       (canonical("tampered"),))
            snapshot = json.loads(row["state_after"])
            for item in snapshot["state"]:
                if item["key"] == "integrity":
                    item["value"] = canonical("tampered")
            fields = {key: row[key] for key in (
                "timestamp", "actor", "action", "policy", "decision",
                "state_before", "state_after", "override_of", "elapsed_ms",
                "prev_hash")}
            fields["state_after"] = canonical(snapshot)
            db.execute("UPDATE events SET state_after=?,event_hash=? WHERE id=?",
                       (fields["state_after"], digest(fields), row["id"]))
        with pytest.raises(IntegrityError, match="witness diverged"):
            substrate.audit()
        with sqlite3.connect(db_path) as db:
            db.execute("UPDATE state SET value=? WHERE key='integrity'",
                       (canonical("trusted"),))
            db.execute("UPDATE events SET state_after=?,event_hash=? WHERE id=?",
                       (original[0], original[1], row["id"]))
            db.execute("""CREATE TRIGGER events_no_update BEFORE UPDATE ON events
                        BEGIN SELECT RAISE(ABORT, 'audit events are append only'); END""")
        assert substrate.audit()[-1]["event_hash"] == original[1]

        second = substrate.propose("agent", session, {
            "kind": "generation.prepare", "input_ids": [source],
            "provider": "strict-provider", "provider_request": PROFILE})
        second_claim = substrate.claim_generation(
            second["generation_id"], second["execution_token"], "strict-provider")
        denied_payload = dict(
            payload, generation_id=second["generation_id"],
            request_hash=second_claim["request_hash"],
            gateway_credential=second_claim["gateway_credential"])
        before_calls = json.loads(command(
            prefix, "exec", "-T", "provider", "python", "-c",
            "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/count'))['calls'])",
            env=env))
        substrate.set_circuit("control-token", "provider", "strict-provider", True,
                              "provider compromise")
        with pytest.raises(urllib.error.HTTPError) as revoked:
            post(f"https://localhost:{gateway_port}/generate", denied_payload, certs)
        assert revoked.value.code == 403
        after_calls = json.loads(command(
            prefix, "exec", "-T", "provider", "python", "-c",
            "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8080/count'))['calls'])",
            env=env))
        assert before_calls == after_calls

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
        if server is not None:
            server.should_exit = True
        if server_thread is not None:
            server_thread.join(timeout=10)
        subprocess.run(["docker", *prefix, "down", "--volumes", "--remove-orphans"],
                       cwd=ROOT, env=env, capture_output=True, timeout=180)
        subprocess.run(["docker", "image", "rm", f"gov-substrate-phase9:{project}"],
                       cwd=ROOT, env=env, capture_output=True, timeout=60)
