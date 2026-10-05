"""Real package-mirror-to-Kubernetes blast-radius experiment."""

import base64
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from generation_adapter import run_local_generation
from substrate import Substrate, create_app


ROOT = Path(__file__).resolve().parents[3]


def import_text(substrate, text):
    return substrate.import_object(
        "public", "text/plain", base64.b64encode(text.encode()).decode(),
        ["agent"], "phase9-kubernetes-fixture")["object_id"]


def probe_text(nonce, target_ip):
    return ("GOV_PROBE_CONFIG\nmode=scan\n" f"nonce={nonce}\n"
            f"target_ip={target_ip}\ngateway_ip={target_ip}\n")


@pytest.mark.runtime_enforcement
def test_package_mirror_cannot_expand_kubernetes_blast_radius(
        conformance_backend, tmp_path):
    backend = conformance_backend
    if backend.name != "kubernetes":
        pytest.skip("package-mirror blast-radius proof runs on Kubernetes only")
    mirror_image = os.getenv("KUBERNETES_PHASE9_IMAGE")
    assert mirror_image and "@sha256:" in mirror_image

    target = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "phase9-target", "namespace": backend.namespace,
                     "labels": {"phase9-role": "target"}},
        "spec": {"automountServiceAccountToken": False, "enableServiceLinks": False,
                 "restartPolicy": "Never", "securityContext": {
                     "runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "target", "image": backend.image,
                     "imagePullPolicy": "IfNotPresent",
                     "command": ["/usr/local/bin/gov-runtime-probe", "--serve"],
                     "securityContext": {"allowPrivilegeEscalation": False,
                         "readOnlyRootFilesystem": True, "runAsNonRoot": True,
                         "runAsUser": 65534, "runAsGroup": 65534,
                         "capabilities": {"drop": ["ALL"]},
                         "seccompProfile": {"type": "RuntimeDefault"}}}]}}
    target_service = {"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "phase9-target", "namespace": backend.namespace},
        "spec": {"selector": {"phase9-role": "target"},
                 "ports": [{"port": 8002, "targetPort": 8002}]}}
    mirror = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "phase9-mirror", "namespace": backend.namespace,
                     "labels": {"phase9-role": "mirror"}},
        "spec": {"automountServiceAccountToken": False, "enableServiceLinks": False,
                 "restartPolicy": "Never", "securityContext": {
                     "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "mirror", "image": mirror_image,
                     "imagePullPolicy": "IfNotPresent",
                     "command": ["python", "/app/service.py", "mirror"],
                     "env": [{"name": "PORT", "value": "8080"},
                             {"name": "TARGET_URL",
                              "value": "http://phase9-target:8002/"}],
                     "securityContext": {"allowPrivilegeEscalation": False,
                         "readOnlyRootFilesystem": True, "runAsNonRoot": True,
                         "runAsUser": 65532, "runAsGroup": 65532,
                         "capabilities": {"drop": ["ALL"]},
                         "seccompProfile": {"type": "RuntimeDefault"}}}]}}
    mirror_service = {"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "phase9-mirror", "namespace": backend.namespace},
        "spec": {"selector": {"phase9-role": "mirror"},
                 "ports": [{"port": 8002, "targetPort": 8080}]}}
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "phase9-mirror-only", "namespace": backend.namespace},
        "spec": {"podSelector": {"matchLabels": {"phase9-role": "mirror"}},
                 "policyTypes": ["Egress"], "egress": [{"to": [{"podSelector": {
                     "matchLabels": {"phase9-role": "target"}}}],
                     "ports": [{"protocol": "TCP", "port": 8002}]},
                    {"to": [{"namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": "kube-system"}}}],
                     "ports": [{"protocol": "UDP", "port": 53},
                               {"protocol": "TCP", "port": 53}]}]}}
    target_ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "phase9-target-from-mirror", "namespace": backend.namespace},
        "spec": {"podSelector": {"matchLabels": {"phase9-role": "target"}},
                 "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {
                     "matchLabels": {"phase9-role": "mirror"}}}],
                     "ports": [{"protocol": "TCP", "port": 8002}]}]}}
    backend._kubectl("create", "-f", "-", input_text=json.dumps({
        "apiVersion": "v1", "kind": "List",
        "items": [target, target_service, mirror, mirror_service, policy, target_ingress]}))
    backend._fixtures.extend((
        "networkpolicy/phase9-target-from-mirror",
        "networkpolicy/phase9-mirror-only", "service/phase9-mirror",
        "pod/phase9-mirror", "service/phase9-target", "pod/phase9-target"))
    backend._kubectl("wait", "--for=condition=Ready", "pod/phase9-target",
                     "pod/phase9-mirror", "--timeout=90s", timeout=100)
    mirror_info = json.loads(backend._kubectl("get", "service/phase9-mirror", "-o", "json"))
    mirror_ip = mirror_info["spec"]["clusterIP"]

    port = backend._free_port()
    forward = subprocess.Popen(
        backend._command("port-forward", "pod/phase9-mirror", f"{port}:8080",
                         "--address=127.0.0.1"), cwd=ROOT,
        env=backend.supervisor._environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    backend._port_forwards.append(forward)
    mirror_url = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            request = urllib.request.Request(mirror_url + "/proxy", data=b"{}",
                                             headers={"Content-Type": "application/json"},
                                             method="POST")
            with urllib.request.urlopen(request, timeout=1) as response:
                result = json.load(response)
            if result == {"proxied": "reachable"}:
                break
        except OSError:
            time.sleep(.1)
    else:
        raise AssertionError("package mirror could not reach the Kubernetes target")
    request = urllib.request.Request(mirror_url + "/credentials", data=b"{}",
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=2) as response:
        assert json.load(response) == {"service_account_token_present": False}

    actor = {"network": {"allowed": True, "services": [{
                 "origin": mirror_url, "mode": "delegated", "egress": "internal"}]},
             "filesystem": {"read": False, "write": False}, "tools": {},
             "persistence": {"session": True, "cross_session": False},
             "shared_channels": []}
    substrate = Substrate(tmp_path / "blast.db", {
        "actors": {"agent": actor}, "tokens": {"actor-token": "agent"},
        "operator_token": "adapter-token", "circuit_operator_token": "control-token"},
        runtime_supervisor=backend.supervisor)
    session = substrate.create_session("agent")["session_token"]
    denied = substrate.propose("agent", session, {
        "kind": "network.request", "url": mirror_url + "/proxy"})
    assert denied["decision"] == "deny"
    assert denied["reason"] == "delegated_service_unmediated"

    config = import_text(substrate, probe_text(os.urandom(12).hex(), mirror_ip))
    prepared = substrate.propose("agent", session, {
        "kind": "generation.prepare", "input_ids": [config]})
    client = TestClient(create_app(substrate))
    output = run_local_generation(client, prepared["generation_id"], "adapter-token",
                                  prepared["execution_token"], backend.supervisor)
    read = substrate.propose("agent", session, {
        "kind": "object.read", "object_id": output["object_id"]})
    report = json.loads(base64.b64decode(read["content_base64"], validate=True))
    attempts = {item["attempt"]: item for item in report["attempts"]}
    assert attempts["other_container"]["allowed"] is False
    assert attempts["environment_secrets"]["allowed"] is False
    assert attempts["unexpected_mount:/run/secrets"]["allowed"] is False
