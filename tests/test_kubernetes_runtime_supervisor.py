"""Deterministic Kubernetes control tests; no cluster is required."""

import json

import pytest

from kubernetes_runtime_supervisor import KubernetesRuntimeSupervisor


IMAGE = "registry.invalid/gov-substrate/probe@sha256:" + "a" * 64


def supervisor(tmp_path, *, model_claim=None):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("test", encoding="utf-8")
    return KubernetesRuntimeSupervisor(
        "gov-runtime-test",
        IMAGE,
        "test-owner",
        kubeconfig=kubeconfig,
        context="kind-test",
        model_claim=model_claim,
    )


def pod(runtime, generation_id, *, phase="Running", uid="pod-uid"):
    value = runtime._pod_manifest(generation_id)
    value["metadata"]["uid"] = uid
    value["status"] = {
        "phase": phase,
        "containerStatuses": [{
            "restartCount": 0,
            "imageID": "containerd://sha256:" + "a" * 64,
            "state": {phase.lower(): {}},
        }],
    }
    return value


def test_manifest_has_restricted_one_shot_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_API_KEY", "must-not-cross-host-boundary")
    runtime = supervisor(tmp_path)
    manifest = runtime._pod_manifest("1" * 32)
    spec = manifest["spec"]
    worker = spec["containers"][0]

    assert spec["automountServiceAccountToken"] is False
    assert spec["restartPolicy"] == "Never"
    assert spec["hostNetwork"] is False
    assert spec["hostPID"] is False
    assert spec["hostIPC"] is False
    assert spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert worker["image"] == IMAGE
    assert worker["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "runAsGroup": 65534,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert worker["resources"] == {
        "requests": {
            "cpu": "50m",
            "memory": "52Mi",
            "ephemeral-storage": "10Mi",
        },
        "limits": {
            "cpu": "500m",
            "memory": "128Mi",
            "ephemeral-storage": "10Mi",
        },
    }
    assert "env" not in worker and "envFrom" not in worker
    assert "HOST_API_KEY" not in json.dumps(manifest)
    assert {volume["name"] for volume in spec["volumes"]} == {
        "private-tmp", "private-shm",
    }


def test_model_volume_is_optional_and_read_only(tmp_path):
    runtime = supervisor(tmp_path, model_claim="approved-model")
    manifest = runtime._pod_manifest("2" * 32)
    model_volume = next(
        volume for volume in manifest["spec"]["volumes"]
        if volume["name"] == "model"
    )
    model_mount = next(
        mount for mount in manifest["spec"]["containers"][0]["volumeMounts"]
        if mount["name"] == "model"
    )
    assert model_volume["persistentVolumeClaim"] == {
        "claimName": "approved-model", "readOnly": True,
    }
    assert model_mount == {
        "name": "model", "mountPath": "/model", "readOnly": True,
    }


def test_requires_digest_pinned_image_and_explicit_context(tmp_path):
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text("test", encoding="utf-8")
    with pytest.raises(ValueError, match="pinned"):
        KubernetesRuntimeSupervisor(
            "gov-runtime-test", "probe:latest", "test-owner",
            kubeconfig=kubeconfig, context="kind-test",
        )
    with pytest.raises(ValueError, match="context"):
        KubernetesRuntimeSupervisor(
            "gov-runtime-test", IMAGE, "test-owner",
            kubeconfig=kubeconfig, context="",
        )


def test_boundary_requires_restricted_namespace_and_deny_all_policy(tmp_path):
    runtime = supervisor(tmp_path)
    resources = {
        "namespace/gov-runtime-test": {
            "metadata": {"labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
            }},
        },
        "networkpolicy/gov-substrate-default-deny": {
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
            },
        },
    }
    runtime._get = lambda resource, **_kwargs: resources[resource]
    runtime._verify_boundary()

    resources["networkpolicy/gov-substrate-default-deny"]["spec"]["egress"] = [{}]
    with pytest.raises(RuntimeError, match="deny-all"):
        runtime._verify_boundary()


def test_stop_deletes_exact_uid_and_verifies_absence(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "3" * 32
    value = pod(runtime, generation_id)
    runtime._uids[generation_id] = "pod-uid"
    runtime._inspect = lambda _generation_id: value
    deleted = []

    def delete_uid(requested_generation, requested_uid):
        deleted.append((requested_generation, requested_uid))

    runtime._delete_uid = delete_uid
    result = runtime.stop((generation_id,))[0]

    assert result.confirmed is True
    assert result.runtime == "kubernetes"
    assert result.runtime_id == "pod-uid"
    assert result.state == "stopped"
    assert deleted == [(generation_id, "pod-uid")]


def test_reconcile_targets_only_owned_labeled_pods(tmp_path):
    runtime = supervisor(tmp_path)
    first, second = "4" * 32, "5" * 32
    items = [pod(runtime, first, uid="uid-one"), pod(runtime, second, uid="uid-two")]
    commands = []

    def kubectl(*args, **_kwargs):
        commands.append(args)
        return json.dumps({"items": items})

    stopped = []
    runtime._kubectl = kubectl
    runtime.stop = lambda generations: stopped.extend(generations) or tuple()
    assert runtime.reconcile() == ()
    assert stopped == [first, second]
    assert runtime._uids == {first: "uid-one", second: "uid-two"}
    assert commands == [(
        "get", "pods", "-l",
        "gov.substrate/managed=true,gov.substrate/owner=test-owner",
        "-o", "json",
    )]


def test_inspection_rejects_uid_or_isolation_shape_changes(tmp_path):
    runtime = supervisor(tmp_path)
    generation_id = "6" * 32
    value = pod(runtime, generation_id)
    runtime._uids[generation_id] = "expected-uid"
    with pytest.raises(RuntimeError, match="UID changed"):
        runtime._validate_pod(value, generation_id)

    runtime._uids.clear()
    value["metadata"]["uid"] = "expected-uid"
    value["spec"]["containers"][0]["securityContext"][
        "allowPrivilegeEscalation"
    ] = True
    with pytest.raises(RuntimeError, match="container shape"):
        runtime._validate_pod(value, generation_id)
