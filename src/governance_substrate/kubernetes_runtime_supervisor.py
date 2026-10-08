"""Kubernetes backend for supervised, one-shot generation workers."""

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from .runtime_supervisor import StopResult


_GENERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_OWNER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}\Z")
_RUNTIME_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}\Z")
_IMAGE_DIGEST = re.compile(r"[^\s@]+@sha256:([0-9a-f]{64})\Z")

_MANAGED_LABEL = "gov.substrate/managed"
_GENERATION_LABEL = "gov.substrate/generation-id"
_OWNER_LABEL = "gov.substrate/owner"
_DEFAULT_DENY_POLICY = "gov-substrate-default-deny"


class KubernetesRuntimeSupervisor:
    """Launch and terminate exact Kubernetes Pods through kubectl."""

    def __init__(
        self,
        namespace: str,
        image: str,
        owner: str,
        *,
        kubeconfig: str | Path,
        context: str,
        kubectl: str | Path = "kubectl",
        model_claim: str | None = None,
        runtime_name: str = "kubernetes",
    ):
        if not isinstance(namespace, str) or not _DNS_LABEL.fullmatch(namespace):
            raise ValueError("valid lowercase Kubernetes namespace required")
        image_match = _IMAGE_DIGEST.fullmatch(image) if isinstance(image, str) else None
        if image_match is None:
            raise ValueError("Kubernetes worker image must be pinned by sha256 digest")
        if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
            raise ValueError("valid lowercase runtime owner required")
        if not isinstance(context, str) or not context or any(ch.isspace() for ch in context):
            raise ValueError("explicit Kubernetes context required")
        if not isinstance(runtime_name, str) or not _RUNTIME_NAME.fullmatch(runtime_name):
            raise ValueError("valid lowercase runtime name required")
        if model_claim is not None and not _DNS_LABEL.fullmatch(model_claim):
            raise ValueError("valid model PVC name required")

        self.namespace = namespace
        self.image = image
        self.image_digest = image_match.group(1)
        self.owner = owner
        self.context = context
        self.kubectl = str(kubectl)
        self.kubeconfig = Path(kubeconfig).resolve(strict=True)
        self.model_claim = model_claim
        self.runtime_name = runtime_name
        self._lock = threading.RLock()
        self._running: dict[str, subprocess.Popen] = {}
        self._cancelled: set[str] = set()
        self._started: set[str] = set()
        self._uids: dict[str, str] = {}
        self._environment = dict(os.environ)
        self._environment["KUBECONFIG"] = str(self.kubeconfig)

    @staticmethod
    def _name(generation_id: str) -> str:
        if not isinstance(generation_id, str) or not _GENERATION_ID.fullmatch(generation_id):
            raise ValueError("invalid generation ID")
        return f"gov-substrate-{generation_id}"

    def _command(self, *args: str) -> list[str]:
        return [
            self.kubectl,
            "--context", self.context,
            "--namespace", self.namespace,
            *args,
        ]

    def _kubectl(
        self,
        *args: str,
        input_text: str | None = None,
        timeout: int = 30,
    ) -> str:
        result = subprocess.run(
            self._command(*args),
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=self._environment,
        )
        if result.returncode:
            raise RuntimeError("Kubernetes control command failed")
        return result.stdout.strip()

    def _get(self, resource: str, *, missing_ok: bool = False) -> dict | None:
        result = subprocess.run(
            self._command("get", resource, "-o", "json"),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            env=self._environment,
        )
        if result.returncode:
            if missing_ok and "NotFound" in result.stderr:
                return None
            raise RuntimeError("Kubernetes resource inspection failed")
        return json.loads(result.stdout)

    def _verify_boundary(self) -> None:
        namespace = self._get(f"namespace/{self.namespace}")
        labels = namespace.get("metadata", {}).get("labels", {})
        if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
            raise RuntimeError("Kubernetes namespace must enforce restricted Pod Security")
        policy = self._get(f"networkpolicy/{_DEFAULT_DENY_POLICY}")
        spec = policy.get("spec", {})
        if (
            spec.get("podSelector") != {}
            or set(spec.get("policyTypes", [])) != {"Ingress", "Egress"}
            or spec.get("ingress")
            or spec.get("egress")
        ):
            raise RuntimeError("Kubernetes namespace must have deny-all ingress and egress")

    def _pod_manifest(self, generation_id: str) -> dict:
        name = self._name(generation_id)
        volumes = [
            {"name": "private-tmp", "emptyDir": {"sizeLimit": "16Mi"}},
            {
                "name": "private-shm",
                "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"},
            },
        ]
        mounts = [
            {"name": "private-tmp", "mountPath": "/tmp"},
            {"name": "private-shm", "mountPath": "/dev/shm"},
        ]
        if self.model_claim is not None:
            volumes.append({
                "name": "model",
                "persistentVolumeClaim": {
                    "claimName": self.model_claim,
                    "readOnly": True,
                },
            })
            mounts.append({"name": "model", "mountPath": "/model", "readOnly": True})

        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": self.namespace,
                "labels": {
                    _MANAGED_LABEL: "true",
                    _GENERATION_LABEL: generation_id,
                    _OWNER_LABEL: self.owner,
                },
            },
            "spec": {
                "automountServiceAccountToken": False,
                "enableServiceLinks": False,
                "restartPolicy": "Never",
                "terminationGracePeriodSeconds": 1,
                "activeDeadlineSeconds": 130,
                "hostNetwork": False,
                "hostPID": False,
                "hostIPC": False,
                "dnsPolicy": "None",
                "dnsConfig": {"nameservers": ["127.0.0.1"]},
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "fsGroup": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [{
                    "name": "worker",
                    "image": self.image,
                    "imagePullPolicy": "IfNotPresent",
                    "command": [
                        "/usr/bin/env", "-i",
                        "PATH=/usr/local/bin:/usr/bin:/bin",
                        "HOME=/tmp",
                        "/usr/local/bin/gov-runtime-probe",
                    ],
                    "stdin": True,
                    "stdinOnce": True,
                    "tty": False,
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "runAsNonRoot": True,
                        "runAsUser": 65534,
                        "runAsGroup": 65534,
                        "capabilities": {"drop": ["ALL"]},
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "resources": {
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
                    },
                    "volumeMounts": mounts,
                }],
                "volumes": volumes,
            },
        }

    def _validate_pod(self, pod: dict, generation_id: str) -> dict:
        name = self._name(generation_id)
        metadata = pod.get("metadata", {})
        labels = metadata.get("labels", {})
        uid = metadata.get("uid")
        if (
            metadata.get("name") != name
            or metadata.get("namespace") != self.namespace
            or not isinstance(uid, str)
            or not uid
            or labels.get(_MANAGED_LABEL) != "true"
            or labels.get(_GENERATION_LABEL) != generation_id
            or labels.get(_OWNER_LABEL) != self.owner
        ):
            raise RuntimeError("Kubernetes worker identity mismatch")

        expected = self._pod_manifest(generation_id)["spec"]
        spec = pod.get("spec", {})
        fixed_fields = (
            "automountServiceAccountToken", "enableServiceLinks", "restartPolicy",
            "terminationGracePeriodSeconds", "activeDeadlineSeconds", "dnsPolicy",
            "dnsConfig", "securityContext", "volumes",
        )
        if any(spec.get(field) != expected[field] for field in fixed_fields):
            raise RuntimeError("Kubernetes worker isolation shape mismatch")
        if any(spec.get(field, False) is not False
               for field in ("hostNetwork", "hostPID", "hostIPC")):
            raise RuntimeError("Kubernetes worker uses a host namespace")
        containers = spec.get("containers", [])
        if len(containers) != 1:
            raise RuntimeError("Kubernetes worker must contain exactly one container")
        container = containers[0]
        expected_container = expected["containers"][0]
        checked_container_fields = (
            "name", "image", "imagePullPolicy", "command", "stdin", "stdinOnce",
            "securityContext", "resources", "volumeMounts",
        )
        if any(container.get(field) != expected_container[field]
               for field in checked_container_fields):
            raise RuntimeError("Kubernetes worker container shape mismatch")
        if container.get("tty", False) is not False:
            raise RuntimeError("Kubernetes worker container shape mismatch")
        if container.get("env") or container.get("envFrom") or container.get("ports"):
            raise RuntimeError("Kubernetes worker has unexpected ambient configuration")

        statuses = pod.get("status", {}).get("containerStatuses") or []
        if statuses:
            status = statuses[0]
            if status.get("restartCount") != 0:
                raise RuntimeError("Kubernetes worker must not restart")
        known_uid = self._uids.get(generation_id)
        if known_uid is not None and known_uid != uid:
            raise RuntimeError("Kubernetes worker UID changed")
        return pod

    def _inspect(self, generation_id: str) -> dict | None:
        name = self._name(generation_id)
        pod = self._get(f"pod/{name}", missing_ok=True)
        return None if pod is None else self._validate_pod(pod, generation_id)

    def _create_pod(self, generation_id: str) -> dict:
        self._verify_boundary()
        manifest = json.dumps(self._pod_manifest(generation_id), separators=(",", ":"))
        created = json.loads(self._kubectl(
            "create", "-f", "-", "-o", "json", input_text=manifest,
        ))
        created = self._validate_pod(created, generation_id)
        self._uids[generation_id] = created["metadata"]["uid"]
        return created

    def _wait_running(self, generation_id: str, timeout: float = 45) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pod = self._inspect(generation_id)
            if pod is not None:
                phase = pod.get("status", {}).get("phase")
                statuses = pod.get("status", {}).get("containerStatuses") or []
                if phase == "Running" and statuses and statuses[0].get("state", {}).get("running"):
                    return pod
                if phase in ("Failed", "Succeeded"):
                    raise RuntimeError("Kubernetes worker exited before execution")
            time.sleep(0.1)
        raise RuntimeError("Kubernetes worker did not become attachable")

    def _wait_terminal(self, generation_id: str, timeout: float = 30) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pod = self._inspect(generation_id)
            if pod is None:
                raise RuntimeError("Kubernetes worker disappeared before verification")
            if pod.get("status", {}).get("phase") in ("Succeeded", "Failed"):
                return pod
            time.sleep(0.1)
        raise RuntimeError("Kubernetes worker exit could not be verified")

    def _attach_command(self, generation_id: str) -> list[str]:
        return self._command("attach", "-i", self._name(generation_id), "-c", "worker")

    def _delete_uid(self, generation_id: str, uid: str) -> None:
        name = self._name(generation_id)
        options = json.dumps({
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "gracePeriodSeconds": 0,
            "propagationPolicy": "Background",
            "preconditions": {"uid": uid},
        }, separators=(",", ":"))
        path = f"/api/v1/namespaces/{self.namespace}/pods/{name}"
        self._kubectl("delete", "--raw", path, "-f", "-", input_text=options)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = self._get(f"pod/{name}", missing_ok=True)
            if current is None:
                return
            if current.get("metadata", {}).get("uid") != uid:
                raise RuntimeError("Kubernetes worker name was reused during deletion")
            time.sleep(0.1)
        raise RuntimeError("Kubernetes worker removal could not be verified")

    def runtime_identity(self, generation_id: str) -> str | None:
        pod = self._inspect(generation_id)
        if pod is None:
            return None
        return pod["metadata"]["uid"]

    def run(self, generation_id: str, sealed_context: str) -> str:
        self._name(generation_id)
        with self._lock:
            if generation_id in self._started or generation_id in self._cancelled:
                raise RuntimeError("generation already running or revoked")
            self._started.add(generation_id)
            pod = self._create_pod(generation_id)
            uid = pod["metadata"]["uid"]
        self._wait_running(generation_id)
        process = subprocess.Popen(
            self._attach_command(generation_id),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self._environment,
        )
        with self._lock:
            self._running[generation_id] = process
        try:
            try:
                stdout, _ = process.communicate(input=sealed_context, timeout=120)
            except subprocess.TimeoutExpired:
                self.stop((generation_id,))
                raise RuntimeError("local generation timed out") from None
            with self._lock:
                if generation_id in self._cancelled or process.returncode:
                    self.stop((generation_id,))
                    raise RuntimeError("local generation stopped or failed")
                terminal = self._wait_terminal(generation_id)
                if terminal.get("status", {}).get("phase") != "Succeeded":
                    self.stop((generation_id,))
                    raise RuntimeError("local generation stopped or failed")
                self._delete_uid(generation_id, uid)
                return stdout
        finally:
            with self._lock:
                self._running.pop(generation_id, None)

    def stop(self, generation_ids: tuple[str, ...]) -> tuple[StopResult, ...]:
        with self._lock:
            return tuple(self._stop_one(generation_id) for generation_id in generation_ids)

    def _stop_one(self, generation_id: str) -> StopResult:
        self._name(generation_id)
        self._cancelled.add(generation_id)
        process = self._running.get(generation_id)
        runtime_id = None
        try:
            pod = self._inspect(generation_id)
            if pod is None:
                return StopResult(
                    generation_id, self.runtime_name, None, True, "absent"
                )
            runtime_id = pod["metadata"]["uid"]
            self._delete_uid(generation_id, runtime_id)
            return StopResult(
                generation_id, self.runtime_name, runtime_id, True, "stopped"
            )
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
            return StopResult(
                generation_id, self.runtime_name, runtime_id,
                False, "stop_unconfirmed",
            )
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

    def reconcile(self) -> tuple[StopResult, ...]:
        selector = f"{_MANAGED_LABEL}=true,{_OWNER_LABEL}={self.owner}"
        payload = json.loads(self._kubectl("get", "pods", "-l", selector, "-o", "json"))
        generations = []
        for pod in payload.get("items", []):
            generation_id = pod.get("metadata", {}).get("labels", {}).get(
                _GENERATION_LABEL
            )
            self._validate_pod(pod, generation_id)
            self._uids[generation_id] = pod["metadata"]["uid"]
            generations.append(generation_id)
        return self.stop(tuple(generations))
