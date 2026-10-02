"""Write a sanitized, machine-readable manifest for runtime evidence."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def command(*args, required=True):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=30,
        )
    except FileNotFoundError:
        if required:
            raise RuntimeError(
                f"environment command unavailable: {args[0]}"
            ) from None
        return {
            "command": list(args),
            "returncode": 127,
            "stdout": "",
            "stderr": "command unavailable",
        }
    if required and result.returncode:
        raise RuntimeError(f"environment command failed: {args[0]}")
    return {
        "command": list(args),
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def read_text(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def docker_manifest():
    info_result = command("docker", "info", "--format", "{{json .}}")
    info = json.loads(info_result["stdout"])
    if info.get("OSType") != "linux":
        raise RuntimeError("native Linux Docker runtime required")
    return {
        "docker_info": {
            "server_version": info.get("ServerVersion"),
            "storage_driver": info.get("Driver"),
            "cgroup_driver": info.get("CgroupDriver"),
            "cgroup_version": info.get("CgroupVersion"),
            "kernel_version": info.get("KernelVersion"),
            "operating_system": info.get("OperatingSystem"),
            "os_type": info.get("OSType"),
            "architecture": info.get("Architecture"),
            "security_options": info.get("SecurityOptions"),
            "available_runtimes": sorted((info.get("Runtimes") or {}).keys()),
            "default_runtime": info.get("DefaultRuntime"),
        },
        "docker_version": json.loads(command(
            "docker", "version", "--format", "{{json .}}"
        )["stdout"]),
        "containerd_version": command("containerd", "--version", required=False),
        "runc_version": command("runc", "--version", required=False),
    }


def podman_manifest():
    info = json.loads(command("podman", "info", "--format", "json")["stdout"])
    security = info["host"]["security"]
    if security.get("rootless") is not True:
        raise RuntimeError("rootless Podman runtime required")
    if info["host"].get("serviceIsRemote", False):
        raise RuntimeError("local Podman runtime required")
    return {
        "podman_info": {
            "arch": info["host"].get("arch"),
            "cgroup_manager": info["host"].get("cgroupManager"),
            "cgroup_version": info["host"].get("cgroupVersion"),
            "network_backend": info["host"].get("networkBackend"),
            "rootless": security.get("rootless"),
            "service_is_remote": info["host"].get("serviceIsRemote", False),
            "security": security,
            "oci_runtime": info["host"].get("ociRuntime"),
        },
        "podman_version": json.loads(command(
            "podman", "version", "--format", "json"
        )["stdout"]),
        "rootless_uid_map": command(
            "podman", "unshare", "cat", "/proc/self/uid_map"
        )["stdout"],
        "rootless_gid_map": command(
            "podman", "unshare", "cat", "/proc/self/gid_map"
        )["stdout"],
        "oci_runtime_version": command("crun", "--version", required=False),
    }


def wasmtime_manifest(executable, module):
    executable = Path(executable).resolve(strict=True)
    module = Path(module).resolve(strict=True)
    if not executable.is_file() or not module.is_file():
        raise RuntimeError("Wasmtime executable and module must be files")
    if module.read_bytes()[:4] != b"\0asm":
        raise RuntimeError("Wasmtime module is not WebAssembly")
    return {
        "wasmtime_version": command(str(executable), "--version"),
        "wasmtime_sha256": sha256(executable),
        "module_sha256": sha256(module),
        "module_size": module.stat().st_size,
        "guest_target": "wasm32-wasip1",
        "guest_environment_inherited": False,
        "guest_network_inherited": False,
    }


def native_linux_manifest(launcher, worker, cgroup_root):
    launcher = Path(launcher).resolve(strict=True)
    worker = Path(worker).resolve(strict=True)
    cgroup_root = Path(cgroup_root).resolve(strict=True)
    return {
        "launcher_sha256": sha256(launcher),
        "worker_sha256": sha256(worker),
        "cgroup_root": str(cgroup_root),
        "cgroup_controllers": read_text(cgroup_root / "cgroup.controllers"),
        "cgroup_subtree_control": read_text(cgroup_root / "cgroup.subtree_control"),
        "user_namespace_limit": read_text("/proc/sys/user/max_user_namespaces"),
        "unprivileged_user_namespaces": read_text(
            "/proc/sys/kernel/unprivileged_userns_clone"
        ),
        "isolation_controls": [
            "user/mount/pid/ipc/uts/network namespaces", "Landlock ABI >= 6",
            "seccomp filter", "no_new_privs", "zero capability sets",
            "cgroup v2 cpu/memory/pids", "closed inherited descriptors",
            "supervisor-owned process group",
        ],
    }


def native_windows_manifest(worker):
    worker = Path(worker).resolve(strict=True)
    return {
        "worker_sha256": sha256(worker),
        "isolation_controls": [
            "zero-capability AppContainer", "restricted primary token",
            "low-integrity token", "explicit filesystem ACL",
            "isolated profile storage", "explicit inherited handle list",
            "Job Object active-process/memory limits", "kill-on-job-close",
            "exact PID and creation-time verification",
        ],
    }


def kubernetes_manifest(namespace, probe_image):
    namespace_info = json.loads(command(
        "kubectl", "get", f"namespace/{namespace}", "-o", "json"
    )["stdout"])
    policy = json.loads(command(
        "kubectl", "--namespace", namespace, "get",
        "networkpolicy/gov-substrate-default-deny", "-o", "json"
    )["stdout"])
    nodes = json.loads(command("kubectl", "get", "nodes", "-o", "json")["stdout"])
    calico = json.loads(command(
        "kubectl", "--namespace", "kube-system", "get", "pods",
        "--selector", "k8s-app=calico-node", "-o", "json"
    )["stdout"])
    return {
        "kubectl_version": json.loads(command(
            "kubectl", "version", "-o", "json"
        )["stdout"]),
        "current_context": command(
            "kubectl", "config", "current-context"
        )["stdout"],
        "namespace": namespace,
        "namespace_labels": namespace_info.get("metadata", {}).get("labels", {}),
        "default_deny_policy": policy.get("spec", {}),
        "probe_image": probe_image,
        "nodes": [{
            "name": node.get("metadata", {}).get("name"),
            "kubelet_version": node.get("status", {}).get("nodeInfo", {}).get(
                "kubeletVersion"
            ),
            "container_runtime": node.get("status", {}).get("nodeInfo", {}).get(
                "containerRuntimeVersion"
            ),
            "kernel_version": node.get("status", {}).get("nodeInfo", {}).get(
                "kernelVersion"
            ),
            "os_image": node.get("status", {}).get("nodeInfo", {}).get("osImage"),
        } for node in nodes.get("items", [])],
        "calico_nodes": [{
            "name": pod.get("metadata", {}).get("name"),
            "node": pod.get("spec", {}).get("nodeName"),
            "images": [
                container.get("image")
                for container in pod.get("spec", {}).get("containers", [])
            ],
            "image_ids": [
                container.get("imageID")
                for container in pod.get("status", {}).get("containerStatuses", [])
            ],
            "phase": pod.get("status", {}).get("phase"),
        } for pod in calico.get("items", [])],
    }


def openshell_manifest(cli, gateway, policy, probe_image):
    policy = Path(policy).resolve(strict=True)
    gateway_info = json.loads(command(
        cli, "--gateway", gateway, "--color", "never",
        "gateway", "info", "--output", "json",
    )["stdout"])
    image = json.loads(command(
        "docker", "image", "inspect", probe_image
    )["stdout"])[0]
    return {
        "openshell_version": command(cli, "--version")["stdout"],
        "gateway": gateway_info,
        "compute_driver": "docker",
        "policy_sha256": sha256(policy),
        "policy_path": policy.name,
        "probe_image": probe_image,
        "probe_image_id": image.get("Id"),
        "sandbox_configuration": {
            "one_sandbox_per_generation": True,
            "providers_attached": [],
            "automatic_providers": False,
            "filesystem_default": "deny",
            "network_default": "deny",
            "process_uid": 65534,
            "process_gid": 65534,
            "landlock": "hard_requirement",
        },
        **docker_manifest(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=(
        "docker", "podman", "gvisor", "wasmtime", "native-linux",
        "native-windows", "kubernetes", "openshell",
    ),
                        required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wasmtime-bin")
    parser.add_argument("--wasmtime-module")
    parser.add_argument("--native-launcher")
    parser.add_argument("--native-worker")
    parser.add_argument("--cgroup-root")
    parser.add_argument("--kube-namespace")
    parser.add_argument("--probe-image")
    parser.add_argument("--openshell-cli", default="openshell")
    parser.add_argument("--openshell-gateway")
    parser.add_argument("--openshell-policy")
    args = parser.parse_args()

    if args.backend == "podman":
        backend = podman_manifest()
    elif args.backend == "wasmtime":
        if not args.wasmtime_bin or not args.wasmtime_module:
            raise RuntimeError("Wasmtime evidence requires executable and module")
        backend = wasmtime_manifest(args.wasmtime_bin, args.wasmtime_module)
    elif args.backend == "native-linux":
        if not args.native_launcher or not args.native_worker or not args.cgroup_root:
            raise RuntimeError("native Linux evidence requires launcher, worker, and cgroup root")
        backend = native_linux_manifest(
            args.native_launcher, args.native_worker, args.cgroup_root
        )
    elif args.backend == "native-windows":
        if not args.native_worker:
            raise RuntimeError("native Windows evidence requires worker")
        backend = native_windows_manifest(args.native_worker)
    elif args.backend == "kubernetes":
        if not args.kube_namespace or not args.probe_image:
            raise RuntimeError(
                "Kubernetes evidence requires namespace and probe image"
            )
        backend = kubernetes_manifest(args.kube_namespace, args.probe_image)
    elif args.backend == "openshell":
        if not args.openshell_gateway or not args.openshell_policy or not args.probe_image:
            raise RuntimeError(
                "OpenShell evidence requires gateway, policy, and probe image"
            )
        backend = openshell_manifest(
            args.openshell_cli, args.openshell_gateway,
            args.openshell_policy, args.probe_image,
        )
    else:
        backend = docker_manifest()
    if args.backend == "gvisor":
        if "runsc" not in backend["docker_info"]["available_runtimes"]:
            raise RuntimeError("runsc is not registered with Docker")
        backend["runsc_version"] = command("runsc", "--version")

    manifest = {
        "schema": 1,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": os.environ.get("GITHUB_SHA") or command(
            "git", "rev-parse", "HEAD"
        )["stdout"],
        "runner_image": {
            "name": os.environ.get("ImageOS"),
            "version": os.environ.get("ImageVersion"),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "os_release": read_text("/etc/os-release"),
            "cgroup_controllers": read_text("/sys/fs/cgroup/cgroup.controllers"),
            "apparmor_enabled": read_text("/sys/module/apparmor/parameters/enabled"),
            "apparmor_version": command(
                "apparmor_parser", "--version", required=False
            ),
            "libseccomp_version": command(
                "dpkg-query", "-W", "-f=${Version}", "libseccomp2",
                required=False,
            ),
            "process_status": {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in (read_text("/proc/self/status") or "").splitlines()
                if line.startswith(("NoNewPrivs:", "Seccomp:", "Seccomp_filters:"))
            },
        },
        "backend": args.backend,
        "runtime": backend,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)


if __name__ == "__main__":
    main()
