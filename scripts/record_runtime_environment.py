"""Write a sanitized, machine-readable manifest for OCI runtime evidence."""

import argparse
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("docker", "podman", "gvisor"),
                        required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    backend = docker_manifest() if args.backend != "podman" else podman_manifest()
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
