"""OS-level attempts run through the reference worker's Docker settings."""

import base64
import json
import os
import socket
import sys
import time
from pathlib import Path


config = json.loads(base64.b64decode(sys.argv[1], validate=True))
rows = []


def attempt(name, operation):
    try:
        result = operation()
    except OSError as exc:
        rows.append({"attempt": name, "allowed": False,
                     "result": f"{type(exc).__name__}:errno={exc.errno}"})
    else:
        rows.append({"attempt": name, "allowed": True, "result": str(result)[:160]})


def connect(address, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(address)
    return "TCP connect succeeded"


def unix_connect(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(path)
    return "Unix socket connect succeeded"


def list_path(path):
    return f"listed {path}: {os.listdir(path)[:4]}"


def read_file(path):
    with open(path, "rb") as source:
        return f"read {len(source.read(4))} bytes"


def open_model_for_write():
    descriptor = os.open("/model/model.gguf", os.O_WRONLY | os.O_APPEND)
    os.close(descriptor)
    return "write descriptor opened (no bytes written)"


def create_on_model_mount():
    path = Path("/model/probe-new")
    path.touch(exist_ok=False)
    path.unlink()
    return "created and removed a file on the model mount"


def environment_names(data):
    names = {item.split(b"=", 1)[0].decode("utf-8", "replace")
             for item in data.split(b"\0") if item}
    allowed = {"PATH", "HOME", "PYTHONDONTWRITEBYTECODE", "OMP_NUM_THREADS",
               "OPENBLAS_NUM_THREADS", "LC_CTYPE"}
    leaked = sorted(names - allowed)
    return leaked


if config["mode"] == "scan":
    target = config["target_ip"]
    gateway = config["gateway_ip"]
    attempt("direct_ipv4", lambda: connect((target, 8002)))
    attempt("direct_ipv6", lambda: connect(("2606:4700:4700::1111", 443), socket.AF_INET6))
    attempt("dns_public", lambda: len(socket.getaddrinfo("example.com", 443)))
    attempt("dns_other_container", lambda: len(socket.getaddrinfo("environment-target", 8002)))
    attempt("docker_gateway", lambda: connect((gateway, 80)))
    attempt("host_docker_internal", lambda: socket.create_connection(
        ("host.docker.internal", 80), timeout=2).close() or "TCP connect succeeded")
    attempt("cloud_metadata_ipv4", lambda: connect(("169.254.169.254", 80)))
    attempt("cloud_metadata_ipv6", lambda: connect(("fd00:ec2::254", 80), socket.AF_INET6))
    attempt("other_container", lambda: connect((target, 8002)))
    for port in (80, 2375, 8000, 8001, 8002, 8080):
        attempt(f"loopback_ipv4:{port}",
                lambda port=port: connect(("127.0.0.1", port)))
    attempt("loopback_ipv6", lambda: connect(("::1", 8002), socket.AF_INET6))

    for path in ("/var/run/docker.sock", "/run/docker.sock",
                 "/run/containerd/containerd.sock", "/ipc/substrate.sock",
                 "/tmp/agent.sock"):
        attempt(f"unix_socket:{path}", lambda path=path: unix_connect(path))
    for path in ("/workspace", "/ipc", "/run/secrets", "/host", "/mnt/c",
                 "/mnt/e", "/run/desktop/mnt/host"):
        attempt(f"unexpected_mount:{path}", lambda path=path: list_path(path))
    marker = config["host_marker"]
    for path in (f"/workspace/{marker}", f"/host/{marker}",
                 f"/mnt/e/gov-substrate/{marker}",
                 f"/run/desktop/mnt/host/e/gov-substrate/{marker}"):
        attempt(f"host_or_workspace_file:{path}", lambda path=path: read_file(path))

    attempt("model_read", lambda: read_file("/model/model.gguf"))
    attempt("model_write_descriptor", open_model_for_write)
    attempt("model_mount_directory_write", create_on_model_mount)
    leaked = environment_names(b"\0".join(
        f"{name}={value}".encode() for name, value in os.environ.items()))
    rows.append({"attempt": "environment_secrets", "allowed": bool(leaked),
                 "result": f"unexpected_names={leaked}"})
    for name, path in (("proc_self_environ", "/proc/self/environ"),
                       ("proc_pid1_environ", "/proc/1/environ")):
        leaked = environment_names(Path(path).read_bytes())
        rows.append({"attempt": name, "allowed": bool(leaked),
                     "result": f"unexpected_names={leaked}"})
    attempt("unrelated_host_pid", lambda: read_file(f"/proc/{config['host_pid']}/status"))
    visible_pids = sorted(int(item) for item in os.listdir("/proc") if item.isdecimal())
    rows.append({"attempt": "unrelated_processes", "allowed":
                 any(pid != os.getpid() for pid in visible_pids),
                 "result": f"container_pids={visible_pids};self={os.getpid()}"})
    rows.append({"attempt": "ipc_namespace", "allowed": True,
                 "result": os.readlink("/proc/self/ns/ipc")})
    rows.append({"attempt": "mount_namespace", "allowed": True,
                 "result": os.readlink("/proc/self/ns/mnt")})

    tmp_marker = Path("/tmp") / config["marker"]
    tmp_marker.write_text("private tmp", encoding="utf-8")
    rows.append({"attempt": "private_tmp", "allowed":
                 tmp_marker.read_text(encoding="utf-8") == "private tmp",
                 "result": "write/read in container tmpfs"})
    shm_marker = Path("/dev/shm") / config["marker"]
    shm_marker.write_text("private shm", encoding="utf-8")
    rows.append({"attempt": "private_shm", "allowed":
                 shm_marker.read_text(encoding="utf-8") == "private shm",
                 "result": "write/read in container IPC namespace"})

elif config["mode"] in ("write_markers", "hold_markers"):
    for path in (Path("/tmp") / config["marker"], Path("/dev/shm") / config["marker"]):
        path.write_text("first worker", encoding="utf-8")
        rows.append({"attempt": f"write_private:{path.parent}", "allowed":
                     path.read_text(encoding="utf-8") == "first worker",
                     "result": "first worker wrote and read marker"})
    rows.append({"attempt": "ipc_namespace", "allowed": True,
                 "result": os.readlink("/proc/self/ns/ipc")})
    if config["mode"] == "hold_markers":
        listeners = []
        for parent in ("/tmp", "/dev/shm"):
            address = f"{parent}/{config['marker']}.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(address)
            listener.listen(1)
            listeners.append(listener)
            rows.append({"attempt": f"listen_private:{parent}", "allowed": True,
                         "result": "Unix listener bound"})
        print(json.dumps(rows), flush=True)
        time.sleep(60)
        sys.exit(0)
elif config["mode"] == "read_markers":
    for path in (Path("/tmp") / config["marker"], Path("/dev/shm") / config["marker"]):
        attempt(f"previous_worker:{path.parent}", lambda path=path: read_file(path))
        attempt(f"previous_socket:{path.parent}",
                lambda path=path: unix_connect(str(path) + ".sock"))
    rows.append({"attempt": "ipc_namespace", "allowed": True,
                 "result": os.readlink("/proc/self/ns/ipc")})
else:
    raise ValueError("unknown probe mode")

print(json.dumps(rows))
