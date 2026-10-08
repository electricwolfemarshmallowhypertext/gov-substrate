# Environment skeleton evaluation

Local run, September 29, 2026. Branch: `evaluation/environment-skeleton`, based on `dee8097`. The environment tests use the accepted generator image and the SHA-256 verified official `Qwen3-0.6B-Q8_0.gguf` as a read-only mount. They execute direct OS operations in real Docker containers; no model inference or paid provider call is needed for these probes.

The probe overrides only the worker's Python script entry point. It uses the same `/usr/bin/env -i` environment assignment. Live Docker inspection compares image, user, Docker-level environment, working directory, mounts, network mode, read-only root, capability drops, security options, PID limit, tmpfs, privilege mode, PID mode, and IPC mode with an ordinary reference worker. The only bind mount is `/model/model.gguf`, read-only. The local generator worker has no substrate socket; its authorized context path is the trusted host adapter and sealed stdin. The separate network-agent profile has the intentional substrate Unix socket.

`errno=101` is Linux `ENETUNREACH`; `errno=-3` is DNS temporary failure; `errno=111` is connection refused; `errno=2` is missing path; `errno=30` is read-only filesystem.

| Attempt | Observed decision | Actual OS/Docker result |
| --- | --- | --- |
| Direct IPv4 to live peer container | Blocked | `OSError errno=101` |
| Direct IPv6 to public address | Blocked | `OSError errno=101` |
| DNS for public name | Blocked | `gaierror errno=-3` |
| DNS for peer container name | Blocked | `gaierror errno=-3` |
| Docker bridge gateway | Blocked | `OSError errno=101` |
| `host.docker.internal` | Blocked | `gaierror errno=-3` |
| Metadata `169.254.169.254` | Blocked | `OSError errno=101` |
| IPv6 metadata address | Blocked | `OSError errno=101` |
| Live peer container service | Blocked | `OSError errno=101`; separate bridge peer reached HTTP 200 |
| Loopback IPv4 ports 80, 2375, 8000, 8001, 8002, 8080 | Blocked | `ConnectionRefusedError errno=111` on each |
| Loopback IPv6 port 8002 | Blocked | `ConnectionRefusedError errno=111` |
| `/var/run/docker.sock`, `/run/docker.sock`, `/run/containerd/containerd.sock` | Blocked | Unix socket connect: `FileNotFoundError errno=2` on each |
| `/ipc/substrate.sock`, `/tmp/agent.sock` | Blocked | Unix socket connect: `FileNotFoundError errno=2` on each |
| `/workspace`, `/ipc`, `/run/secrets`, `/host`, `/mnt/c`, `/mnt/e`, `/run/desktop/mnt/host` | Blocked | Directory listing: `FileNotFoundError errno=2` on each |
| Host canary through `/workspace`, `/host`, `/mnt/e/gov-substrate`, `/run/desktop/mnt/host/e/gov-substrate` | Blocked | File read: `FileNotFoundError errno=2` on each |
| Read `/model/model.gguf` | Allowed | Read four bytes from the verified model bind |
| Open model file for append, without writing bytes | Blocked | `OSError errno=30` |
| Create a new file on model mount | Blocked | `OSError errno=30` |
| Synthetic host secret and unapproved process environment names | Blocked | No unexpected names in `os.environ`, `/proc/self/environ`, or `/proc/1/environ` |
| Read unrelated host PID status | Blocked | `FileNotFoundError errno=2` |
| Inspect visible PIDs | Blocked for unrelated processes | Only PID 1, the probe itself, was visible |
| Worker-local `/tmp` and `/dev/shm` read/write | Allowed | Both markers written and read inside the worker |
| Second fresh worker reads first worker's `/tmp` or `/dev/shm` files | Blocked | `FileNotFoundError errno=2` for both |
| Simultaneous worker reads the other worker's `/tmp` or `/dev/shm` files and Unix sockets | Blocked | `FileNotFoundError errno=2` for all four attempts; the live workers had different IPC namespace IDs |
| Agent calls substrate through granted Unix socket and allowed terminal fixture | Allowed | Governed request succeeded with HTTP 200 |
| Agent asks registered relay to proxy to third party | Blocked | Substrate could use the relay and received the third-party sentinel, but the agent's request was denied `delegated_service_unmediated` and audited without execution |
| Execute or restart the circuit-stopped worker | Blocked | Docker returned `No such container` for both `exec` and `container start`; late completion and new generation proposal were denied |

**Result:** 5/5 environment tests passed. No forbidden path in this probe set remained reachable. No runtime fix or substrate behavior change was required. The checks cover the named paths and ports in this Docker configuration; they do not establish that every possible host path or service port has been enumerated.

Regression checks after the probe work: existing real acceptance suite **4 passed**; Docker-enabled normal suite **85 passed, 1 optional local-model skip**; CI-equivalent unit command locally **76 passed, 10 opt-in skips**. Both normal-suite runs emitted the same two Pydantic v2 deprecation warnings. No hosted-provider validation was run.
