# Native Operating-System Runtime Evaluation

## Result

Phase 6 adds native Linux and native Windows implementations of the existing
runtime-neutral supervisor contract. Both backends passed the same real-worker
suite at source commit `c3950beda4bba91c4af109d8029e4a08818642df`:

| Backend | Supervisor conformance | Runtime enforcement |
| --- | ---: | ---: |
| Native Linux | 3 passed | 2 passed |
| Native Windows | 3 passed | 2 passed |

The completed jobs and sanitized runtime manifests are in the
[Phase 6 CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36756130136).
The native jobs used the real GitHub-hosted Ubuntu 24.04 and Windows runners.
They did not use a mocked process manager, fake stop result, container engine,
or paid model API.

## Shared proof

The native backends use the same substrate, `RuntimeSupervisor` interface,
hostile Rust worker, and acceptance assertions as the existing runtime matrix.
The tests proved that each backend:

1. launched a real untrusted worker;
2. supplied only the sealed governed input envelope;
3. returned worker output as a governed object with exact parents and inherited classification;
4. rejected altered and replayed grants;
5. stopped the exact worker during a circuit trip and verified termination;
6. rejected a late completion from the stopped worker;
7. reconciled an orphan after supervisor restart;
8. blocked the probed network, host-file, process, socket, secret, and persistence paths; and
9. preserved sealed standard input and fresh private temporary storage.

These are model-independent runtime results. Phase 6 does not claim native
model inference; the hostile probe deliberately tests capability enforcement
without depending on model behavior.

## Native Linux boundary

The Linux backend combines:

- user, mount, network, PID, IPC, and UTS namespaces;
- a private `/proc` mount;
- fresh, size-limited `/tmp` and `/dev/shm` tmpfs mounts owned by the untrusted UID;
- Landlock filesystem, TCP/UDP, signal, and abstract Unix-socket restrictions;
- a seccomp filter for high-risk kernel interfaces;
- cleared inheritable, permitted, effective, bounding, and ambient capabilities;
- UID and GID 65534 after sandbox setup;
- delegated cgroup v2 CPU, memory, and process limits; and
- exact launcher and worker identities bound to kernel process start times.

The trusted launcher preopens the fixed worker executable and readiness record
before entering the user namespace. The worker cannot use either descriptor as
an ambient capability after startup. Circuit shutdown targets the recorded
process group and cgroup, waits for exit, and removes the generation state.
Restart reconciliation applies the same identity checks to recorded orphans.

## Native Windows boundary

The Windows backend combines:

- a fresh AppContainer profile for every generation;
- zero AppContainer capability SIDs and low integrity;
- an explicit inherited-handle list containing only standard input, output, and error pipes;
- a fresh private profile root with separate temporary and shared-memory directories;
- an explicit environment containing only required system and private-path values;
- a Job Object limited to one active process and 128 MiB process memory;
- kill-on-close and explicit Job Object termination; and
- exact runtime identity bound to PID and Windows process creation time.

The probe verified the AppContainer, zero-capability token, low-integrity token,
and Job Object from inside the real worker. Direct network attempts were denied,
host and Docker control paths were unavailable, and no prior worker's private
files appeared in the next worker.

## Defects exposed during real execution

The real runners exposed implementation defects that compile-only checks did
not reveal:

- Linux lost access to its readiness pathname after entering the user
  namespace. The trusted launcher now preopens the record before isolation.
- Linux orphan reconciliation initially counted exited zombie processes as
  live. Process identity now treats terminal zombie/dead states as exited.
- Linux private tmpfs roots were writable only by root. They are now created
  for the untrusted UID and GID.
- Windows initially inferred private storage from platform defaults. The
  supervisor now supplies explicit fresh private temporary and shared-memory
  paths through the allowlisted environment.

The tests were not weakened to accommodate these failures.

## Limits

This evidence applies to the recorded GitHub-hosted Ubuntu 24.04 and Windows
runner configurations. It does not prove all Linux kernels, Windows builds,
enterprise policies, or native launch contexts. The Linux launcher requires a
trusted root or equivalently delegated setup path and cgroup v2. The Windows
backend relies on AppContainer, token integrity, ACL, and Job Object behavior.
The trusted host, kernel, launcher/supervisor, and test runner remain inside the
trusted computing base. A compromised component in that base is outside this
boundary. A native macOS backend is not implemented.
