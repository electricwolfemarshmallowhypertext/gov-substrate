# Runtime Conformance

Phases 2 through 4 separate the runtime boundary from model behavior. A backend must
implement the same supervisor contract and pass the same real assertions before
the project describes it as conformant.

## Evidence classes

| Class | What it establishes | What does not count |
| --- | --- | --- |
| Conformance | A real backend implements launch, exact identity, verified stop, late-completion rejection, and restart reconciliation. | Mock engines and fake stop results. |
| Runtime enforcement | A real hostile worker attempts forbidden OS and runtime paths and records the observed result. | Reading configuration without making the attempt. |
| Model integration | A real model receives sealed governed context and returns output through the governed-object path. | Deterministic text fixtures or fake provider clients. |

Unit tests remain useful for policy and control logic. They do not count as
runtime evidence.

## Reusable backend contract

`runtime_conformance.RuntimeConformanceBackend` supplies runtime-specific
control to shared assertions:

- expose a `RuntimeSupervisor`;
- create a fresh supervisor against the same deployment;
- identify the exact worker bound to a generation;
- launch a deliberately orphaned worker;
- verify that a runtime identity no longer exists;
- provide a real network target that is reachable outside the worker; and
- remove only resources created by that test backend.

The substrate API remains runtime-neutral. The shared tests call the same
`run`, `stop`, and `reconcile` supervisor operations regardless of backend.

## Fixed hostile worker

`runtime-probe/` contains one dependency-free Rust program. The same source is
compiled for Linux, Windows, and `wasm32-wasip1`. Compilation demonstrates
source portability; it does not establish enforcement on a backend that has not
run the real suite.

The probe is model-independent. It accepts only the sealed input envelope on
standard input, rejects prompt/history/messages/tools fields, and obtains its
test configuration from a governed input object. In scan mode it makes real
attempts against:

- IPv4, IPv6, DNS, bridge, host, metadata, loopback, and another container;
- Docker, containerd, substrate, and ungranted Unix sockets;
- workspace, host, secret, IPC, and model paths;
- its process environment and `/proc` environments;
- host and unrelated process IDs;
- prior-worker files in `/tmp` and `/dev/shm`; and
- fresh private temporary and shared-memory storage.

The expected granted surface in each tested OCI fixture is the sealed standard
input plus private `/tmp` and `/dev/shm` storage. The fixture has no network and
no bind mounts. Each attempt returns:

`attempt -> allowed/blocked -> actual OS result`

The suite fails if any forbidden path succeeds or any granted path fails.

## Shared real tests

The conformance assertions prove:

1. a real untrusted worker launches;
2. only sealed governed context enters it;
3. its output becomes a governed object;
4. output classification and ordered parents match the sealed inputs;
5. altered and replayed grants are rejected;
6. a circuit trip targets the exact running worker;
7. runtime termination and removal are verified;
8. a stopped worker cannot submit a late completion;
9. a restarted supervisor finds and removes a labeled orphan;
10. forbidden network, filesystem, process, IPC, socket, secret, and persistence paths fail under real OS calls; and
11. explicitly granted input and private temporary storage remain usable.

## Phase 3 OCI matrix

The same Linux probe image and the same five assertions ran in each row. No
backend-specific assertion was removed. Each job uploaded a sanitized manifest
recording the source commit, runner image, kernel, cgroups, seccomp/AppArmor
state, engine, and OCI runtime versions.

| Backend | Recorded environment | Conformance | Runtime enforcement |
| --- | --- | ---: | ---: |
| Native Docker/containerd | Ubuntu 24.04.5, Linux 6.17 Azure kernel, Docker 28.0.4, containerd 2.3.5, runc 1.5.1, cgroup v2, AppArmor and seccomp | 3 passed | 2 passed |
| Rootless Podman | Ubuntu 24.04.5, Linux 6.17 Azure kernel, Podman 4.9.3, crun 1.14.1, rootless user namespace, cgroup v2, seccomp; Docker daemon unavailable | 3 passed | 2 passed |
| gVisor | Same native Ubuntu Docker host with the worker explicitly assigned to `runsc` release `release-20260921.0` | 3 passed | 2 passed |

The [Phase 3 CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36727109512)
contains the completed jobs and downloadable environment manifests. Docker/OCI
remains the reference deployment. Podman and gVisor are additional conformant
OCI environments under the recorded configurations.

## Phase 4 Wasmtime/WASI backend

`WasmtimeRuntimeSupervisor` executes the `wasm32-wasip1` hostile probe in a
fresh Wasmtime process and instance for every generation. The guest inherits no
environment or network. The only preopens are fresh per-run `/tmp` and
`/dev/shm` directories. The backend sets fuel, wall-clock, memory, table,
instance, host-call, resource, and random-byte limits. It supplies no guest
arguments after the module path and exposes no model, workspace, host, or other
resource directory.

The supervisor binds each generation to the Wasmtime PID and operating-system
process creation identity. Trusted metadata contains the generation, project,
module hash, PID, creation identity, and combined runtime identity. A circuit
trip terminates that exact process and verifies it is no longer active. A fresh
supervisor reads the same metadata, rejects altered records, and terminates
orphaned instances before the substrate starts.

Local pre-push verification used official Wasmtime 49.0.1 on Windows 11 and the
same Rust 1.90 `wasm32-wasip1` probe: **3 conformance and 2 runtime-enforcement
tests passed**. The Linux CI job downloads the pinned official Wasmtime archive,
verifies SHA-256, rebuilds the same probe, runs the same five assertions, and
uploads a sanitized environment manifest. See the
[Wasmtime/WASI runtime evaluation](Wasmtime-Runtime-Evaluation.md).

## Separate model proof

Model integration is not a prerequisite for the hostile-worker suite. The
separate inference check uses only the pinned official
`Qwen/Qwen3-0.6B-GGUF` `Qwen3-0.6B-Q8_0.gguf` artifact. It verifies that real
inference uses the same sealed input and governed output path. Phi is retained
as historical model-diversity evidence from v0.5.0 and is not part of this
runtime-diversity phase.

## Commands

```powershell
$env:RUN_ACCEPTANCE_TESTS = '1'

# Supervisor behavior against real workers.
python -m pytest -q tests/acceptance/conformance -m conformance

# Real OS/runtime attempts from the hostile worker.
python -m pytest -q tests/acceptance/conformance -m runtime_enforcement

# Separate real-model check; requires the pinned Qwen file.
$env:GENERATION_MODEL_BLOB = 'C:\path\to\Qwen3-0.6B-Q8_0.gguf'
python -m pytest -q tests/acceptance/test_local_runtime.py -m model_integration
```

CI selects an additional backend with `RUNTIME_CONFORMANCE_BACKEND=podman` or
`RUNTIME_CONFORMANCE_BACKEND=gvisor`. Wasmtime uses
`RUNTIME_CONFORMANCE_BACKEND=wasmtime` with pinned `WASMTIME_BIN` and
`WASMTIME_MODULE` paths. Podman must be local and rootless. The
Podman job proves the Docker daemon is unavailable. The gVisor job installs a
pinned official release, verifies its archive SHA-256, registers `runsc` with
Docker, and verifies each worker's assigned runtime through Docker inspect.

The normal unit suite remains:

```powershell
python -m pytest -q tests --ignore=tests/acceptance
```

## Limits

The substrate can standardize the contract and assertions; each runtime must
still prove its own isolation properties. Wasmtime does not implement Linux
process namespaces or Unix-domain sockets, so those probe rows are explicitly
recorded as unsupported rather than presented as OS attempts. Network, DNS,
filesystem, environment, lifecycle, and fresh-storage checks execute against
the real WASI guest. A fully compromised host, kernel, runtime engine, or trusted
supervisor remains outside this boundary.
