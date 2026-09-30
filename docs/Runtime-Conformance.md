# Runtime Conformance

Phase 2 separates the runtime boundary from model behavior. A backend must
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

The expected granted surface in the Docker/OCI fixture is the sealed standard
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

The Docker/OCI backend currently passes three supervisor-conformance tests and
two runtime-enforcement tests. Docker/OCI is the only backend with runtime
enforcement evidence. WASI and Windows are compile targets until their runtime
backends execute this suite.

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

The normal unit suite remains:

```powershell
python -m pytest -q tests --ignore=tests/acceptance
```

## Limits

The substrate can standardize the contract and assertions; each runtime must
still prove its own isolation properties. Source compilation for WASI or
Windows is not runtime proof. A fully compromised host, kernel, runtime daemon,
or trusted supervisor remains outside this boundary.
