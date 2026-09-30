# Wasmtime/WASI Runtime Evaluation

## Question

Can the backend-neutral Governance Substrate supervisor contract and hostile
runtime probe execute under WASI without changing the substrate API or weakening
the common lifecycle assertions?

## Runtime

- Wasmtime: official `v49.0.1` release
- Guest target: `wasm32-wasip1`
- Probe compiler: Rust `1.90.0`, locked dependency-free crate
- Supervisor: `WasmtimeRuntimeSupervisor`
- Local pre-push host: Windows 11, build `10.0.26200`, AMD64
- CI host: Ubuntu 24.04.5, Linux `6.17.0-1022-azure`, x86_64

The supervisor starts a fresh Wasmtime process and guest instance for every
generation. It disables the Wasmtime compilation cache, inherited environment,
inherited network, TCP, UDP, and name lookup. It grants only fresh private
directories at `/tmp` and `/dev/shm`. No model, workspace, host directory, or
other resource handle is exposed to the guest.

Execution is bounded by 500,000,000 fuel units, a 120-second Wasm deadline, 64
MiB linear memory, one instance, two memories, two tables, 256 WASI resources,
1,000,000 host-call fuel units, and 64 KiB per random-byte request. The trusted
host process also enforces a 130-second communication deadline.

## Exact identity and recovery

Each worker record binds:

- project and generation ID;
- module SHA-256;
- operating-system PID;
- operating-system process creation identity; and
- the combined runtime identity returned to the circuit audit.

Circuit shutdown verifies that exact PID/creation pair is active before
termination and verifies it is no longer active afterward. Restart
reconciliation reads the same trusted metadata and fails closed if any field,
identity, owner, or module hash is altered. Private run directories are removed
only after verified exit.

## Real results

The shared suite ran against real Wasmtime on the local Windows host without
relaxing its lifecycle or governance assertions:

- supervisor conformance: **3 passed**;
- runtime enforcement: **2 passed**;
- total: **5 passed**.

The suite proved sealed input and governed output, exact parent order and
classification, altered and replayed grant rejection, exact circuit shutdown,
late-completion denial, orphan reconciliation, blocked network and DNS calls,
blocked ungranted filesystem paths, an empty guest environment, and fresh
private storage across sequential workers.

The probe records Linux-only Unix sockets, `/proc`, PID visibility, and namespace
checks as `unsupported_by_target`. These rows are explicit limitations, not
runtime-enforcement passes. WASI network, DNS, filesystem, environment, and
storage attempts are real guest operations.

## CI evidence

The [completed Phase 4 CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36736013718)
passed the same **3 conformance + 2 runtime-enforcement tests** on Ubuntu 24.04.5.
The `runtime-conformance-wasmtime` job downloaded the official
`wasmtime-v49.0.1-x86_64-linux.tar.xz` asset and verified archive SHA-256
`c71f7e0d30a92e418f0d17db7c6d8f6664c1ad764340a1278678f4209deab534`.
It compiled the same probe with pinned Rust 1.90 and uploaded a sanitized
environment manifest recording:

- source commit `3499280165a62a4eaabd59ee0ce58886855d59f7`;
- Wasmtime `49.0.1` (`46c23a87d`);
- Ubuntu 24.04.5 on Linux `6.17.0-1022-azure`;
- runner image `ubuntu24` version `20260927.320.1`;
- guest module SHA-256 `473d70ad20e263c205d70ffd7c77ddd33d2b8f5c4aeff0d8a5b414432e53f0c1`;
- inherited guest environment and network both disabled.

## Limits

This evidence applies to the pinned Wasmtime configuration and tested hosts. It
does not establish a native Windows process sandbox, Linux namespace behavior
inside WASI, or model inference under Wasmtime. Model integration remains a
separate evidence class. A compromised host, Wasmtime binary, kernel, trusted
supervisor, or substrate remains outside this process-local boundary.
