# NVIDIA OpenShell Runtime Evaluation

## Question

Can NVIDIA OpenShell implement the shared runtime-supervisor contract while Governance Substrate remains authoritative over authorization, provenance, classification, publication, and audit?

## Reference configuration

The evaluation pins NVIDIA OpenShell `v0.1.2` from NVIDIA's official GitHub release and verifies the Debian package SHA-256 before installation. The authoritative run uses the OpenShell Docker driver on an Ubuntu 24.04 GitHub-hosted runner.

Each generation receives one OpenShell sandbox. The supervisor binds the complete generation identifier and owner to sandbox labels, supplies sealed context over standard input, disables automatic providers, and applies a default-deny policy with:

- no network policy grants;
- read-only system paths;
- private writable `/tmp` and `/dev/shm` paths;
- Landlock as a hard requirement;
- UID and GID `65534`;
- an empty worker environment except `PATH` and `HOME`.

The gateway requires an authenticated operator connection and a gateway launch token. The worker receives neither gateway credentials nor a control path.

## Lifecycle binding

The runtime supervisor records the exact OpenShell sandbox identifier for each complete generation identifier. A circuit trip deletes that exact sandbox, waits until OpenShell reports it absent, and rejects a late completion through the existing substrate claim lifecycle. Supervisor restart reconciliation selects only sandboxes carrying the substrate owner and managed labels.

OpenShell supplies runtime isolation. Governance Substrate continues to decide grants, object provenance, classification, publication, declassification, circuit state, and audit events.

## Evidence boundary

The backend uses the unchanged runtime conformance suite:

| Evidence category | Real checks |
|---|---|
| Supervisor conformance | sealed governed input/output, one-use claim, circuit-trip termination, late-completion rejection, orphan reconciliation |
| Runtime enforcement | direct attempts against forbidden network, filesystem, process, IPC, socket, secret, and persistence paths; explicitly granted paths remain usable |

The suite also reads `/proc/self/status` inside the real sandbox and requires UID `65534`, `NoNewPrivs=1`, seccomp filtering, and zero inheritable, permitted, effective, bounding, and ambient Linux capabilities.

The CI run records the OpenShell version, Docker driver, policy hash, hostile-probe image identity, host, and sandbox configuration as an uploaded evidence artifact.

## Negative environment result retained

A native OpenShell gateway under WSL2 reached Docker and created the sandbox, but the sandbox supervisor could not establish its callback to the gateway across the WSL2 and Docker Desktop network boundary. The worker never executed, so that attempt is retained as an environment compatibility failure and is not counted as enforcement evidence.

The authoritative Phase 5 result comes from the native Linux CI topology where the OpenShell gateway and Docker daemon share the supported host environment.

## Scope

This evaluation covers OpenShell `v0.1.2`, its Docker compute driver, the checked-in policy, and the shared hostile probe on Ubuntu 24.04. It does not establish results for OpenShell's Kubernetes driver, other host platforms, arbitrary policy files, or future OpenShell releases.
