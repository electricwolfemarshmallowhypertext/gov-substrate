# Governance Substrate v0.6.0

Governance Substrate has a working reference implementation whose tested runtime boundary enforced capabilities independently of model behavior across local and hosted models.

## Changes since v0.5.0

- **Backend-neutral conformance:** a shared supervisor contract and purpose-built Rust hostile probe separate supervisor behavior, real runtime enforcement, and model integration. The same probe source was exercised under Docker/containerd, rootless Podman/crun, gVisor/runsc, Wasmtime/WASI, NVIDIA OpenShell, native Linux, native Windows, Kind/Calico, and GKE Autopilot in recorded configurations.
- **Additional runtime supervisors:** Podman, Wasmtime, OpenShell, native Linux, native Windows, and Kubernetes implementations use the existing substrate boundary and the common conformance assertions. Docker/OCI remains the reference backend.
- **Incident-derived evaluation:** deterministic and real isolated-worker tests exercise delegated proxying, authorization scope, side channels, persistence, redirects, and exfiltration paths against local fixtures.
- **Compromised-adapter controls:** the provider gateway binds a one-use dispatch credential to a sealed request, checks circuit revocation before dispatch, and signs the completion identity. Request-bound operator approval, independent audit witnessing, and anomaly containment have separate tests.
- **Task-scoped authority:** short-lived parent and child task identities bind sessions and execution grants to named actors and action families. Named grants govern shared communication channels.
- **Automatic containment and shutdown evidence:** repeated denials can trigger scoped circuit trips. Audit receipts identify the trigger, affected authority, timing, exact worker, and whether shutdown was verified. Real Docker tests include force-kill of an uncooperative worker and orphan reconciliation.
- **Reference harness inventory and CI:** machine-readable worker capabilities are checked against API routes and real Docker inspection and probes. CI keeps unit, runtime conformance, enforcement, and Qwen model-integration evidence distinct.

## Verification and scope

The [Phase 10 evidence freeze](Evidence-Freeze-2026-10-05.md) identifies its tested commit, runtime manifests, negative results, and artifact hashes. Later controls were verified separately: [CI run 37487547840](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37487547840) passed 141 unit tests with 10 opt-in skips, four real Qwen Docker acceptance tests, and five real Docker environment probes. The local real Docker supervisor suite passed two tests, including forced shutdown and orphan recovery.

Results apply to the named tests and recorded configurations. Unit tests with fakes do not count as runtime proof. The substrate cannot attest to hidden hosted-provider behavior or secure a fully compromised trusted host or kernel. The manuscript is a separate publication artifact and is not part of this software archive.
