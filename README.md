# Governance Substrate

**Governance beneath the agent, not inside the prompt.**

Governance Substrate puts enforceable capability boundaries beneath AI agents. It decides what an agent may reach, change, retain, or publish, then records both the decision and the execution result.

> **Technical architecture:** [Substrate Reference Architecture](docs/Substrate-Reference-Architecture.md)

Current release: [Governance Substrate v0.5.0](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/releases/tag/v0.5.0)

## Demonstrated result

> Governance as Substrate has a working reference implementation whose tested runtime boundary enforced capabilities independently of model behavior across local and hosted models.

In the tested reference configuration:

- agents could not directly reach the network or governed workspace;
- state, file, network, publication, and provider-transfer requests passed through the substrate;
- one-use execution grants bound authorization to the exact actor, session, action, inputs, policy, and capability;
- an operator circuit breaker revoked authority and stopped supervised workers;
- each tested runtime supervisor verified stopped workers and reconciled orphaned workers after restart;
- classified model output inherited the highest classification of its sealed governed inputs;
- private generated output could not be published, while clean public output could be published.

## How it works

`agent → substrate authorization → one-use grant → execution → verified outcome → audit`

The circuit breaker is checked before authorization and again before execution. Agent intent does not create authority.

## Implemented boundaries

- **State:** governed transitions, session and persistent state, integrity checks, and audited one-shot overrides.
- **Network:** destination-scoped requests through an audited adapter; the reference agent container has no direct network route.
- **Filesystem:** actor-, session-, and shared-file authority through an audited adapter; the reference agent has no workspace mount.
- **Delegated services:** services that can proxy, store, forward, or invoke downstream resources fail closed unless their downstream authority is mediated.
- **Data egress:** external publication accepts governed public objects rather than arbitrary agent-supplied bytes.
- **Object provenance:** transforms and generated text retain exact parents and inherit the highest input classification. Lowering classification requires an audited operator action.
- **Hosted transfer:** external model providers are denied by default and must be registered for the classifications they may receive.
- **Execution control:** one-use grants, scoped emergency stops, verified worker shutdown, and orphan reconciliation.
- **Compromised-adapter controls:** exact provider request identities, short-lived gateway credentials, request-bound operator approval, signed completion receipts, independent audit witnessing, and anomaly-triggered containment.

Generation is model- and provider-agnostic. The optional local worker and the OpenAI, Anthropic, Gemini, and OpenRouter adapters use the same sealed-input and governed-output path.

## Evidence

The project reports six kinds of evidence separately:

- **Unit tests** verify policy and control logic. Fakes and mocks are allowed here; these tests do not prove runtime isolation.
- **Runtime conformance** uses real workers to verify the backend-neutral supervisor contract: launch, exact identity, verified stop, late-completion rejection, and orphan reconciliation.
- **Runtime enforcement** uses a model-independent hostile Rust worker to make real OS and runtime attempts against forbidden and granted paths.
- **Model integration** uses real Qwen inference through the same sealed-input and governed-output path, separately from the hostile-worker proof.
- **Hosted validation** verifies the governed request and output path with external providers. It does not attest to a provider's internal runtime.
- **Incident-derived acceptance** replays documented proxy, authorization, side-channel, persistence, redirect, and exfiltration failure classes against local services and isolated workers.
- **Compromised-host/provider evaluation** separates detectable adapter or provider contradictions from behavior that remains outside the observable boundary.

[Runtime conformance](docs/Runtime-Conformance.md) defines the shared contract and evidence rules. Native Ubuntu Docker/containerd, rootless Podman/crun, gVisor/runsc, Wasmtime/WASI, NVIDIA OpenShell, native Linux, native Windows, Kind/Calico, and GKE Autopilot use the same real suite. Docker/OCI remains the reference backend. Each result comes from the hostile probe running in the named backend rather than from configuration inspection alone.

Current `main` runtime evidence:

- native Ubuntu Docker/containerd: **3 conformance + 2 runtime-enforcement tests passed**;
- rootless Podman/crun with the Docker daemon unavailable: **3 + 2 passed**;
- gVisor `runsc` release `release-20260921.0`: **3 + 2 passed**;
- Wasmtime 49.0.1 on Windows 11 and Ubuntu 24.04.5: **3 + 2 passed** on each host;
- NVIDIA OpenShell v0.1.2 with its Docker driver on Ubuntu 24.04: **3 + 2 passed**;
- native Linux namespaces, Landlock, seccomp, capabilities, and cgroup v2: **3 + 2 passed**;
- native Windows AppContainer, low integrity, zero capabilities, and Job Object supervision: **3 + 2 passed**;
- Kubernetes 1.36.4 with Calico 3.32.2, restricted Pod Security, and default-deny ingress and egress: **3 + 2 passed** in a disposable Kind cluster;
- GKE Autopilot 1.35.8 with restricted Pod Security and default-deny ingress and egress: **3 + 2 passed** in a disposable managed cluster;
- [Phase 3 OCI CI and runtime manifests](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36727109512);
- [Phase 4 Wasmtime/WASI CI and runtime manifest](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36736013718);
- [Phase 5 NVIDIA OpenShell CI and runtime manifest](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37021722123);
- [Phase 6 native Linux and Windows CI and runtime manifests](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36756130136);
- [Phase 7 Kubernetes/Calico CI and runtime manifest](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36761111887).

Release verification for v0.5.0:

- unit suite: **91 passed, 10 opt-in skips**;
- real Qwen Docker acceptance: **4 passed**;
- the same real-runtime acceptance with Phi-4 Mini: **4 passed**;
- environment isolation probes: **5 passed**;
- [release CI](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36651807299): unit, Qwen acceptance, and environment jobs passed;
- [manual model-matrix CI](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36617457396): Qwen and Phi acceptance passed.

Local model evidence uses pinned, hash-verified official Qwen and Microsoft Phi artifacts through the same Docker worker. Hosted reports cover GPT-6 Luna, GPT-6 Sol, Claude Opus 4.7, direct Gemini Flash, and OpenRouter with pinned GLM, Grok, and Kimi upstreams. Future model runs should answer a new boundary question rather than add model names.

## Evaluation reports

- [Runtime conformance](docs/Runtime-Conformance.md)
- [NVIDIA OpenShell runtime evaluation](docs/OpenShell-Runtime-Evaluation.md)
- [Kubernetes runtime evaluation](docs/Kubernetes-Runtime-Evaluation.md)
- [Native operating-system runtime evaluation](docs/Native-OS-Runtime-Evaluation.md)
- [Wasmtime/WASI runtime evaluation](docs/Wasmtime-Runtime-Evaluation.md)
- [Environment skeleton](docs/Environment-Skeleton-Evaluation.md)
- [Local-model runtime matrix](docs/Local-Model-Matrix-Evaluation.md)
- [Incident-derived escape evaluation](docs/Incident-Derived-Escape-Evaluation.md)
- [Compromised host/provider evaluation](docs/Compromised-Host-Provider-Evaluation.md)
- [Free-form output provenance](docs/Free-Form-Output-Provenance.md)
- [Generation adapters](docs/Generation-Adapters.md)
- [Hosted OpenAI validation](docs/Hosted-Object-Validation.md)
- [Claude Opus 4.7 validation](docs/Anthropic-Opus-4.7-Validation-Report.md)
- [Direct Gemini validation](docs/Gemini-Direct-Validation.md)
- [OpenRouter GLM validation](docs/OpenRouter-Validation.md)
- [OpenRouter Grok validation](docs/OpenRouter-Grok-4.7-Validation.md)
- [OpenRouter Kimi validation](docs/OpenRouter-Kimi-K3-Validation.md)

Earlier evaluations document the failures that motivated scoped authority, persistence lifetimes, delegated-service handling, sensitive-data egress, and object provenance:

- [Containment evaluation](docs/Containment-Evaluation.md)
- [Scoped-authority evaluation](docs/Scoped-Authority-Evaluation.md)
- [Sensitive-data egress evaluation](docs/Sensitive-Data-Egress-Evaluation.md)
- [Object-provenance evaluation](docs/Object-Provenance-Evaluation.md)

## Research

**Governance as Substrate: Engineering Patterns for Resilient Collective Systems — V2, September 2026 Revision**

- [Research paper DOI](https://doi.org/10.5281/zenodo.23002435)
- [v0.5.0 release notes](docs/Release-v0.5.0.md)

## Scope

The evidence applies to the documented reference configuration and tested scenarios. It does not establish universal AI confinement or prove every runtime backend.

The substrate controls capabilities placed behind its boundary. It cannot secure an agent given an alternate unmediated route, attest to hidden behavior inside a hosted provider, or defend itself from a fully compromised trusted host or kernel. Docker/OCI is the reference backend. Rootless Podman, gVisor, Wasmtime/WASI, NVIDIA OpenShell, native Linux, native Windows, disposable Kind/Calico, and disposable GKE Autopilot configurations have separate real conformance evidence; untested backends require the same proof before equivalent claims are made.

## License

The software source code is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`). Copyright © 2026 Antiparty Inc.

Organizations that want to incorporate Governance Substrate into proprietary products or services without AGPL obligations may request a separate commercial license from [smith@antiparty.co](mailto:smith@antiparty.co). The Governance Substrate name, associated branding, trademarks, research papers, and prose documentation are not licensed under the software license unless expressly stated.
