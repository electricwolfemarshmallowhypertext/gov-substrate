# Evidence Freeze — 2026-10-05

This is the canonical evidence index for Governance Substrate through Phase 10.
It freezes the tested implementation, environment records, structured results,
negative results, and SHA-256 digests without expanding the model matrix.

## Frozen identity

- Freeze tag: [`evidence-2026-10-05`](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/tree/evidence-2026-10-05)
- Runtime-tested commit: [`1d46d46`](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/commit/1d46d46d735e107b72ea4fa68e5ba560749ba7d1)
- Successful CI run: [`37375053106`](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37375053106)
- Machine-readable ledger: [`manifest.json`](evidence-freeze-2026-10-05/manifest.json)
- Preserved CI job and step outcomes: [`ci-run-37375053106.json`](evidence-freeze-2026-10-05/ci-run-37375053106.json)
- Preserved negative results: [`negative-results.json`](evidence-freeze-2026-10-05/negative-results.json)

The freeze commit adds evidence records and verification only. The runtime code
under test is commit `1d46d46`. `scripts/verify_evidence_freeze.py` verifies all
committed artifact hashes and evidence references. After publication, the same
script with `--require-tag` verifies that the annotated freeze tag points to the
freeze commit and contains the tested commit in its history.

## Outcome vocabulary

- **Held:** the stated boundary and its intended allowed path both behaved as specified.
- **Denied:** the substrate or runtime blocked the attempted action before the claimed consequence.
- **Detected:** the substrate identified a contradiction, mutation, replay, or integrity failure and failed closed.
- **Outside boundary:** the observation is not evidence for or against the claimed substrate control.

These labels describe only the named tests in the recorded environments.

## Claim ledger

| Claim | Outcome | Code and tests | Environment and raw result | Remaining boundary |
| --- | --- | --- | --- | --- |
| Managed state and audit integrity | **Detected** | [`substrate.py`](../../src/governance_substrate/substrate.py), [`audit_witness.py`](../../src/governance_substrate/audit_witness.py), [`test_substrate.py`](../../tests/test_substrate.py), [real witness test](../../tests/acceptance/phase9/test_gateway_boundary.py) | [Docker manifest](evidence-freeze-2026-10-05/environments/docker.json), [CI result](evidence-freeze-2026-10-05/ci-run-37375053106.json) | Local-only mode trusts its host; high-assurance mode requires an independent witness. |
| Network, filesystem, process, IPC, socket, secret, persistence, and shared-resource boundaries | **Denied** | [`network_adapter.py`](../../src/governance_substrate/network_adapter.py), [`filesystem_adapter.py`](../../src/governance_substrate/filesystem_adapter.py), [environment probes](../../tests/acceptance/environment/test_environment.py), [incident acceptance](../../tests/acceptance/incidents/test_incident_escape.py) | [Docker manifest](evidence-freeze-2026-10-05/environments/docker.json), [incident raw result](results/incident-derived-docker.json), [CI job](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37375053106/job/111981482508) | Only the enumerated paths and recorded configuration were tested. |
| One-use grants, circuit revocation, and verified shutdown | **Denied** | [`substrate.py`](../../src/governance_substrate/substrate.py), [`runtime_supervisor.py`](../../src/governance_substrate/runtime_supervisor.py), [grant tests](../../tests/test_execution_grants_circuit.py), [real force-kill test](../../tests/test_docker_runtime_integration.py), [real gateway revocation test](../../tests/acceptance/phase9/test_gateway_boundary.py) | [Docker manifest](evidence-freeze-2026-10-05/environments/docker.json), [native Docker CI job](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37375053106/job/111981482498) | Calls already admitted at the provider-dispatch boundary are in flight and cannot be recalled. |
| Backend-neutral runtime conformance and hostile-worker enforcement | **Held** | [`runtime_supervisor.py`](../../src/governance_substrate/runtime_supervisor.py), [hostile Rust probe](../../tests/probes/runtime-probe/src/main.rs), [supervisor contract](../../tests/acceptance/conformance/test_supervisor_contract.py), [runtime enforcement](../../tests/acceptance/conformance/test_runtime_enforcement.py) | [Eight frozen manifests](evidence-freeze-2026-10-05/environments), [CI result](evidence-freeze-2026-10-05/ci-run-37375053106.json) | Each result applies to its recorded backend version, host, and configuration. |
| Managed Kubernetes conformance | **Held** | [`kubernetes_runtime_supervisor.py`](../../src/governance_substrate/kubernetes_runtime_supervisor.py), shared conformance and enforcement tests above | [GKE manifest and raw result](results/kubernetes-managed-gke.json), [Kind manifest](evidence-freeze-2026-10-05/environments/kubernetes.json) | The managed result applies to the recorded disposable GKE Autopilot cluster. |
| Local-model governed generation | **Held** | [`generation_adapter.py`](../../src/governance_substrate/generation_adapter.py), [`local_generation_worker.py`](../../src/governance_substrate/local_generation_worker.py), [real local runtime](../../tests/acceptance/test_local_runtime.py), [network scope](../../tests/acceptance/test_network_scope.py) | [Docker manifest](evidence-freeze-2026-10-05/environments/docker.json), [local-model results](results/local-models.json), [Qwen CI job](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/37375053106/job/111981482479) | This validates integration and enforcement, not model safety. |
| Hosted-model governed generation | **Held** | [`generation_adapter.py`](../../src/governance_substrate/generation_adapter.py), [hosted adapter tests](../../tests/test_hosted_generation_adapters.py), [Gemini tests](../../tests/test_gemini_direct_smoke.py), [OpenRouter tests](../../tests/test_openrouter_direct_smoke.py) | [Hosted boundary manifest](evidence-freeze-2026-10-05/environments/hosted-validations.json), [OpenAI Luna](results/object-hosted-luna.json), [OpenAI Sol](results/object-hosted-sol.json), [Anthropic](results/object-hosted-opus-47-scope-only.json), [Gemini](results/gemini-direct.json), [GLM](results/openrouter-glm-5.2.json), [Grok](results/openrouter-grok-4.7.json), [Kimi](results/openrouter-kimi-k3.json) | The substrate cannot attest to provider internals. |
| Adapter, provider, completion, replay, and audit contradictions | **Detected** | [`provider_gateway.py`](../../src/governance_substrate/provider_gateway.py), [`audit_witness.py`](../../src/governance_substrate/audit_witness.py), [compromise tests](../../tests/test_compromised_host_provider.py), [real gateway test](../../tests/acceptance/phase9/test_gateway_boundary.py) | [Docker manifest](evidence-freeze-2026-10-05/environments/docker.json), [hosted boundary manifest](evidence-freeze-2026-10-05/environments/hosted-validations.json), [CI result](evidence-freeze-2026-10-05/ci-run-37375053106.json) | Hidden provider behavior with no observable contradiction remains outside the boundary. |
| Fully compromised trusted host or opaque provider internals | **Outside boundary** | [reference architecture](../Substrate-Reference-Architecture.md), [compromised-host/provider evaluation](../evaluations/Compromised-Host-Provider-Evaluation.md) | [Hosted boundary manifest](evidence-freeze-2026-10-05/environments/hosted-validations.json), [negative-results ledger](evidence-freeze-2026-10-05/negative-results.json) | Requires an independent host, hardware or provider attestation, or another control plane. |

## Runtime manifests and artifact identity

All eight CI runtime manifests were emitted by run `37375053106` from tested
commit `1d46d46` and copied into the repository before their Actions artifacts
expire. The machine ledger records each committed file's SHA-256 and its GitHub
artifact ID. The managed GKE and hosted-validation records have separate stated
provenance because they did not run in that CI topology.

| Runtime | Frozen manifest | GitHub artifact ID |
| --- | --- | ---: |
| Docker/containerd | [`docker.json`](evidence-freeze-2026-10-05/environments/docker.json) | `11371676463` |
| Rootless Podman/crun | [`podman.json`](evidence-freeze-2026-10-05/environments/podman.json) | `11371696425` |
| gVisor/runsc | [`gvisor.json`](evidence-freeze-2026-10-05/environments/gvisor.json) | `11371900525` |
| Wasmtime/WASI | [`wasmtime.json`](evidence-freeze-2026-10-05/environments/wasmtime.json) | `11371380631` |
| NVIDIA OpenShell | [`openshell.json`](evidence-freeze-2026-10-05/environments/openshell.json) | `11371186790` |
| Native Linux | [`native-linux.json`](evidence-freeze-2026-10-05/environments/native-linux.json) | `11371630659` |
| Native Windows | [`native-windows.json`](evidence-freeze-2026-10-05/environments/native-windows.json) | `11371800553` |
| Kind/Calico | [`kubernetes.json`](evidence-freeze-2026-10-05/environments/kubernetes.json) | `11371292015` |

## Negative results

The freeze retains unsuccessful or non-evidentiary attempts rather than
silently converting them into passes. The machine-readable ledger records:

- OpenShell under WSL2: worker never executed; **outside boundary** for runtime enforcement.
- First GKE attempt: admission changed resources and exact validation failed closed; **denied**.
- Two Gemini HTTP 503 attempts: no output; provider availability **outside boundary**.
- OpenRouter 256-token truncation: non-normal completion rejected; **detected**.
- Expired OpenRouter key: no inference; credential/provider condition **outside boundary**.
- Initial unforced Opus scope case: evaluation assertion failed and was preserved; **detected**.
- Official Llama weights unavailable: validation did not run; upstream access **outside boundary**.
- Hidden provider behavior and a fully compromised trusted host remain **outside boundary**.

No negative result is counted as a successful governance or runtime assertion.
