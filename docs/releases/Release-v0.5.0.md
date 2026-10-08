# Governance Substrate v0.5.0

Governance Substrate has a working reference implementation whose tested runtime boundary enforced capabilities independently of model behavior across local and hosted models.

## Major changes since v0.4.0

- **One-use execution grants:** cryptographically random grants bind an admitted action to its actor, session, governed inputs, policy version, intended capability or provider, and expiration. Execution rejects altered, mismatched, expired, or replayed grants and audits issuance and use.
- **Operator circuit breaker:** authorized operators can stop actions globally or by actor, capability, or provider. The substrate checks the breaker before authorization and execution, invalidates affected grants and sessions, blocks provider calls, and records trigger and reset events.
- **Verified runtime-supervisor shutdown:** the runtime-neutral supervisor interface now requires termination and verification for substrate-controlled workers. Docker/OCI remains the reference backend.
- **Orphan-worker reconciliation:** the Docker supervisor discovers and removes managed workers that outlive substrate process state.
- **Real Docker acceptance suite:** end-to-end tests exercise the real substrate, Docker daemon, isolated worker, local inference, governed output, circuit-breaker shutdown, late-completion rejection, orphan reconciliation, and network-scope enforcement.
- **Environment-skeleton isolation probes:** real containers attempt forbidden network, filesystem, socket, process, environment, IPC, persistence, and proxy paths while also verifying explicitly granted capabilities.
- **Qwen and Phi local-model matrix:** official Qwen3 0.6B and Microsoft Phi-4 Mini artifacts run through the same worker API and isolation boundary. Model artifacts are pinned and hash-verified.
- **Direct Gemini validation:** a bounded direct Google API replay verified denial before provider transfer, inherited private classification with publication denial, and clean public generation with successful publication.
- **OpenRouter validation:** bounded replays with GLM 5.2, Grok 4.7, and Kimi K3 used pinned upstream providers with fallback disabled and recorded the router as an additional trust boundary.
- **Expanded CI coverage:** separate jobs distinguish policy/control unit tests from real Qwen Docker acceptance and environment probes; the larger Phi acceptance leg is available as a manual workflow.

## Scope of the evidence

The release combines deterministic policy tests, real Docker/runtime enforcement, two local model families, direct hosted-provider validation, and routed hosted-provider validation. Hosted API runs are recorded evaluation evidence and are not repeated in CI.

The evidence applies to the documented reference configuration and tested scenarios. It does not establish universal confinement, attest to hosted providers' internal runtimes, or prove every possible runtime backend. Docker/OCI is the current reference backend; the substrate interfaces remain runtime-neutral.
