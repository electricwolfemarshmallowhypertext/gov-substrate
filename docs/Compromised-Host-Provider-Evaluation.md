# Compromised host and provider evaluation

Phase 9 tests what the substrate can detect or prevent when a host adapter is
misconfigured or malicious, and what remains unknowable when a provider or
trusted host is compromised. No paid model or provider API is used.

## Controls added

### Exact hosted request identity

A strict provider registration seals the model, upstream, fallback setting,
data-collection setting, ZDR requirement, and retention declaration alongside
the ordered governed object IDs and hashes. The resulting request identity is
bound to the generation grant. Substituting any field is denied before a
provider call.

For providers marked `gateway_required`, the substrate issues a random,
HMAC-authenticated gateway credential bound to the actor, generation, provider,
request identity, nonce, and 120-second expiry. Only its SHA-256 digest is
stored. The external gateway verifies the credential and consumes it once. A
provider credential remains in the gateway and is absent from the worker.

Immediately before an upstream request, the gateway presents that credential
back to the substrate. The substrate rechecks the sealed request and circuit
state and atomically consumes a one-use dispatch authorization. A circuit trip
after claim but before dispatch therefore denies the gateway request before the
provider is contacted. Dispatch authorization defines the start of an in-flight
provider request; a call already dispatched cannot be recalled.

The gateway returns a signed receipt binding the generation, provider, exact
request identity, exact response hash, and gateway credential. The substrate
accepts the generated text only when every receipt field and signature matches.
Receipt replay, cross-generation use, altered response bytes, provider changes,
and circuit-revoked executions fail closed.

### Exact operator approval

A provider may declare `approval_required_at`. A transfer at or above that
classification is escalated before generation. The operator receives a
short-lived approval token bound to the actor, active session, exact normalized
request, ordered input manifest, provider, classification, and registry policy.
The token is one use and cannot authorize a changed or later request.

### Independent audit witness

The optional witness interface replicates every event head outside SQLite. The
reference client uses mutual TLS and verifies the independent head before each
state transition or audit read. A missing, rejecting, or divergent witness
makes the substrate fail closed. Local hash chaining and SQLite triggers remain;
the witness adds a separate trust boundary rather than replacing them.
`GOV_SUBSTRATE_HIGH_ASSURANCE=1` makes the witness a startup requirement. The
real acceptance test coherently changes managed state and recomputes the local
audit head; local consistency is preserved, but the independently stored head
diverges and the substrate fails closed.

### Automatic scoped containment

Optional monitoring records denied-action fingerprints. Repeated denials by one
actor trigger the actor circuit. The same denied resource fingerprint from
multiple actors triggers the relevant capability circuit. Circuit activation
uses the existing revocation, session shutdown, worker termination, and audit
path. Thresholds and the observation window are explicit registry policy.

## Evidence

| Attempt | Evidence | Result |
| --- | --- | --- |
| Add, remove, reorder, or replace governed inputs | Existing immutable object, manifest-hash, ordered-parent, and one-use grant tests | Denied or detected before completion |
| Substitute model, upstream, fallback, collection, ZDR, or retention policy | Phase 9 deterministic strict-profile test | Denied before a gateway call |
| Invent, alter, expire, reuse, or cross a gateway credential | Deterministic receipt tests plus real Docker gateway replay | Denied |
| Trip the provider circuit after claim but before gateway dispatch | Real Docker gateway/provider call counter | Denied before the upstream call; call count unchanged |
| Forge, alter, replay, or attach a completion to another generation | Signed receipt and response-hash tests | Denied |
| Send private data without exact operator review | Deterministic high-risk approval test | Escalated; only the exact approved request proceeds |
| Rewrite or fork the local audit without the witness | Deterministic divergence test | Audit and subsequent actions fail closed |
| Disable the independent witness | Real Docker mTLS witness test | Audit verification fails closed |
| Coherently rewrite local managed state and its audit head | Real Docker mTLS witness test | Independent head diverges; audit fails closed |
| Repeated denied resource probing | Deterministic monitor test | Actor circuit triggered |
| Same denied resource probed by multiple actors | Deterministic monitor test | Capability circuit triggered |
| Worker bypasses the provider gateway | Real Docker worker with `network_mode: none` | Direct gateway and provider connections failed |
| Gateway reaches the local provider | Real Docker mTLS gateway | Succeeded with the credential held only by the gateway |
| Package mirror proxies toward a Kubernetes target | Disposable Kind/Calico acceptance | The mirror-to-target path is exercised; the governed delegated request and direct worker path remain denied |

The Docker acceptance uses separate provider, mTLS gateway, independent mTLS
witness, and networkless worker containers. The Kubernetes acceptance uses an
intentionally proxy-capable package mirror, a restricted target Pod, a
default-deny namespace, explicit mirror-only network policy, no service-account
token mount, and the same hostile worker used by the runtime suite.

## Provider behavior classification

| Provider behavior | Classification |
| --- | --- |
| Wrong declared model, upstream, fallback, privacy, or retention metadata | **Detected** when it contradicts the sealed profile or returned metadata |
| Missing, malformed, oversized, tool-bearing, callback-bearing, or nonfinal response | **Rejected** by the provider adapter or gateway |
| Replayed response or response attached to another generation | **Rejected** by the one-use receipt binding |
| Semantically unrelated or cross-request text returned with otherwise valid signed metadata | **Contained, not identified:** inherited classification and publication rules remain; semantic origin cannot be attested locally |
| Hidden provider context, undisclosed retention, or internal model substitution not exposed in provider evidence | **Outside the observable boundary** without provider-supported remote attestation |
| Provider transport or service failure | **Execution failure**, distinct from a substrate authorization decision |

## Boundary

The separate gateway and witness reduce the worker host's trusted computing
base. They do not make a hostile kernel safe. A root-level compromise can alter
process memory, steal local mTLS client credentials, bypass host egress rules,
or forge observations before they leave the host. Stronger deployments must
place the substrate, gateway, credential store, and witness in separate security
domains and enforce agent-host egress outside that host.

The substrate proves what it authorized, what exact governed bytes and policy
it bound to a request, what response bytes the gateway signed, and what object
it stored. It does not claim to prove unobservable behavior inside an opaque
provider.
