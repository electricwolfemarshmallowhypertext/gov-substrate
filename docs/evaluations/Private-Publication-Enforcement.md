# Private-object publication enforcement

2026-10-09: **10/10 PASS**. Real HTTP substrate API, independent client
processes, actual network executor and live HTTP receiver. No mocks or paid calls.

Each fresh run imported one public and one private text object through the trusted
substrate import path. Both were accessible to the same actor; publication to the
same receiver was granted. The local receiver origin was explicitly allowed as a
private-IP test endpoint, with external publication classification policy.

| Attempt | Observed result |
| --- | --- |
| Public object.publish | Real network_adapter.fetch executed; receiver got exact public payload |
| Private object.publish | Denied: object_classification_blocks_egress; no additional receiver delivery |
| Audit | Exact actor, object ID and destination hash matched; no private publication execution result |

Ten public deliveries, zero private deliveries, ten matching audit denials.
Test: `tests/test_private_publication_enforcement.py`.
Implementation/executor: `src/governance_substrate/substrate.py` object publication
policy and execution, `src/governance_substrate/network_adapter.py::fetch`.
Ignored receipts and SQLite audit databases:
`dist/private-publication-proof/ten-runs.json` links all ten fresh runs.

Initial test failed an audit assertion that expected a raw destination instead of
the existing hashed destination field. Not counted as PASS. Corrected exact hash
assertion passed: `1 passed, 2 warnings in 6.35s`; nine fresh repetitions passed.
The two warnings were websockets deprecations. No production code changed.

Scope: real mediated publication enforcement. Not a model-injection result or
isolated-worker network-bypass proof. Test canaries are generated data, not secrets.
Both API and receiver were stopped after every run.
