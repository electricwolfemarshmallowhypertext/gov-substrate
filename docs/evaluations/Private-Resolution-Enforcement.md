# Case 3: allowed hostname resolving to a forbidden private address

On 2026-10-09, this case passed once under pytest and nine more times with
fresh resources. **10/10 passed.** No DNS function, network operation,
executor result or audit record was mocked. No paid model call was made.

## Actual path

The normal OS resolver resolved the public hostname `127.0.0.1.nip.io` to
`127.0.0.1`. A real HTTP receiver listened on that loopback address. An
independent client process fetched it through the hostname and received its
expected response, proving both resolution and receiver reachability worked.

The actor's network policy allowed that hostname's origin but did not grant
it a private-address exception. A separate literal-IP origin for the same
receiver had an explicit private-address grant, providing a successful
substrate-mediated control. Client processes submitted both requests through
the actual HTTP substrate API.

The hostname request passed origin authorization. The real HTTP executor
resolved it and failed with `resolved address not allowed` before opening a
TCP connection. The receiver observed no additional TCP connections or HTTP
requests. The audit recorded the allowed authorization and its linked failed
execution outcome with the exact URL and rejection detail.

This is **executor rejection after hostname authorization**, not a policy
decision of `deny`.

| Observed across ten fresh runs | Result |
| --- | --- |
| Real resolver returned forbidden loopback address | 10 |
| Direct hostname reachability controls succeeded | 10 |
| Explicitly granted private-address controls succeeded | 10 |
| Hostname requests rejected by the actual executor | 10 |
| Additional receiver TCP connections from rejected requests | 0 |
| Additional receiver HTTP requests from rejected requests | 0 |
| Matching linked audit outcome receipts | 10 |

Each repetition used fresh processes, HTTP listeners, tokens, sessions, request
paths and a substrate database. HTTP services were stopped after every run.

## Implementation and evidence

- Test: `tests/test_private_resolution_enforcement.py`.
- Actual IP validation and transport: `fetch` in `src/governance_substrate/network_adapter.py`.
- API, grants and outcome audit: `src/governance_substrate/substrate.py`.
- First run: **1 passed, 2 dependency deprecation warnings in 6.68s**.
- First local receipt/database: ignored `dist/private-resolution-proof/6c44d6692cfc4cc9914fe85a7b41ab3f/`.
- Nine-run rollup: ignored `dist/private-resolution-proof/nine-additional-runs.json`.

This proves real hostname-to-forbidden-loopback enforcement in the tested
mediated path. It does not establish DNS rebinding protection across changing
answers, every private/metadata address variant, model injection success or
isolated-worker bypass prevention. It uses the normal resolver, which may
cache DNS answers; no claim is made that each run contacted an authoritative
DNS server.
