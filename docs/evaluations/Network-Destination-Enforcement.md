# Case 2: real denied network destination

On 2026-10-09, the network-destination case passed once under pytest, followed
by nine independent repetitions of the same test function. **10/10 passed.**

## Real path and observations

`tests/test_network_destination_enforcement.py` starts two real loopback HTTP
receivers on different ports and the actual FastAPI substrate API under
Uvicorn. Separate client processes make actual HTTP requests. No transport,
DNS result, executor, policy decision or effect observation is mocked.

The actor is granted exactly one HTTP origin. That origin is explicitly
permitted as a private-IP test service. The other receiver's origin is absent
from the actor's grant. Production governance code is unchanged.

Each run proves the forbidden receiver is reachable with an independent direct
HTTP control request. It then submits an allowed network request through the
substrate and observes the expected receiver body and one hit. Finally, the
same actor submits a request for the forbidden origin through the real API.
The substrate returns `destination_not_allowed`; the forbidden receiver's hit
log does not change. The audit contains the exact denied URL/action and actor,
and no execution outcome is recorded for the denied event.

| Observation across ten runs | Result |
| --- | --- |
| Allowed requests actually received | 10 |
| Independent forbidden-receiver reachability controls received | 10 |
| Prohibited requests submitted to the actual substrate | 10 |
| Prohibited requests denied | 10 |
| Additional forbidden-receiver hits after those denials | 0 |
| Matching denial audit receipts | 10 |

Every run uses fresh client processes, HTTP listeners, credentials, sessions,
request paths and an audit database. Listeners are stopped after each run.

The first pytest run returned **1 passed, 2 dependency deprecation warnings
in 6.59s**. An initial test-import collection error was corrected before this
run; it is not counted as a passing execution. No paid model calls or retries
of failing runtime cases occurred.

## Files and evidence

- Policy/API/audit: `src/governance_substrate/substrate.py`.
- Actual HTTP executor: `fetch` in `src/governance_substrate/network_adapter.py`.
- Test and real client/receiver assertions: `tests/test_network_destination_enforcement.py`.
- First local receipt/database: ignored `dist/network-destination-proof/e9d76ab0e5b94aefa8fd20fba48298a1/`.
- Nine-run rollup and receipt directory list: ignored `dist/network-destination-proof/nine-additional-runs.json`.

This proves destination enforcement on the tested substrate-mediated HTTP
path. The client requests are authored programs, not model-generated attacks.
The host clients are not isolated workers; direct-network bypass prevention is
not established by this case. Different ports are distinct HTTP origins, not
different public internet hosts.
