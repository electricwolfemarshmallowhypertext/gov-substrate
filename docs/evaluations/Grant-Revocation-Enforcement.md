# Issued-grant circuit revocation enforcement

2026-10-09: **10/10 PASS**. Actual HTTP authorization/execution requests, real
operator circuit control, persisted grant/session revocation and live SMTP sinks.
No mocks or paid calls.

Every fresh run first delivered one exact control message through the real SMTP
adapter. A second send_email action was authorized but not executed. The trusted
operator then tripped the actor circuit through Substrate.set_circuit.

| Attempt/check | Observed result |
| --- | --- |
| Control grant execution | Exact message delivered |
| Second authorization | Grant issued without another SMTP effect |
| Actor circuit trip | Unused grant persisted as revoked; session inactive |
| Execute revoked grant/session | invalid_session denial; zero new SMTP messages or MAIL commands |
| New session | capability_unavailable denial |
| Audit | Exact denied call ID and argument hash matched; no execution result linked to denial |

Totals: ten control deliveries, ten revoked unused grants, zero post-trip SMTP
deliveries, ten matching audit denials.
Implementation: `src/governance_substrate/substrate.py` circuit revocation and
execution checks; executor `src/governance_substrate/tool_adapter.py::SMTPSendEmailAdapter.execute`.
Test: `tests/test_grant_revocation_enforcement.py`.
Ignored rollup/receipts/databases: `dist/grant-revocation-proof/ten-runs.json`.
Tokens are not written to JSON receipts. Servers and sinks stopped each run.

The initial test expected capability_unavailable at execution. Actual session
revocation produced invalid_session first. That assertion failure is not counted
as PASS. The corrected test additionally verifies the actual revoked grant and
inactive session in SQLite: `1 passed, 2 warnings in 7.15s`; nine fresh repetitions
passed. Warnings were existing websockets deprecations. Production code unchanged.

Scope: a grant issued before an actor trip cannot execute through the mediated
path. This is not worker shutdown evidence or a hosted credential-race experiment.
