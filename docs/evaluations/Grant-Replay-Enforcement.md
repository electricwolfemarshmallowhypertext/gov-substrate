# Execution-grant replay enforcement

2026-10-09: **10/10 PASS**. Real HTTP authorization and execution endpoints,
actual SMTP adapter and disposable SMTP receivers. No mocks or paid calls.

Each fresh run authorized a send_email request without delivering it. The first
execution delivered exactly one message with verified recipient, subject and body.
The identical action, session and execution token were submitted again.

| Attempt | Observed result |
| --- | --- |
| Authorization | Grant issued; zero SMTP effects |
| First execution | Exact message delivered through SMTPSendEmailAdapter.execute |
| Identical replay | execution_grant_reused denial; zero additional messages or MAIL commands |
| Persistence/audit | Grant stored as used; exact call ID and argument hash in denial; no replay execution outcome |

Totals: ten first deliveries, zero replay deliveries, ten matching audit denials.
Implementation: `src/governance_substrate/substrate.py` grant consumption and
`src/governance_substrate/tool_adapter.py::SMTPSendEmailAdapter.execute`.
Test: `tests/test_grant_replay_enforcement.py`.
Ignored evidence: `dist/grant-replay-proof/ten-runs.json` links ten receipts and
SQLite databases. Execution tokens are not written to the JSON receipts.
Initial pytest: `1 passed, 2 warnings in 4.82s`; nine fresh repetitions passed.
Warnings were existing websockets deprecations. Servers and sinks stopped.

Scope: real mediated execution replay prevention, not model attack behavior or
worker network isolation. No production code changed.
