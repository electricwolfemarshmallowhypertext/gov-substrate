# Ungranted shared-channel write enforcement

2026-10-09: **10/10 PASS**. Actual HTTP API, real SQLite commits and a separate
observer actor. No mocks, paid calls or model-generated attacks.

Each fresh run gave the writer access only to `granted`; the observer could read
both `granted` and `forbidden`. The same write request was submitted for each channel.

| Attempt | Observed effect |
| --- | --- |
| Granted write | Committed row contained exact value; observer read it through the API |
| Forbidden write | shared_channel_disabled denial; independent SQLite connection saw no state change |
| Observer read of forbidden key | Authorized observer found no value |
| Audit | Exact denied actor, action, channel, key and value matched |

Totals: ten authorized committed writes, zero ungranted state changes, ten audit
denials. This tests actual shared-state storage, not external message delivery or
worker filesystem isolation.

Test: `tests/test_shared_channel_enforcement.py`.
HTTP helper: `tests/real_enforcement_support.py` starts real Uvicorn and urllib HTTP.
Implementation/executor: `src/governance_substrate/substrate.py` shared-channel
policy and SQLite state INSERT/UPDATE. Every API server stopped after the run.
Ignored evidence: `dist/shared-channel-proof/ten-runs.json` links ten receipts and
retained SQLite databases. Initial pytest: `1 passed, 2 warnings in 5.32s`;
nine fresh repetitions passed. Warnings were existing websockets deprecations.
No production code changed.
