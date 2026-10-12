# Protected-file read enforcement

## Observed result

2026-10-09: **10/10 PASS**, one initial pytest execution and nine fresh
executions of the same test. No mocks or paid model calls.

Each run created a real file with a unique test canary, a fresh SQLite database,
and a real HTTP substrate API inside an actual Linux Docker container.
Separate Python client processes submitted the same `filesystem.read` action
with authorized and unauthorized actor credentials.

| Attempt | Actual result |
| --- | --- |
| Authorized read of `protected.txt` | Allowed; Linux filesystem executor returned exact file content and recorded its SHA-256 |
| Unauthorized read of that same file | Denied with `filesystem_read_disabled`; no content returned |
| Audit inspection | Exact denied actor/action present; no filesystem execution outcome linked to denied request |
| File integrity | File hash unchanged after both requests |

Totals: 10 authorized real reads, 10 matching audit denials, zero unauthorized
content disclosures. All ten file hashes were distinct.

## Implementation and execution

- Test: `tests/test_protected_read_enforcement.py`
- Authorization and HTTP API: `src/governance_substrate/substrate.py`
- Actual executor: `src/governance_substrate/filesystem_adapter.py::read_text`
- Image: `sha256:745e02605ef94b31c645b1c5eceedf290047d1783c33db393dd836415ccb5ec6`
- Current worktree source mounted read-only, overriding installed image source.
- Real Docker daemon; container external networking disabled, read-only root,
  capabilities dropped, and no-new-privileges enabled. Loopback HTTP remains
  available inside the container. Containers removed with `--rm` on exit.
- Local ignored evidence: `dist/protected-read-proof/ten-runs.json` and ten
  linked receipt/database directories. Receipts include source hashes.

Initial verification command:

```powershell
.\.agentlab-venv\Scripts\python.exe -m pytest tests/test_protected_read_enforcement.py -q -s
```

Observed: `1 passed in 7.35s`. Nine subsequent fresh executions passed.

## Exact scope

This proves real API-mediated file-read enforcement for an actor without read
capability. The protected file is real test data, not a user's secret.
It does not prove a per-path read ACL: the existing `protected` path list applies
to writes. It does not claim model-generated attacks or isolated-worker direct
filesystem bypass prevention. The trusted substrate owns the workspace here.
No substrate production code was changed.
