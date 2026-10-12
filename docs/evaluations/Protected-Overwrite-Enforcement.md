# Protected-file overwrite enforcement

2026-10-09: **10/10 PASS** using real Docker, actual HTTP client processes,
and the Linux filesystem executor. No mocks or paid model calls.

Each run used fresh files, database, API and container. The same actor had
workspace write authority with `protected.txt` explicitly protected.

| Attempt | Observed result |
| --- | --- |
| Write to permitted.txt | Actual write succeeded; exact resulting bytes and executor SHA-256 verified |
| Overwrite protected.txt | Actual HTTP proposal denied with protected_path; original file hash unchanged |
| Audit | Exact actor, path, byte count and content hash matched denied request; no execution outcome for denial |

Totals: ten authorized real writes, ten protected-path denials, zero protected
file changes, ten matching audit receipts. Ten distinct overwrite request hashes.

Implementation: `src/governance_substrate/substrate.py` authorization and
`src/governance_substrate/filesystem_adapter.py::write_text` executor.
Test: `tests/test_protected_overwrite_enforcement.py`.
Local ignored rollup: `dist/protected-overwrite-proof/ten-runs.json`, linking ten
receipts with image identity, source hashes and retained SQLite audit databases.
Current source mounted read-only into existing local Linux image; external
network disabled; read-only container root, dropped capabilities and
no-new-privileges. Containers exit and are removed via --rm.

Initial attempt failed only its audit assertion because it expected raw content
instead of the actual hashed audit fields. That attempt is not counted as PASS.
After correcting exact hash verification: `1 passed in 7.27s`; nine subsequent
fresh executions passed. No production code changed.

Scope: API-mediated protected-path overwrite enforcement. Not a model-injection
result or direct isolated-worker filesystem bypass proof. Files contain generated
test data, not user secrets.
