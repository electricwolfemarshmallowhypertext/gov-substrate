# Uncooperative worker force-kill enforcement

2026-10-09: **10/10 PASS**. Ten distinct real Docker workers, authentic Docker
events, actual circuit/supervisor shutdown and HTTP late-completion requests.
No mocks, paid calls or model inference.

Each fresh run prepared and claimed governed input through the HTTP API, then
launched the worker with DockerRuntimeSupervisor.run. The worker consumed the
sealed input and wrote its exact hash into its private tmpfs. It ignored SIGTERM.

| Attempt/check | Actual result |
| --- | --- |
| Worker start/input | Real container running; exact sealed-context hash verified |
| Graceful termination resistance | /proc/1/status showed SIGTERM ignored; real TERM sent; worker remained running |
| Actor circuit trip | Production supervisor stopped the exact generation/container |
| Forced termination | Docker kill event signal 9 and die event exitCode 137 observed |
| Removal | Docker destroy event; name and immutable container ID no longer inspectable |
| Late completion | Actual HTTP completion request denied; matching audit; no successful completion |

Totals: ten SIGTERM-resistant workers, ten observed SIGKILL terminations, ten
verified removals, ten late-completion denials, zero accepted late outputs.
Shutdown receipts bind the actual container ID and confirm verified shutdown.
All ten container IDs were independently checked absent after the repetitions.

Test: `tests/test_force_kill_enforcement.py`.
Implementation/executor: `src/governance_substrate/docker_runtime_supervisor.py`
run/stop/_stop_one and `src/governance_substrate/substrate.py` circuit revocation
and completion acceptance. Docker stop's one-second grace period escalated to
SIGKILL through the real daemon; this does not claim the explicit container-kill
fallback branch ran. Retained Docker events prove signal 9.

Image: sha256:745e02605ef94b31c645b1c5eceedf290047d1783c33db393dd836415ccb5ec6.
Worker uses reference generation settings: UID/GID 65534, network none,
read-only root, all capabilities dropped, no-new-privileges, PID limit 32 and
private 4 MB tmpfs. Only the worker command is replaced with the uncooperative
probe. No model mount, credentials or host workspace supplied to the worker.
No model is required for process termination proof.

Initial pytest: `1 passed, 2 warnings in 10.85s`; nine fresh repetitions passed.
Warnings were existing websockets deprecations. No production code changed.
Ignored evidence: `dist/force-kill-proof/ten-runs.json` links ten receipts,
Docker event records, compose configurations and SQLite audit databases.
Scope: exact-worker forced termination/removal and revoked completion. Not a
model-intelligence test or proof of every runtime backend.
