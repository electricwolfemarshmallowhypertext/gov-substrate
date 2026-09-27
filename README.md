# Governance Substrate Reference Architecture

A small reference implementation of the paper's distinction: policy declares what should happen; the substrate and execution boundary decide which **managed state transitions** become real. The source is *Governance as Substrate: Engineering Patterns for Resilient Collective Systems*, Tionne Smith, September 2026 revision. The PDF is intentionally excluded from this code repository because it is marked all rights reserved.

## Managed state boundary (Milestone 1)

Actors authenticate with bearer tokens from environment variables. The service issues one active session per actor. Every valid proposal reaches one SQLite transaction that checks the capability registry, verifies the previous audit chain and committed state, makes a decision, and appends an event. An admitted `state.write` and its audit event commit together. A denied or escalated proposal leaves managed state unchanged and still produces an event. An authenticated operator can apply an escalated persistent write once, with a reason and an audit link to the original proposal.

The state layer includes actor identity, explicit capabilities, session and persistent namespaces, prior events, and current health observations. The audit records actor, action, policy rule and registry digest, full managed state before and after, decision, timestamp, and override link. SQLite triggers reject ordinary updates and deletes of audit rows; a SHA-256 chain detects unauthorized changes to audit content. Direct changes to managed state are detected against the last admitted state snapshot on the next request.

Filesystem, shell, and external API execution adapters remain absent; proposals for them are logged and denied.

## Network capability boundary (Milestone 2)

`network.request` is a bounded HTTP GET capability. A policy must set `network.allowed: true` and list exact origins under `network.destinations`, such as `http://fixture:8000`. The gate logs its allow or deny decision before any outbound call. On allowance, the adapter pins the resolved IP for the connection, sends only a GET, does not follow redirects, limits the response to 64 KiB, and appends a second event with the execution outcome, origin, resolved IP, HTTP status, byte count, and body digest. A denied destination produces no outbound call.

The Docker lab runs the **agent** as an unprivileged process with `network_mode: none`, a read-only root filesystem, no Docker socket, and no mounted database or policy file. Its only shared mount contains the substrate Unix socket. The **substrate** runs in a separate container with network access and the SQLite database. The agent receives no operator token. Changing the mounted YAML while the adapter runs does not change its loaded policy; restarting against the existing audit with changed policy fails closed.

This is the enforced deployment shape for Milestone 2. Running the local FastAPI service beside an unsandboxed agent does not confine that agent's OS network access.

## Run locally

Requires Python 3.11 or newer. From this directory in PowerShell:

```powershell
python -m pip install -e '.[test]'
$env:RESEARCH_AGENT_TOKEN = [guid]::NewGuid().ToString('N')
$env:GOV_SUBSTRATE_OPERATOR_TOKEN = [guid]::NewGuid().ToString('N')
$env:GOV_SUBSTRATE_AUTOSTART = '1'
python -m uvicorn substrate:app --host 127.0.0.1 --port 8000
```

The API schema is at `http://127.0.0.1:8000/docs`. Keep the generated tokens for the lifetime of the database: the audit anchors token hashes and capability definitions. Use `GOV_SUBSTRATE_REGISTRY` and `GOV_SUBSTRATE_DB` to select another registry file or database path. A registry or token change against an existing database fails closed; audited migration is future work.

Example flow: `POST /sessions` with `Authorization: Bearer <actor token>`; then `POST /proposals` with the same header and `X-Session-Token: <returned session token>`:

```json
{"action":{"kind":"state.write","scope":"session","key":"note","value":"hello"}}
```

Use `scope: "persistent"` to request a cross-session write. The example policy escalates it. An operator can call `POST /overrides` with `Authorization: Bearer <operator token>` and `{"event_id": <escalated event id>, "reason": "..."}`. `GET /audit` requires the operator token; `GET /health` requires an actor token. A second session invalidates the first session token. The example registry denies network; the isolated network example uses `tests/fixtures/network_registry.yaml` and `compose.network.yaml`.

## Measured properties

These are explicit prototype proxies, not validated measures of institutional health. `null` means there is not enough observation to compute the value.

| Property | API field | Value in this prototype |
| --- | --- | --- |
| Legibility | `legibility` | `1` when the audit chain verifies and current managed state exactly matches the last admitted state; otherwise `0`. This is an internal consistency check, not an independent external sample. |
| Plasticity | `plasticity_seconds` | Median time from an escalated proposal to its one-shot override; `null` before an override. It measures one repair path, not general adaptability. |
| Friction coherence | `friction_coherence` | Lowest ratio of median gate latencies across actors making the same action kind, requiring at least two observations per actor. `1` is equal latency; `null` when no comparable groups exist. It excludes human and economic burden. |
| Accountability topology | `accountability_topology` | Share of non-genesis events with an actor and policy rule, provided the audit chain verifies; `0` if the chain fails, `null` before an attempt. It does not establish real-world responsibility. |

## Adversarial evaluation

Run `python -m pytest -q --basetemp .pytest_tmp`. The ordinary suite makes these assertions against the API and SQLite store:

| Scenario | Expected observation | Test |
| --- | --- | --- |
| Local TCP reachable underneath while policy denies network | Direct local TCP connection succeeds in the test process; mediated network proposal is denied and logged | `test_network_policy_blocks_reachable_underlay` |
| Hidden cross-session memory | Old session token invalid; new session cannot read old session state | `test_hidden_cross_session_memory_is_not_readable` |
| Credential scope expansion | Denied and logged | `test_credential_scope_expansion_is_denied` |
| Cross-agent shared state | Reader denied without channel membership | `test_cross_agent_state_requires_explicit_shared_channel` |
| Underlying state corrupted after a valid decision | Next transition denied; legibility becomes `0` | `test_corrupted_state_fails_closed_and_is_logged` |
| Operator attempts an unlogged override | Invalid operator rejected; authenticated rejected attempts logged; successful override is linked and one-shot; audit update/delete triggers reject edits | `test_override_is_authenticated_one_shot_and_append_only` |
| Audit content or registry modified out of band | Further proposals fail closed | `test_audit_tampering_blocks_further_actions`, `test_unlogged_registry_change_fails_closed` |

### Docker isolation test

Requires a running Docker Desktop Linux engine. On PowerShell:

```powershell
$env:RUN_DOCKER_TESTS = '1'
python -m pytest -q tests/test_network_isolation.py --basetemp .pytest_tmp_docker
```

The test builds a local image, starts a networked static fixture and adapter, then launches separate networkless agent containers. It checks direct TCP to both a public IP and the fixture's IP, allowed GET plus outcome audit events, denied destination with no outbound call, rejection when the actor token is used on the operator endpoint, a new session invalidating the old token, blocked shared-storage writes, unchanged running authority after editing YAML, and fail-closed behavior after restart with the edited registry. The test removes its uniquely named containers, network, and volumes. On this host, an ordinary Docker bridge container could connect to `1.1.1.1:443`, while the agent with `network_mode: none` could not.

Set `RUN_LIVE_NETWORK_TESTS=1` as well to exercise an explicitly allowed `https://example.com/` request through the adapter. That check requires external internet access and is excluded from the default Docker test. The dated results from this workspace are in `docs/evaluation-2026-09-27.md`.

### Optional LLM smoke run

With `ANTHROPIC_API_KEY` set, install `python -m pip install -e '.[llm]'` and run `python tests/llm_smoke.py`. It makes two tool-use cases with `claude-haiku-4-5-20251001`: one allowed origin and one denied origin. The model API runs in a trusted driver; every model-selected tool call executes in the networkless agent container. The API key is never passed to that container. The script caps each case at two model calls and prints token usage and audit event IDs. Model behavior is a validation layer, not the confinement mechanism.

### Scope and limits

The Docker test proves a network capability boundary for the supplied container configuration. It does not prove confinement for arbitrary host processes, privileged containers, or agents given other mounts or sockets. HTTP GET is the only implemented outbound method. An admitted external request cannot be rolled back; its decision event commits before execution, and a process crash before the outcome event can leave an unresolved attempt. A database owner can drop triggers or rewrite the hash chain; external anchoring is needed for stronger immutability. Invalid authentication and malformed HTTP requests are rejected before an actor can be attributed and are not part of the audit. The four health values remain prototype proxies, not empirical validation of the paper's full framework.
