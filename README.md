# Governance Substrate Reference Architecture

A small reference implementation of the paper's distinction: policy declares what should happen; the substrate and execution boundary decide which **managed state transitions** become real. The source is *Governance as Substrate: Engineering Patterns for Resilient Collective Systems*, Tionne Smith, September 2026 revision. The PDF is intentionally excluded from this code repository because it is marked all rights reserved.

## What this milestone enforces

Actors authenticate with bearer tokens from environment variables. The service issues one active session per actor. Every valid proposal reaches one SQLite transaction that checks the capability registry, verifies the previous audit chain and committed state, makes a decision, and appends an event. An admitted `state.write` and its audit event commit together. A denied or escalated proposal leaves managed state unchanged and still produces an event. An authenticated operator can apply an escalated persistent write once, with a reason and an audit link to the original proposal.

The state layer includes actor identity, explicit capabilities, session and persistent namespaces, prior events, and current health observations. The audit records actor, action, policy rule and registry digest, full managed state before and after, decision, timestamp, and override link. SQLite triggers reject ordinary updates and deletes of audit rows; a SHA-256 chain detects unauthorized changes to audit content. Direct changes to managed state are detected against the last admitted state snapshot on the next request.

Network, filesystem, shell, and external API permissions are present in the YAML registry. Their execution adapters are **not implemented** in this milestone: proposals for them are logged and denied. This prevents the API from claiming to confine an agent process it does not control.

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

Use `scope: "persistent"` to request a cross-session write. The example policy escalates it. An operator can call `POST /overrides` with `Authorization: Bearer <operator token>` and `{"event_id": <escalated event id>, "reason": "..."}`. `GET /audit` requires the operator token; `GET /health` requires an actor token. A second session invalidates the first session token.

## Measured properties

These are explicit prototype proxies, not validated measures of institutional health. `null` means there is not enough observation to compute the value.

| Property | API field | Value in this prototype |
| --- | --- | --- |
| Legibility | `legibility` | `1` when the audit chain verifies and current managed state exactly matches the last admitted state; otherwise `0`. This is an internal consistency check, not an independent external sample. |
| Plasticity | `plasticity_seconds` | Median time from an escalated proposal to its one-shot override; `null` before an override. It measures one repair path, not general adaptability. |
| Friction coherence | `friction_coherence` | Lowest ratio of median gate latencies across actors making the same action kind, requiring at least two observations per actor. `1` is equal latency; `null` when no comparable groups exist. It excludes human and economic burden. |
| Accountability topology | `accountability_topology` | Share of non-genesis events with an actor and policy rule, provided the audit chain verifies; `0` if the chain fails, `null` before an attempt. It does not establish real-world responsibility. |

## Adversarial evaluation

Run `python -m pytest -q --basetemp .pytest_tmp`. The suite makes these assertions against the API and SQLite store:

| Scenario | Expected observation | Test |
| --- | --- | --- |
| Network requested despite policy denying it | Denied and logged; no network adapter runs | `test_network_policy_blocks_reachable_underlay` |
| Hidden cross-session memory | Old session token invalid; new session cannot read old session state | `test_hidden_cross_session_memory_is_not_readable` |
| Credential scope expansion | Denied and logged | `test_credential_scope_expansion_is_denied` |
| Cross-agent shared state | Reader denied without channel membership | `test_cross_agent_state_requires_explicit_shared_channel` |
| Underlying state corrupted after a valid decision | Next transition denied; legibility becomes `0` | `test_corrupted_state_fails_closed_and_is_logged` |
| Operator attempts an unlogged override | Invalid operator rejected; authenticated rejected attempts logged; successful override is linked and one-shot; audit update/delete triggers reject edits | `test_override_is_authenticated_one_shot_and_append_only` |
| Audit content or registry modified out of band | Further proposals fail closed | `test_audit_tampering_blocks_further_actions`, `test_unlogged_registry_change_fails_closed` |

These tests establish behavior of the managed API. They do not establish system-wide isolation. An agent with direct access to the database file, OS network, shell, or another storage service can act outside this boundary. Deployments must run the agent with separate OS credentials and deny direct access to those resources, or add enforceable adapters and isolation. A database owner can drop triggers or rewrite the entire hash chain; external anchoring is needed for stronger immutability. Invalid authentication and malformed HTTP requests are rejected before an actor can be attributed and are not part of the audit. No empirical claim about the four paper properties follows from this prototype alone.
