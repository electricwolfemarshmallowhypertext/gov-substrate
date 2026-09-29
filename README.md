# Governance Substrate

**Governance beneath the agent, not inside the prompt.**

Governance Substrate is a reference architecture for enforcing AI agent capabilities at the system boundary. The environment determines which actions can execute, even when an agent asks for something else.

> **Technical architecture:** [Substrate Reference Architecture](docs/Substrate-Reference-Architecture.md)

## Research paper

**Governance as Substrate: Engineering Patterns for Resilient Collective Systems — V2, September 2026 Revision**

[Read the paper on ResearchGate →](https://www.researchgate.net/publication/403770865_Engineering_Patterns_for_Resilient_Collective_Systems_V2_-_September_2026_Revision)

## What it demonstrates

In the supplied isolated-container configuration, an agent cannot directly change governed state, reach the network, or access the governed workspace. It must request those actions through the substrate. The substrate checks authority and state integrity, records its decision, and records the outcome of any admitted execution.

`agent → proposed action → capability boundary → allow / deny / escalate → execution outcome + audit`

**Agent intent is not authority.**

## Implemented boundaries

- **State:** Admitted transitions, session and persistent state, tamper detection, and auditable one-shot overrides.
- **Network:** No direct outbound route from the agent container. A destination-scoped HTTP GET adapter mediates and audits requests.
- **Filesystem:** No workspace mount in the agent container. A scoped adapter mediates file reads and writes and rejects protected paths and escape attempts.
- **Scoped authority:** Actor-, session-, and shared-resource access are distinct capabilities rather than implicit shared access.
- **Delegated services:** Services that can proxy, store, forward, or act downstream are treated as delegated capabilities and fail closed unless explicitly mediated.
- **Sensitive-data egress:** External publication is constrained by composed authority, not destination access alone.
- **Object provenance:** Governed objects retain classification through supported transforms and sealed generation contexts; lowering classification requires an audited operator action.
- **Local generation:** A one-shot CPU model worker receives only substrate-assembled text inputs. It has no outbound network, governed workspace, secret environment, or conversation store.
- **Execution grants and emergency stops:** One-use execution tokens bind approved actions to their actor, session, inputs, policy, and capability. A separate operator control revokes scoped grants and requires verified shutdown from a wired local runtime supervisor.

Generation is model- and provider-agnostic. The local worker is optional; a trusted host can use the same sealed-input handoff with OpenAI, Anthropic, or another adapter while the substrate assigns output provenance and classification. Hosted transfer is denied until the provider is registered with an explicit classification grant.

## Results

Governance Substrate has been evaluated against state tampering, unauthorized network access, filesystem escape, cross-agent communication, persistent memory, delegated-service abuse, privilege expansion, sensitive-data egress, and classified-object publication.

Current implementation enforces:

- isolated agent execution with no direct network or governed-workspace access
- actor- and session-scoped authority
- fail-closed policy and state integrity checks
- explicit treatment of delegated services
- governed sensitive-data publication
- object-level classification and exact parent provenance through fixed transforms and sealed free-form generation
- auditable decisions, execution outcomes, and operator-approved declassification

The evaluations intentionally include failure cases. Earlier tests exposed cross-agent, persistence, and proxy-service gaps; subsequent enforcement changes closed those paths under the hardened policy.

Evaluations:

- [Baseline containment evaluation](docs/Containment-Evaluation.md)
- [Scoped-authority evaluation](docs/Scoped-Authority-Evaluation.md)
- [Sensitive-data egress evaluation](docs/Sensitive-Data-Egress-Evaluation.md)
- [Object-provenance evaluation](docs/Object-Provenance-Evaluation.md)
- [Free-form output provenance evaluation](docs/Free-Form-Output-Provenance.md)
- [Generation adapter integration](docs/Generation-Adapters.md)
- [Hosted object-provenance validation report](docs/Hosted-Object-Validation.md)
- [Claude Opus 4.7 validation report](docs/Anthropic-Opus-4.7-Validation-Report.md)
- [Environment skeleton evaluation](docs/Environment-Skeleton-Evaluation.md)

The same five governed object-provenance scenarios held across deterministic tests, two local models, GPT-6 Luna, GPT-6 Sol, and Claude Opus 4.7.

In a separate forced-call check, Opus requested a reachable third-party fixture outside the actor's grant. The substrate denied and logged it. The initial Opus scope response was inconclusive; the denial came from a one-request follow-up.

## Testing

- **Unit tests — policy and control logic:** `python -m pytest -q tests --ignore=tests/acceptance`. Fake provider and Docker clients are used where appropriate; opt-in Docker tests in the normal suite are skipped unless separately enabled. These results establish decision logic, not runtime enforcement.
- **Acceptance tests — real Docker and runtime enforcement:** Set `GENERATION_MODEL_BLOB` to the official [Qwen/Qwen3-0.6B-GGUF](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/blob/main/Qwen3-0.6B-Q8_0.gguf) file `Qwen3-0.6B-Q8_0.gguf`, then set `RUN_ACCEPTANCE_TESTS=1` and run `python -m pytest -q tests/acceptance`. The suite verifies SHA-256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031` before building the worker. It runs local inference through the real substrate, Docker worker, and runtime supervisor; verifies inherited object classification and provenance; stops/removes a running worker through the circuit breaker; reconciles an orphan on supervisor restart; and denies an agent access to a service that is reachable by the substrate.

The GitHub Actions `unit-tests` job runs on pushes and pull requests. The separate `acceptance-tests` job is manual (`workflow_dispatch`) because it downloads the pinned 639 MB official model and builds a CPU inference image. The download is from the official Qwen repository at a fixed commit and is SHA-256 checked before tests. CI makes no paid model calls. The acceptance tests require a real Docker daemon and fail if prerequisites are missing; they are not replaced by fake-client results.

Local verification on September 29, 2026: **76 passed, 10 opt-in skips** in the normal suite; **4 passed, 0 skipped** in the real Docker acceptance suite using the SHA-256 verified Qwen Q8_0 file. The acceptance suite has not yet been run in GitHub Actions.

## Read more

- [Substrate Reference Architecture](docs/Substrate-Reference-Architecture.md) — implementation, test protocol, and limitations.
- [Scoped Authority Evaluation](docs/Scoped-Authority-Evaluation.md) — baseline comparison, replay, and limits.
- [Sensitive-Data Egress Evaluation](docs/Sensitive-Data-Egress-Evaluation.md) — publication authority and local-model replay.
- [Object Provenance Evaluation](docs/Object-Provenance-Evaluation.md) — classified objects, transforms, and audited declassification.
- [Governance as Substrate: Engineering Patterns for Resilient Collective Systems, V2](https://doi.org/10.5281/zenodo.23002435) — research framework.

## License

The software source code is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`). Copyright © 2026 Antiparty Inc. You may use, modify, and distribute the software under that license's terms.

Organizations seeking to incorporate the software into proprietary products or services without AGPL obligations may request a separate commercial license from [smith@antiparty.co](mailto:smith@antiparty.co). A commercial license is granted only by a separate written agreement. The Governance Substrate name and associated branding, trademarks, research papers, and prose documentation are not licensed under the software license unless expressly stated.

## Scope

Governance Substrate enforces capabilities that are explicitly placed behind its boundary.

The current implementation covers governed state, network access, filesystem authority, delegated services, sensitive-data egress, and classified-object publication in the documented isolated-container architecture.

It does not claim to secure arbitrary host processes, privileged containers, unmediated external systems, or capabilities that bypass the substrate. Generated prose is classified from the exact governed objects supplied to a sealed generation. A compromised host or provider that injects extra context remains outside that boundary.
