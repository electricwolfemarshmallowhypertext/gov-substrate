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

Governance Substrate defines the boundary. Docker/OCI is the current reference enforcement backend, not a product requirement.

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
- [Direct Gemini Flash validation report](docs/Gemini-Direct-Validation.md)
- [OpenRouter validation report](docs/OpenRouter-Validation.md)
- [Environment skeleton evaluation](docs/Environment-Skeleton-Evaluation.md)
- [Local-model runtime matrix](docs/Local-Model-Matrix-Evaluation.md)

The same five governed object-provenance scenarios held across deterministic tests, two local models, GPT-6 Luna, GPT-6 Sol, and Claude Opus 4.7.

In a separate forced-call check, Opus requested a reachable third-party fixture outside the actor's grant. The substrate denied and logged it. The initial Opus scope response was inconclusive; the denial came from a one-request follow-up.

A separate direct `gemini-3.8-flash` run confirmed provider-transfer denial before an API call, private generated-output publication denial, and clean public generated-output publication.

A separate `z-ai/glm-5.2` run through OpenRouter, pinned to the Z.AI upstream with fallback disabled, confirmed the same three outcomes while treating the router as an additional trust and routing layer.

## Testing

- **Unit tests — policy and control logic:** `python -m pytest -q tests --ignore=tests/acceptance`. Fake provider and Docker clients are used where appropriate; opt-in Docker tests in the normal suite are skipped unless separately enabled. These results establish decision logic, not runtime enforcement.
- **Acceptance tests — real Docker and runtime enforcement:** Set `GENERATION_MODEL_BLOB` to either pinned artifact in the [local-model matrix](docs/Local-Model-Matrix-Evaluation.md), set `RUN_ACCEPTANCE_TESTS=1`, and run `python -m pytest -q tests/acceptance --ignore=tests/acceptance/environment`. The same tests run real local inference through the substrate, Docker worker, and runtime supervisor; verify output classification and provenance; stop and remove a running worker; reject late completion; reconcile an orphan; and deny an agent access to a substrate-reachable unauthorized service. The model file is verified by size and SHA-256 before the worker is built.
- **Environment probes — physical isolation:** Run `python -m pytest -q tests/acceptance/environment` separately with a pinned model file. These direct OS and Docker probes establish the reported isolation properties for the tested configuration; repeating them with different weights would not add network or filesystem isolation evidence.

The GitHub Actions `unit-tests` and `acceptance-qwen` jobs run on pushes and pull requests. Qwen uses the official historical Q8_0 revision and a checked SHA-256. The `acceptance-phi` job runs only when manually requested with `workflow_dispatch` and `run_phi=true`; it downloads official Microsoft weights, verifies their hashes, converts them with a pinned official `llama.cpp` commit, then runs the same acceptance command. CI makes no paid model calls. Fake-client tests remain unit evidence, separate from real Docker acceptance.

Local verification on September 29, 2026: Qwen acceptance **4 passed**; Phi acceptance **4 passed**; separate environment probes **5 passed**; normal unit suite **76 passed, 10 opt-in skips**. A [manual Linux CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36617457396) passed both Qwen and Phi acceptance, environment probes, and unit tests. Qwen also passed the [automatic CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36614343212).

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
