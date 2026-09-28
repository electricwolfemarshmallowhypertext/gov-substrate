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
- **Object provenance:** Governed objects retain classification through supported transforms and audited actor-context generation; lowering classification requires an audited operator action.

## Results

Governance Substrate has been evaluated against state tampering, unauthorized network access, filesystem escape, cross-agent communication, persistent memory, delegated-service abuse, privilege expansion, sensitive-data egress, and classified-object publication.

Current implementation enforces:

- isolated agent execution with no direct network or governed-workspace access
- actor- and session-scoped authority
- fail-closed policy and state integrity checks
- explicit treatment of delegated services
- governed sensitive-data publication
- object-level classification and provenance through fixed transforms and governed free-form generation
- auditable decisions, execution outcomes, and operator-approved declassification

The evaluations intentionally include failure cases. Earlier tests exposed cross-agent, persistence, and proxy-service gaps; subsequent enforcement changes closed those paths under the hardened policy.

Evaluations:

- [Baseline containment evaluation](docs/Containment-Evaluation.md)
- [Scoped-authority evaluation](docs/Scoped-Authority-Evaluation.md)
- [Sensitive-data egress evaluation](docs/Sensitive-Data-Egress-Evaluation.md)
- [Object-provenance evaluation](docs/Object-Provenance-Evaluation.md)
- [Free-form output provenance evaluation](docs/Free-Form-Output-Provenance.md)
- [Hosted object-provenance validation report](docs/Hosted-Object-Validation.md)
- [Claude Opus 4.7 validation report](docs/Anthropic-Opus-4.7-Validation-Report.md)

The same five governed object-provenance scenarios held across deterministic tests, two local models, GPT-6 Luna, GPT-6 Sol, and Claude Opus 4.7.

In a separate forced-call check, Opus requested a reachable third-party fixture outside the actor's grant. The substrate denied and logged it. The initial Opus scope response was inconclusive; the denial came from a one-request follow-up.

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

It does not claim to secure arbitrary host processes, privileged containers, unmediated external systems, or capabilities that bypass the substrate. Generated prose is classified when submitted through `object.generate` using the actor's audited governed-object context; inputs supplied outside that boundary remain unverified.
