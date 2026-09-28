# Governance Substrate

**Governance beneath the agent, not inside the prompt.**

Governance Substrate is a small working reference architecture for enforcing AI agent capabilities at the system boundary. The environment determines which actions can execute, even when an agent asks for something else.

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

## Results

The frozen `v0.3.0` baseline passed 12 deterministic tests: ten local state/API tests and two Docker isolation tests. In a separate three-request OpenAI smoke check, a permitted file read and write succeeded and a protected write was denied. The OpenAI key stayed in the trusted host driver; the agent container received only its substrate actor credential.

The [baseline containment evaluation](docs/Containment-Evaluation.md) exposed three gaps through allowed shared surfaces. The [scoped-authority replay](docs/Scoped-Authority-Evaluation.md) checks actor-specific files, file lifetimes, and fail-closed treatment of a delegated relay. No paid model was used for the replay.

## Read more

- [Substrate Reference Architecture](docs/Substrate-Reference-Architecture.md) — implementation, test protocol, and limitations.
- [Scoped Authority Evaluation](docs/Scoped-Authority-Evaluation.md) — baseline comparison, replay, and limits.
- [Governance as Substrate: Engineering Patterns for Resilient Collective Systems, V2](https://doi.org/10.5281/zenodo.23002435) — research framework.

## License

The software source code is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`). Copyright © 2026 Antiparty Inc. You may use, modify, and distribute the software under that license's terms.

Organizations seeking to incorporate the software into proprietary products or services without AGPL obligations may request a separate commercial license from [smith@antiparty.co](mailto:smith@antiparty.co). A commercial license is granted only by a separate written agreement. The Governance Substrate name and associated branding, trademarks, research papers, and prose documentation are not licensed under the software license unless expressly stated.

## Scope

This is a reference implementation and research artifact. The results establish the tested boundaries for the supplied container configuration. They do not establish universal AI confinement or validate every mechanism proposed in the paper.
