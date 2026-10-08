# Governance Substrate

**Governance belongs beneath the model, enforced by the system.**

Governance Substrate is a runtime layer that enforces what AI agents can access, change, retain, and publish — outside the model, at the system boundary.

> **Technical architecture:** [Substrate Reference Architecture](docs/Substrate-Reference-Architecture.md)

Current source version: [v0.6.0](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/tree/v0.6.0)

> **TL;DR:** Agent intent is not authority. Governance Substrate places permissions, execution control, provenance, and audit beneath the agent so the system — not the prompt — decides what actions are allowed.

## Demonstrated result

The reference implementation has enforced capability boundaries independently of model behavior across tested local and hosted model paths, and container, native, WASI, and Kubernetes runtimes.

In the tested configurations, governed actions passed through the substrate, ungranted runtime paths were blocked, generated outputs retained provenance and classification, and supervised workers could be revoked, stopped, and verified.

## How it works

`agent → substrate authorization → one-use grant → execution → verified outcome → audit`

The substrate checks authority before execution, mediates governed capabilities, records what happened, and verifies the result. Agent intent does not create authority.

## Evidence

The project separates policy tests from real runtime evidence. Evaluation includes runtime conformance, hostile-worker enforcement, model integration, hosted-provider validation, incident-derived failure cases, and compromised-host/provider scenarios.

The canonical empirical baseline is the [Phase 10 evidence freeze](docs/Evidence-Freeze-2026-10-05.md).

## Research

**Governance as Substrate: Engineering Patterns for Resilient Collective Systems — V2, September 2026 Revision**

- [Research paper DOI](https://doi.org/10.5281/zenodo.23002435)
- [v0.6.0 release notes](docs/Release-v0.6.0.md)

## Scope

The evidence applies to the documented reference configuration and tested scenarios; it does not establish universal AI confinement or prove every runtime backend.

## License

The software source code is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`). Copyright © 2026 Antiparty Inc.

Organizations that want to incorporate Governance Substrate into proprietary products or services without AGPL obligations may request a separate commercial license from [smith@antiparty.co](mailto:smith@antiparty.co).

The Governance Substrate name, associated branding, trademarks, research papers, and prose documentation are not licensed under the software license unless expressly stated.
