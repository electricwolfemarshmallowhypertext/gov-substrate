# Research case and evidence

AI agents can request actions, but a request is not authority. Governance
Substrate tests whether a system beneath the model can enforce scoped
capabilities, govern generated data, record outcomes, and stop workers.

The [reference architecture](Substrate-Reference-Architecture.md) describes the
implementation and trust boundary. This page points to the evidence. It is a
public guide, separate from private grant drafts and the research paper.

## What was tested

| Question | Evidence |
| --- | --- |
| Do the policy and provenance rules hold? | Deterministic tests and the [Phase 10 evidence freeze](evidence/Evidence-Freeze-2026-10-05.md) |
| Can a real worker use an ungranted capability? | [Runtime conformance](evidence/Runtime-Conformance.md), [environment probes](evaluations/Environment-Skeleton-Evaluation.md), and [incident replay](evaluations/Incident-Derived-Escape-Evaluation.md) |
| Does governed generation work across model paths? | [Local model matrix](evaluations/Local-Model-Matrix-Evaluation.md), [hosted validation](evaluations/Hosted-Object-Validation.md), and [generation adapters](Generation-Adapters.md) |
| What happens after revocation or adapter compromise? | [Containment](evaluations/Containment-Evaluation.md) and [compromised host/provider evaluation](evaluations/Compromised-Host-Provider-Evaluation.md) |
| Can a remote runtime be checked before receiving governed input? | [Confidential Space evaluation plan and recorded results](evaluations/Google-Confidential-Space-Validation-Plan.md) |

The frozen [manifest and raw results](evidence/evidence-freeze-2026-10-05/manifest.json)
identify the tested commit, environments, outcomes, and limits. The current
repository also contains later evaluations; their individual reports state
which tests were real and which were deterministic.

## Remaining research questions

The substrate can govern only context and capabilities it mediates. Opaque
provider internals and a fully compromised trusted host remain outside its
local proof. Conservative classification of generated text can also retain a
private label when the output contains no protected information. See the
[output assurance evaluation](evaluations/Output-Assurance-Research-Evaluation.md)
for the current boundary and experimental work. No experimental release
candidate is an automatic declassification decision.
