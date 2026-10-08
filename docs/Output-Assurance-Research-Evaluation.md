# Output assurance research evaluation

This document describes research integrated after the v0.6.0 release. It does
not change that release or claim attestation for an opaque hosted provider. No
paid model-provider API was called.

## Current implementation boundary

| Assurance | Source | Public generated output |
| --- | --- | --- |
| `local_verified` | Substrate-mediated local generation | Existing public-object publication rule |
| `hosted_opaque` | Default for every hosted provider | Held until a separate operator release decision |
| `hosted_attested` | Registered provider with a separately verified runtime evidence contract | Existing public-object publication rule after verification |

Highest-input classification remains mandatory. An opaque hosted completion is
stored with exact sealed parents and its inherited label, but a separate,
integrity-checked release hold prevents `object.publish`. The hold follows
transforms, declassification, and later generations using the held object.
Actors who can read held objects also lose raw external-request and shared-write
authority. The operator-only `/objects/release` action requires a reason and
creates a new public child with the same bytes; it never changes the original.
Releasing a private object first requires the existing audited declassification
step. The release decision is a trust decision by the operator, not proof that
the provider output was semantically safe.

## Offline release-candidate experiment

`experimental_release_candidates.py` compares candidate text with repeated
generations after each protected input is removed and replaced. It records the
candidate, protected fixture inputs, counterfactual outputs, equivalence result,
leakage-test result, and a proposed lower classification. It has no substrate
publication authority and always reports `publication_authorized: false`.

The seven synthetic fixtures include direct, paraphrased, encoded, indirect,
covertly structured, constant hidden-source leakage, and one clean public
answer. None of the six labelled leaks is proposed for a lower label; the clean
answer is proposed as a
release candidate. There are zero unsafe proposals and zero false alarms in
this tiny deterministic fixture. One unnecessary private label is identified.
These counts are **not** evidence that automated declassification is sound:
the fixture supplies the leakage oracle and uses exact-text equivalence.
In particular, constant hidden-source leakage survives counterfactual changes
and is caught only by the fixture's independent leak label.

No automatic release threshold has been met or enabled. A future preregistered
evaluation would need a defined threat model, independent semantic/leak labels,
adversarial paraphrases and encodings, release-yield measurements, and a stated
upper confidence bound on unsafe releases.

## Remote attestation path and cloud acceptance

`hosted_attested` now requires a Google Confidential Space token whose signature,
issuer, audience, nonce, production image status, image digest, project, zone,
and hardware type match the registered policy. The substrate checks this at the
existing provider-call boundary **before** the trusted driver sends encrypted
governed context. The token binds a fresh nonce, sealed request hash, expected
model artifact hash, and workload-generated exchange and result public keys.

The measured workload hashes the pinned model file before serving either Qwen
or Phi. It verifies the decrypted sealed request and signs a result containing
the generation, request, model, output, and image hashes. Completion checks the
signature and the gateway receipt's evidence hash. The active `hosted_attested`
path no longer accepts the earlier shared-secret simulator as evidence.

Offline tests use synthetic tokens and a fake inference callback to check local
decision wiring. Separate real Google Confidential Space acceptance runs used
authentic Google attestation and real remote inference for Qwen and Phi. For
each model, the valid case accepted a signed result as a governed object, and
wrong nonce, image measurement, and model hash were denied before input release:
**4/4 cases passed per model**. The recorded evidence and limits are in
`Google-Confidential-Space-Validation-Plan.md`. This experiment does not attest
to the internals of ordinary opaque hosted providers.

## Verification

`tests/test_output_assurance.py` exercises a valid gateway receipt carrying
semantically contaminated text from public input. The text is stored with its
provenance but cannot publish automatically; derived objects retain the hold.
The same test verifies operator-only release. The attested-path unit tests use
the same assertions for both model profiles and reject wrong nonce, image, and
model evidence before any governed input is sent. An altered signed result is
rejected at completion.
`tests/test_release_candidate_experiment.py` covers the seven synthetic
leakage categories and confirms the evaluator cannot authorize publication.

Historical hosted-model validation reports describe the behavior of their
respective released versions. Current smoke drivers now expect a public hosted
output to be held; they do not make paid calls in the unit tests.

Earlier in this work, the unpaid unit suite passed **168 tests** with **10 skipped**.
The existing real Docker phase-9 gateway acceptance case passed **1 test**;
it proves the existing gateway/network boundary still runs, not remote
provider attestation. The later Google cloud acceptance runs are reported
separately above; no paid hosted-model API was called for this work.
