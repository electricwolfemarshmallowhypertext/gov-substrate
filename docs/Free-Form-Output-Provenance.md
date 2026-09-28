# Generation-scoped output provenance

Free-form text generation now uses a sealed, one-use context manifest. An
authenticated actor proposes `generation.prepare` with an ordered, nonempty
list of governed input object IDs. The request accepts no prompt, history,
output text, classification, or parent fields. Task instructions must be
imported as governed objects and included in that input list.

The substrate checks that the actor may read every input, resolves immutable
bytes, records the exact IDs and SHA-256 hashes, and assigns the highest input
classification:

`public < internal < private < restricted`

This manifest is stored in integrity-checked state and audited before any
generation starts. A trusted host adapter claims it once using the existing
host-only operator credential. The adapter verifies input hashes and passes
only media types and substrate-supplied bytes to a fresh worker. The worker
has no network, workspace, substrate socket, API credential, persistent
volume, or prior conversation. It returns only text; output fields that try
to supply provenance are rejected. The substrate accepts a completion only
for the claimed manifest, stores an immutable text object with exactly the
sealed parents and inherited label, and audits the completed outcome. A
second claim or completion is denied. A failed worker leaves a claimed run
without an output object and cannot be replayed.

The worker's deterministic fixture concatenates text inputs and renders an
image input by its hash. It does not classify content. The same actor can
complete a private generation and then a separate public-only generation:
the latter remains public because the fresh worker receives only its sealed
public inputs. Encoded, paraphrased, summarized, or rewritten text inherits
the manifest's classification regardless of its wording. The existing
`object.publish` gate still accepts only governed public text for external
publication. Lowering a generated object's label still requires the
operator-only audited declassification path, which creates a new child and
does not change the original.

## Deterministic checks

`tests/test_free_form_output_provenance.py` covers exact parents, all four
labels, mixed inputs, transformed inputs, session reset, public-only reuse by
the same actor, rejected model-provided fields, missing or inaccessible
inputs, tampered manifests, replay, publication, and declassification.
`tests/test_generation_worker_docker.py` runs two one-shot workers with the
same actor, confirms private then public lineage, and checks the worker has
no network, governed mounts, or credential variables. It also checks the
Compose isolation settings.

Run the combined deterministic and Docker suite with Docker Desktop running:

```powershell
$env:RUN_DOCKER_TESTS = '1'
python -m pytest -q --basetemp .pytest_tmp_generation
```

On 2026-09-28, the combined suite passed **42 tests with none skipped**.
Pydantic emitted two class-based configuration deprecation warnings; they did
not affect the result. No hosted model was called.

## Trust boundary

The substrate governs only the context it assembles and supplies. The host
adapter is trusted to invoke the worker with that exact context. A compromised
host or provider that secretly injects additional context is outside this
boundary. The deterministic worker is evidence for the supplied isolated
container configuration; no hosted model was called for this change.
