# Free-form output provenance: deterministic evaluation

This branch adds an `object.generate` proposal for model-written UTF-8 text.
The actor supplies only `kind` and `content`. The substrate assigns the
classification and stores the text as an immutable governed object before it
can be published. The generated content is excluded from the audit log; its
hash, parent IDs, assigned classification, and decision remain attributable.

## Provenance rule

For actor A, the substrate reads A's append-only audit history. The source set
is every distinct object ID in A's **allowed** `object.read` or
`object.transform` actions, in first-exposure order, across all sessions.
Generation without a source is denied. The generated object's parents are
exactly that source set, and its classification is the highest parent label:

`public < internal < private < restricted`

The actor cannot supply a label or parent list. Extra proposal fields are
rejected. This conservative rule includes earlier governed context even if a
particular generation did not use it. Resetting a session cannot erase that
history. An actor with only public governed exposure can generate a public
object; a clean actor identity and isolated execution context are required
after another actor has seen sensitive data.

The existing `object.publish` gate still admits only governed public text to
an external publication service. A generated private or restricted object can
be lowered only through the existing operator-only `/objects/declassify`
route, which records a reason and creates a new child without modifying the
original.

## Deterministic checks

`tests/test_free_form_output_provenance.py` uses fixed text as the generation
fixture and a local publication-adapter stub. It covers public, internal,
private, mixed public/private, and restricted inputs; paraphrasing, encoding,
summarizing, and rewriting; session reset; attempted model-assigned labels;
operator declassification; and publication from a public-only actor context.

Run without model APIs:

```powershell
python -m pytest -q tests/test_free_form_output_provenance.py --basetemp .pytest_tmp_free_form
```

On 2026-09-28, this focused suite passed **13 tests**. The complete local
suite passed **30 tests** with **6 Docker-gated tests skipped**; the Docker
tests were not run for this change.

## Boundary and remaining gap

The rule covers governed objects observed through the substrate under the
same actor identity. It cannot establish which data a model saw through an
unmediated prompt, host process, external tool, another actor, or retained
model/runtime memory. A production generation driver must keep all model
inputs on this governed path and isolate a clean public-only context from
previous sensitive context. This deterministic fixture does not validate a
hosted model or a new runtime. No content scanning is used as authority.
