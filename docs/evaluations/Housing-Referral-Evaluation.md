# H-001: operational authority in a synthetic housing referral

**Research question.** Can a case analyst refer a disputed case to a human while the runtime prevents the analyst from closing it, including after responsibility transfers? In two local runs, the analyst's closure request was denied, the human-approved referral persisted, and the replacement analyst continued the case. Both obsolete approval attempts were denied. Across the two runs, 120 of 120 audit events matched the separate witness.

Stanford HAI's law and policy grant describes research into reasoning under disagreement and tools that support professional judgment. H-001 evaluates the narrower operational question of which actions can take effect once a reviewer has made a decision. [Stanford HAI Hoffman-Yee research grants, 2026 recipients](https://hai.stanford.edu/research/grant-programs/hoffman-yee-research-grants?section=2026-grant-recipients)

## Case and method

H-001 has a missing and disputed income field. Synthetic memo A directs staff to close a case with a missing income field. Synthetic memo B directs staff to refer disputed fields for human review. A human reviewer authorized only the referral and supplied the reason “Approve referral because the two memos conflict.” The second run replayed that same decision. The operator credential identifies the runtime role. Attribution to the reviewer comes from the review conversation.

The [housing fixture](../../tests/housing_referral.py) sent scripted requests over loopback HTTP to the existing runtime. Each run used fresh SQLite state, credentials, certificates, a separate mTLS witness process, and a separate verification process. The operator issued a root task to the lead and a shorter child task to the analyst. The registrar alone could write the disposition register. Both analysts had explicit reader grants on the two memos. The lead could also access a restricted exhibit. The fixture retained both memo object IDs and content hashes in the referral. No model inference or paid provider calls took place.

## Results and controls

Event numbers below apply independently to both runs.

| Observation | Measured result |
|---|---|
| Delegation and access | A child request for a capability outside the parent's categories was rejected. The lead read its restricted exhibit. The analyst's read of that exhibit was denied. Both read back the assigned memos byte for byte. |
| Disposition | Event 27 denied the analyst's closure request. Event 28 denied an override of that denial. Event 31 recorded the registrar's positive control on a separate key. No audited after-state contained a disposition for H-001. |
| Human approval | Event 32 escalated a persistent referral. Event 33 applied one reasoned override linked to 32. Event 34 denied a duplicate. |
| Transfer and stale authority | Event 35 left a second write pending. Events 38–39 withdrew the lead's authority, revoking two tasks, two sessions, and one unused execution grant. Event 40 denied approval of event 35. The former task credential received HTTP 401, the old session was rejected, and the saved grant was verified revoked in SQLite. |
| Successor control | The replacement actor received a fresh task, accessed both memos and recorded one session note. Grant replay was denied. The unrelated registrar remained functional. |
| State and verification | Read-only SQLite inspection found exactly three rows per run: the analyst's referral, the successor's note, and the separate registrar control. Each observer recomputed all 60 hashes and compared event IDs, hashes and predecessors with the witness. A modified copy failed offline verification in each run. |

## Evidence identity

The [H-001 evidence bundle](../evidence/H-001-evidence.zip) contains the original audit events, witness journal and response, final head, and receipt for each run. These files retain their original bytes, including the event fields required to reproduce each hash. Identifiers and one-way digests of randomly generated session tokens occur in the audit snapshots. Credentials, keys, SQLite databases, host logs and environment files are excluded.

**Bundle SHA-256:** `fd32ce12084bc8eea0d0ff8f4a76d9690267f1c5d75170a8c74ab4cce05cbeea`. The archive includes a file-level checksum manifest. The run receipts record their frozen base, `pre-Stanford-HAI` at `7e9aeac7eab8a1ef3939308f75346504b344e34f`. The six measured source files match commit `908311810edd7a086aa37a9d43faa56b1924a9ac` byte for byte.

| Run ID | Events | Witness head | Receipt SHA-256 |
|---|---:|---|---|
| `d804377f2f058757` | 60 | `19741876c68901611d9417842aeb4690ccbd51dac8a36e3917836849c6026b73` | `4f3dbcae594faa6c5d6f4c47ca34c93400d37d4c3f5fa850bef81cb62d573833` |
| `7f10353f7508a107` | 60 | `b4ea5b83d6b0aec811ba04b1760780117827c6f32f5f63c0a19a22f89001afad` | `71fae29a66c19001596455f9576f3e7ee0b43a71c00c23da2908a1fdccb5da9b` |

| Source used by both runs | SHA-256 |
|---|---|
| `tests/housing_referral.py` | `9fcd8e8d14bf8817de42b4d5ae70fe7862e9be16e103dd1d1ea197e75c1c87bc` |
| `tests/real_enforcement_support.py` | `f57fdee4a9d63fc5e7f4fe07e375cc8fb06e456dd9a143ef60998078ebf6f0fb` |
| `tests/deployed_authority_service.py` | `4026ab0715ae892c063734621bc5cd7fd29b0fedeff604b38e578cbe1c3e87fc` |
| `tests/acceptance/phase9/test_gateway_boundary.py` | `a45f8efb1b80553beea9ea0dee5372d419dde1b9c99b0d9bf5150ed83f8a630d` |
| `src/governance_substrate/substrate.py` | `e7eb627610cc76f8073748893fec3af5d9f69d38009bc47108d5cdc8a0b66340` |
| `src/governance_substrate/audit_witness.py` | `0c1967c33a5db90157c463d2ebace1342f05b172b67e88d340eae4263c3ac0e8` |

### Verify the archived runs

Use the source at `9083118` in a Python environment with the project and its test dependencies installed (`python -m pip install ".[test]"`). From the repository root, extract the ZIP into a fresh `h001-evidence` directory and run the existing verifier with assertions enabled:

```text
python -m zipfile -e docs/evidence/H-001-evidence.zip h001-evidence
python -B tests/housing_referral.py --verify h001-evidence/d804377f2f058757
python -B tests/housing_referral.py --verify h001-evidence/7f10353f7508a107
```

If using a checkout of the original commit, supply the downloaded ZIP path on the first line. Each command invoking the verifier must exit zero and print the corresponding witness head from the table above. In a clean source export, both archived runs verified (60 events each); the same verifier rejected an altered copy of each audit. Archived records allow independent recomputation of chain and witness agreement. The stored witness responses are unsigned; offline verification alone cannot authenticate the historical witness or establish control of the original host.

To replay the workflow with fresh synthetic state, run `python -B tests/housing_referral.py --approved-referral-reason "Approve referral because the two memos conflict"`. Random IDs, timestamps and chain heads vary across runs.

## Scope of the correction

The [runtime](../../src/governance_substrate/substrate.py) binds an escalated persistent write to its originating session in trusted audit metadata. During the override transaction it checks the actor, originating session, task liveness and current circuit state. Historical events can use an unambiguous active session from the original snapshot. Ambiguous historical origins require a fresh proposal. The [regression test](../../tests/test_substrate.py) covers the missing binding and rejection after session replacement. The pre-fix failure demonstrated missing origin evidence; execution of a revoked write on the frozen build was not tested.

The remaining implementation changes support the fixture: configurable bind address and certificate directory on the witness function, retaining its deployment defaults, and extraction of the existing observer's chain-verification function for reuse.

## Regression validation

After the Docker Desktop restart, the Linux engine reported version 29.5.3 and resolved the local test image to `sha256:745e02605ef94b31c645b1c5eceedf290047d1783c33db393dd836415ccb5ec6`. Force-kill enforcement, protected-file overwrite denial, and protected-file read denial all passed (3/3 in 37.69 seconds). Each test produced a separate execution receipt. The complete default pytest invocation then finished with **203 passed, 27 skipped, 0 failed** in 118.45 seconds. Two dependency deprecation warnings were reported. The skipped tests require explicitly enabled environments or local model fixtures. The count describes the default suite, not every CI configuration.

Local validation artifacts are under `dist/housing-review/ready-20261123-162239/`. The Docker receipt index lists all three proof paths and hashes. Earlier logs remain available separately and document the HTTP 500 failures during engine startup. To repeat the default suite on the same local test setup, set `PYTHONPATH=src`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and `PYTHONDONTWRITEBYTECODE=1`, then run `python -B -m pytest -q -p no:cacheprovider`.

## Interpretation and limits

The result supports an external execution control for a human-approved referral in one configured workflow. Hierarchical task grants constrain capability categories and lifetime. Role configuration and object reader lists supply the resource-level constraints in this example. The transfer changed personnel within one registry version. Registry migration, general resource-subset inheritance and independent identity verification for human reviewers were outside this experiment.

The operator and witness processes share an administrative host. Human review was supplied once and replayed; the workflow did not measure legal reasoning, real-world decision quality, live-model behavior, production isolation, or resilience to host compromise. No regulatory compliance, legal correctness, government deployment or Stanford affiliation is claimed. The research question concerns the execution and accountability component of high-stakes professional workflows.
