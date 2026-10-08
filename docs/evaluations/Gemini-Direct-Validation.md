# Direct Gemini validation report

On 2026-09-29, `gemini-3.8-flash` completed the bounded direct-Google
validation after the user resolved a billing-account issue. The successful run
used two Google API requests, with no retries. The substrate's provider grant,
sealed-context provenance, and publication decisions met all three acceptance
criteria.

## Governed outcomes

| Scenario | Observed result | Google API requests |
| --- | --- | ---: |
| Private input, public-only provider grant | Denied with `provider_classification_denied` before transfer | 0 |
| Private input, explicit private provider grant | Generation succeeded; output was `private` with the sealed prompt and private source as parents; publication denied | 1 |
| Clean public input after private generation | Generation succeeded; output was `public` with the sealed prompt and public source as parents; publication succeeded | 1 |

The public output came from the same actor after its private generation. Its
classification followed the inputs to that specific generation, rather than
the actor's earlier history. No generated text or credential was printed.

The driver calculated 20 input, 200 output (including 190 thinking) tokens
for the private generation and 19 input, 120 output (including 115 thinking)
tokens for the clean public generation from Google's usage metadata. Totals
were **39 input and 320 output tokens**.
At the documented introductory Standard rates, the calculated cost for this
successful run is **$0.00122925**. This is a calculation from reported usage,
not a verified billing charge. The earlier two HTTP 503 attempts returned no
token usage, so their exact billing impact is unknown.

## Execution boundary

The [driver](../../tests/gemini_direct_smoke.py) used synthetic text fixtures, a
real in-process substrate, and a local HTTP publication fixture. It sent the
substrate-sealed text directly to Google's `generateContent` endpoint from the
trusted host. `GEMINI_API_KEY` remained in the trusted host's PowerShell/Python
environment and was not passed to Docker or printed. The adapter added no
conversation history, external tools, or extra prompt. Provider-transfer
authorization occurred before the first model call. The substrate stored both
responses as governed objects with inherited classifications and exact sealed
parents.

The same driver first ran twice and received HTTP 503 on the first Google
request each time. Both runs stopped immediately, after the pre-API denial.
They did not produce model output or exercise publication. These were provider
HTTP failures, not substrate denials or failed governance assertions. After the user
resolved the billing-account issue, the unchanged driver and model completed
the successful run above. The first two attempts are not counted as passes.

Deterministic fake-client tests covered adapter request construction and
governance logic. The non-acceptance test suite passed **83 tests**, with 10
skipped and two existing Pydantic deprecation warnings. These logic tests are
separate from the successful direct-Google run. The validation does not attest
to Google's internal runtime, retention, or undisclosed context.

Google's [model documentation](https://ai.google.dev/gemini-api/docs/generate-content/latest-model)
identifies `gemini-3.8-flash` and its introductory pricing. The
[API error guide](https://ai.google.dev/gemini-api/docs/api-errors) describes
HTTP 503 as service unavailable; the responses alone did not establish the
precise cause of the initial failures.
