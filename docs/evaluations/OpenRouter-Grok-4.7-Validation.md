# OpenRouter Grok 4.7 validation report

On 2026-09-29, `x-ai/grok-4.7` completed the bounded OpenRouter
validation through the pinned xAI upstream. The successful run used two model
API requests, with no retries or fallback provider. The substrate's provider
grant, sealed-context provenance, and publication decisions met all three
acceptance criteria.

## Governed outcomes

| Scenario | Observed result | Model API requests |
| --- | --- | ---: |
| Private input, public-only OpenRouter grant | Denied with `provider_classification_denied` before transfer | 0 |
| Private input, explicit private OpenRouter grant | Generation succeeded through xAI; output was `private` with the sealed prompt and private source as parents; publication denied | 1 |
| Clean public input after private generation | Generation succeeded through xAI; output was `public` with the sealed prompt and public source as parents; publication succeeded | 1 |

The public output came from the same actor after its private generation. Its
classification followed the exact inputs to that generation rather than the
actor's earlier history. No generated text or credential was printed.

OpenRouter reported 1,260 input and 998 output tokens, including 984 reasoning
tokens, for the private generation. It reported 1,260 input and 124 output
tokens, including 119 reasoning tokens, for the clean public generation. The
successful run therefore used **2,520 input and 1,122 output tokens**.
OpenRouter reported a total cost of **$0.008316**.

## Routing and privacy

The [shared OpenRouter driver](../../tests/openrouter_direct_smoke.py) used
synthetic text fixtures, a real in-process substrate, and a local HTTP
publication fixture. It used these fixed settings:

- model: `x-ai/grok-4.7`
- allowed upstream: xAI only (`xai`)
- fallback providers: disabled
- provider data collection: denied
- zero-data-retention routing: not required
- documented upstream retention: 30 days
- output limit: 2,048 tokens per request

The adapter required OpenRouter's response metadata to identify exactly one
selected upstream and to name xAI. A missing or different selection fails
closed. The successful response identified `xAI` for both requests.
`OPENROUTER_API_KEY` remained in the trusted host's PowerShell/Python
environment and was not passed to an agent or Docker.

The test did not claim zero retention. OpenRouter's provider directory listed
xAI with 30-day retention when the run was prepared. The run therefore proves
the tested governance path under that disclosed transfer condition; it does
not prove provider-side non-retention.

No provider failure occurred during the successful run. OpenRouter remains an
intermediary between the trusted host and xAI. The run confirms the routing
metadata and governed inputs observed at the adapter boundary, not either
provider's internal runtime or undisclosed context.

References: [`x-ai/grok-4.7` on OpenRouter](https://openrouter.ai/x-ai/grok-4.7),
[OpenRouter providers](https://openrouter.ai/providers/), and
[OpenRouter routing controls](https://openrouter.ai/blog/insights/ai-data-residency/).
