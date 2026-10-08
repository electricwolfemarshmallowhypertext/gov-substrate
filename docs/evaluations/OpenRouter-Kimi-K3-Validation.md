# OpenRouter Kimi K3 validation report

On 2026-09-29, `moonshotai/kimi-k3` completed the bounded OpenRouter
validation through the pinned Moonshot AI upstream. The successful run used two
model API requests, with no retries or fallback provider. The substrate's
provider grant, sealed-context provenance, and publication decisions met all
three acceptance criteria.

## Governed outcomes

| Scenario | Observed result | Model API requests |
| --- | --- | ---: |
| Private input, public-only OpenRouter grant | Denied with `provider_classification_denied` before transfer | 0 |
| Private input, explicit private OpenRouter grant | Generation succeeded through Moonshot AI; output was `private` with the sealed prompt and private source as parents; publication denied | 1 |
| Clean public input after private generation | Generation succeeded through Moonshot AI; output was `public` with the sealed prompt and public source as parents; publication succeeded | 1 |

The public output came from the same actor after its private generation. Its
classification followed the exact inputs to that generation rather than the
actor's earlier history. No generated text or credential was printed.

OpenRouter reported 103 input and 382 output tokens, including 342 reasoning
tokens, for the private generation. It reported 102 input and 79 output tokens,
including 59 reasoning tokens, for the clean public generation. The successful
run therefore used **205 input and 461 output tokens**. OpenRouter reported a
total cost of **$0.007530**.

## Routing and privacy

The [shared OpenRouter driver](../../tests/openrouter_direct_smoke.py) used
synthetic text fixtures, a real in-process substrate, and a local HTTP
publication fixture. It used these fixed settings:

- model: `moonshotai/kimi-k3`
- allowed upstream: Moonshot AI only (`moonshotai`)
- fallback providers: disabled
- provider data collection: denied
- zero-data-retention routing: required
- documented upstream retention: zero retention
- output limit: 2,048 tokens per request

The adapter required OpenRouter's response metadata to identify exactly one
selected upstream and to name Moonshot AI. A missing or different selection
fails closed. The successful response identified `Moonshot AI` for both
requests. `OPENROUTER_API_KEY` remained in the trusted host's
PowerShell/Python environment and was not passed to an agent or Docker.

No provider failure occurred during the successful run. OpenRouter remains an
intermediary between the trusted host and Moonshot AI. The run confirms the
routing metadata and governed inputs observed at the adapter boundary, not
either provider's internal runtime or undisclosed context.

References: [`moonshotai/kimi-k3` on OpenRouter](https://openrouter.ai/moonshotai/kimi-k3),
[Moonshot AI on OpenRouter](https://openrouter.ai/provider/moonshotai), and
[OpenRouter routing controls](https://openrouter.ai/blog/insights/ai-data-residency/).
