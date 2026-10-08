# OpenRouter validation report

On 2026-09-29, `z-ai/glm-5.2` completed the bounded OpenRouter
validation through the pinned Z.AI upstream. The successful run used two model
API requests, with no retries or fallback provider. The substrate's provider
grant, sealed-context provenance, and publication decisions met all three
acceptance criteria.

## Governed outcomes

| Scenario | Observed result | Model API requests |
| --- | --- | ---: |
| Private input, public-only OpenRouter grant | Denied with `provider_classification_denied` before transfer | 0 |
| Private input, explicit private OpenRouter grant | Generation succeeded through Z.AI; output was `private` with the sealed prompt and private source as parents; publication denied | 1 |
| Clean public input after private generation | Generation succeeded through Z.AI; output was `public` with the sealed prompt and public source as parents; publication succeeded | 1 |

The public output came from the same actor after its private generation. Its
classification followed the exact inputs to that generation rather than the
actor's earlier history. The driver did not print generated text or the API
credential.

OpenRouter reported 31 input and 302 output tokens, including 293 reasoning
tokens, for the private generation. It reported 29 input and 147 output tokens,
including 142 reasoning tokens, for the clean public generation. The successful
run therefore used **60 input and 449 output tokens**. OpenRouter reported a
total cost of **$0.0020596**.

## Routing boundary

The [driver](../../tests/openrouter_direct_smoke.py) used synthetic text fixtures,
a real in-process substrate, and a local HTTP publication fixture. It sent the
substrate-sealed text from the trusted host to OpenRouter with these fixed
routing controls:

- model: `z-ai/glm-5.2`
- allowed upstream: `z-ai` only
- fallback providers: disabled
- provider data collection: denied
- zero-data-retention routing: required

The adapter required OpenRouter's response metadata to identify exactly one
selected upstream and to name Z.AI. A missing or different selection fails
closed. `OPENROUTER_API_KEY` remained in the trusted host's PowerShell/Python
environment and was not passed to an agent or Docker.

OpenRouter is an intermediary between the trusted host and Z.AI. This run
confirms the routing metadata and governed inputs observed at the adapter
boundary. It does not attest to OpenRouter's or Z.AI's internal runtime,
retention, or undisclosed context.

## Preceding stopped attempts

An earlier request used a 256-token output limit and returned a normal API
response with `finish_reason="length"`. The adapter rejected it before
completion was recorded. This was an under-provisioned test envelope for the
reasoning model, not a substrate decision failure. The output limit was raised
to 2048 without changing the model, routing, scenarios, policy, or governance
assertions.

A later attempt stopped on HTTP 401 because that temporary OpenRouter key had
expired. OpenRouter's current-key endpoint also returned 401. No inference
completed in that attempt. This was a provider credential failure, not a
substrate failure.

Deterministic fake-client tests cover request construction, strict upstream
selection, safe error reporting, key-limit metadata, and the same three
governed outcomes. Those tests establish adapter and policy logic; they are
separate from the successful live OpenRouter run.

References: [OpenRouter chat completions API](https://openrouter.ai/docs/api/api-reference/chat/create-a-chat-completion),
[provider routing and privacy controls](https://openrouter.ai/blog/insights/ai-data-residency/),
and [`z-ai/glm-5.2` on OpenRouter](https://openrouter.ai/z-ai/glm-5.2).

The same bounded replay subsequently passed with
[`x-ai/grok-4.7`](OpenRouter-Grok-4.7-Validation.md) and
[`moonshotai/kimi-k3`](OpenRouter-Kimi-K3-Validation.md), each pinned to its
direct upstream.
