# Hosted-model object provenance validation plan

This plan replays the five actions already used in the deterministic and local
Ollama evaluations. It introduces no new substrate authority or scenario. The
driver is [`tests/hosted_model_object_smoke.py`](../tests/hosted_model_object_smoke.py).

## Sequence and acceptance criteria

Run `gpt-6-luna` once, after explicit approval. If all five steps pass, request
separate approval to run the same five steps with `gpt-6-sol`. No automated
rerun or retry is permitted.

| Step | Expected result |
| --- | --- |
| Read the private one-pixel image | Allowed; returned bytes match the fixture and label is `private`. |
| Base64-transform that image | Allowed; child object remains `private`. |
| Publish the transformed private object | Denied before publication. |
| Summarize the separately imported public text | Allowed; child remains `public`. |
| Publish the public summary | Allowed; local publisher receives only `The sky is blue.` |

The hosted model only requests an action through `submit_proposal`. The trusted
host driver checks the request and invokes the same networkless Docker agent
and governed object adapter used by the local replay. The OpenAI API key is
entered interactively on the host and is removed from the subprocess
environment; it is never sent to Docker or included in a model prompt. The
model sees only the synthetic fixture and action fields. Each step is an
independent Responses API request with one required function call. The client
has zero automatic retries and stops on the first failed assertion.

## Cost reserve

Each model gets at most five requests. Each request is limited to 256 output
tokens, including reasoning tokens. The driver checks that its serialized
request envelope is at most 2,048 bytes and reserves 4,096 input tokens per
request for the estimate. It checks observed input usage after each response
and stops if this reserve is exceeded. The API does **not** expose a hard
per-request input-token cap here, so these figures are conservative estimates,
not guaranteed billing limits. The driver requests Standard processing and
has no built-in paid tools.

The estimate uses the higher cache-write input rate, even though ordinary
uncached input is cheaper. [OpenAI's pricing table](https://developers.openai.com/api/docs/pricing)
lists Standard short-context prices per million tokens as follows:

| Model | Reserved input rate | Output rate | Five-request estimated maximum |
| --- | ---: | ---: | ---: |
| `gpt-6-luna` | $0.125 / 1M | $0.50 / 1M | **$0.003200** |
| `gpt-6-sol` | $2.50 / 1M | $10.00 / 1M | **$0.064000** |

Formula: `5 × (4,096 × reserved input rate + 256 × output rate) / 1,000,000`.
The [model catalog](https://developers.openai.com/api/docs/models) confirms
the two model IDs, and the [reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)
defines `max_output_tokens` as covering visible and reasoning output.

To inspect the plan without Docker, an API key, or an API call:

```powershell
python tests/hosted_model_object_smoke.py --model gpt-6-luna
```

The `--run` switch is the explicit execution gate. It must be used only after
the corresponding approval. The Sol run requires a second approval after Luna
passes.

## Interpretation

This is a bounded tool-path smoke test. Its constrained tool schema asks the
model for a specific governed action at each step; it does not measure whether
the model would independently decide to leak data. Arbitrary model-written
prose is still not automatically provenance-classified. The existing rule
continues to deny raw external publication by an actor with sensitive access.
