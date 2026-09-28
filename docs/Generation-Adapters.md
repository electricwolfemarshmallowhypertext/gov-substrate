# Generation adapters

Governance Substrate does not require a particular model or provider. A
generation begins with `generation.prepare`, which accepts an ordered list of
governed object IDs and, for hosted generation, a provider service ID.
Instructions and source material must both be governed objects. The substrate
verifies access, seals their bytes and hashes, and fixes the output
classification to the highest input classification. Hosted transfer is denied
by default. A registered provider may receive only inputs at or below its
configured maximum classification. The allow or deny event records the
provider, input IDs and hashes, and highest classification. An unregistered
provider or an input above its grant is denied before any API call. Local
generation omits `provider` and needs no external-transfer grant.

The trusted host then calls `run_with_adapter`. This claims the manifest once,
checks the hashes, passes the exact ordered inputs to an adapter, and returns
the adapter's text to `/generations/complete`. The substrate stores the text as
a new governed object with the sealed parents and label. The adapter cannot
set its own classification or parents. Publication still requires a governed
`public` object.

## Add to an existing agent stack

Keep the agent's provider key and the substrate operator credential in the
trusted host application. The agent should receive neither credential. At the
point where the agent would otherwise call a model directly, have it propose
`generation.prepare` with the governed object IDs and hosted provider. For
example, OpenAI uses
`{"kind": "generation.prepare", "input_ids": [prompt_id, source_id], "provider": "openai"}`.
Only an allowed proposal returns a `generation_id`. Pass that ID to the host:

```python
from generation_adapter import run_with_adapter
from hosted_generation_adapters import OpenAITextAdapter

provider = OpenAITextAdapter(
    client=openai_client, model=selected_model, max_output_tokens=256,
    service_id="openai")
result = run_with_adapter(substrate_client, generation_id,
                          operator_token, provider)
generated_object_id = result["object_id"]
```

For Anthropic, replace the adapter construction:

```python
from hosted_generation_adapters import AnthropicTextAdapter

provider = AnthropicTextAdapter(
    client=anthropic_client, model=selected_model, max_output_tokens=256,
    service_id="anthropic")
```

The application supplies already configured official SDK clients. Install
`.[llm]` or `.[anthropic]` only for the provider it uses. Models are selected
by the host application; the substrate does not substitute one. Any new
provider can implement `generate(inputs) -> str`, declare its registered
`service_id`, and use the same `run_with_adapter` function. The optional local
Docker adapter uses this same
handoff through `run_local_generation`; hosted adapters do not require Docker.

The registry's optional `providers` mapping defines grants. For a new
deployment, a public-only OpenAI service can be configured as:

```yaml
providers:
  openai: {max_classification: public}
```

The labels are ordered `public < internal < private < restricted`. With no
`providers` mapping, every hosted request is denied. The registry is sealed
by the existing integrity check; changing grants on an initialized database
fails closed until an audited registry migration is performed.

These adapters currently accept UTF-8 `text/plain` inputs only. They reject
unsupported media, oversized input, incomplete responses, and unexpected tool
or non-text output. The OpenAI adapter uses one stateless Responses request
with `store=False` and truncation disabled. The Anthropic adapter uses one
Messages request with a single user turn. Both pass separate text blocks in
the sealed order, add no system instruction or previous conversation, and
disable SDK retries for that request. Every API request can incur charges;
the repository tests use fake clients and make no provider calls.

## Boundary

The substrate authorizes hosted transfer against the sealed input labels and
registered service before the trusted host calls the provider. The host holds
credentials and supplies the exact request fields and governed bytes.
**Sending a private or restricted object to a hosted provider is itself an
external disclosure**, so it requires a provider grant at that level. The
adapter cannot claim a run prepared for a different provider. A claimed
manifest cannot be replayed if a provider call fails.

The substrate can verify the context it supplied and the output object it
records. It cannot attest to a hosted provider's internal runtime, retention,
or any context that provider might add internally. The optional local worker
provides a stronger runtime boundary in the documented container setup.

API request shapes follow the official [OpenAI Responses API](https://developers.openai.com/api/docs/guides/text)
and [Anthropic Messages API](https://platform.claude.com/docs/en/api/python/messages/create).
