# Local-model runtime matrix

Local verification, September 29, 2026. Branch: `test/local-model-matrix`.
The question is whether one governed Docker generation path works with two
independent local model families. This is a runtime and governance check, not
a comparison of model quality.

## Pinned artifacts

| Model | Official source and revision | Local GGUF SHA-256 |
| --- | --- | --- |
| Qwen 3 0.6B Q8_0 | [`Qwen/Qwen3-0.6B-GGUF`](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/blob/ef4088322893040952513f532f736ddeab518403/Qwen3-0.6B-Q8_0.gguf), `ef4088322893040952513f532f736ddeab518403` | `12fae8b8f78f0360b498d04c8db7d33aff29ab7d8080231f93a17c18119e6735` |
| Phi-4 Mini Instruct Q8_0 | [`microsoft/Phi-4-mini-instruct`](https://huggingface.co/microsoft/Phi-4-mini-instruct), `cfbefacb99257ffa30c83adab238a50856ac3083` | `3e81a3ad900b6d67df011d42ef14bad63354a3516fbd229b9bf29755363b25ee` |

Qwen's specified SHA-256 belongs to an earlier official Qwen revision; the
repository's current file has a different hash. Phi is Microsoft's MIT-licensed
model. Its official weight shards were verified before conversion:

- `model-00001-of-00002.safetensors`: `bc703090b63eda16f639fa4de7ac54635c23105ab1da2f6ec4d3403151d38ee6`
- `model-00002-of-00002.safetensors`: `7ff79b9d2d31076bac2663393451f6530f4fc8ca49b09002116c92c373dba983`

The conversion used official [`ggml-org/llama.cpp`](https://github.com/ggml-org/llama.cpp/tree/4df29be4f4c3673f428170fda944a5b19f743bb8)
commit `4df29be4f4c3673f428170fda944a5b19f743bb8`, the commit vendored by
the pinned `llama-cpp-python==0.3.35` package, with `--outtype q8_0`. The
resulting Phi GGUF is 4,084,611,392 bytes. Both model files remain local and
ignored by Git.

## Identical governed path

The `Dockerfile.generation` package pin, `local_generation_worker.py`,
`compose.local-generation.yaml`, substrate, supervisor, sealed input objects,
prompts, and acceptance assertions were unchanged. Only
`GENERATION_MODEL_BLOB` changed between the two runs. The acceptance fixture
checks each file's name, size, and SHA-256 before building the same worker
image. Live worker inspection checks that the sole bind mount is the read-only
`/model/model.gguf` path for both runs.

The same four acceptance tests ran with each artifact. Three exercise the local
generation path: real inference returns a governed private object with exact
parents; an operator circuit trigger stops and removes the exact running
container and rejects late completion; and supervisor restart finds and
removes an orphaned worker. The fourth checks that an unauthorized third-party
service reachable by the substrate remains inaccessible to the agent. That
network-scope test is model-independent but ran in the identical acceptance
command for each leg.

| Local leg | Command scope | Result |
| --- | --- | --- |
| Qwen | `tests/acceptance --ignore=tests/acceptance/environment` | 4 passed, 0 skipped, 2 pre-existing Pydantic warnings, 42.93 s |
| Phi | Same command and assertions | 4 passed, 0 skipped, 2 pre-existing Pydantic warnings, 71.38 s |

The [environment skeleton](Environment-Skeleton-Evaluation.md) is separate
runtime-isolation evidence. It was not counted twice merely because the model
file changed. Its separate Docker probe run passed 5/5; the normal unit suite
passed 76 with 10 opt-in skips.

## CI and limits

GitHub Actions runs the Qwen local-model acceptance job automatically on pushes
and pull requests. A separate manual `workflow_dispatch` job prepares Phi from
the pinned official Microsoft weights and converter before running the same
acceptance command. Each job reports its result separately. The [automatic CI
run for `8a57af8`](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36613632007)
passed the Qwen acceptance, environment-probe, and unit jobs on Linux. The
manual Phi CI job has not been run; its result above is from local real Docker.

The originally proposed `meta-llama/Llama-3.2-3B-Instruct` leg was blocked by
an HTTP 403 on an official weight shard. It was not a failed governance or
model-runtime validation. No Meta weights, community GGUF, hosted model, or
paid API were used for this matrix.

This result covers the tested Docker configuration and these two pinned model
files. It does not assess model quality or attest to other hosts and runtime
backends. The substrate API remains runtime-neutral; Docker/OCI is the current
reference enforcement backend.
