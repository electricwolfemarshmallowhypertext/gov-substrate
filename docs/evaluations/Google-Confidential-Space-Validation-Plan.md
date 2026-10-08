# Google Confidential Space validation report

**Status: completed real-cloud acceptance for Qwen and Phi, 4/4 cases each.**
The trusted driver verified authentic Google Confidential Space attestation
before releasing governed public test input. Each valid case ran real remote
inference and accepted a signed result as a governed object. For each model,
wrong nonce, wrong image measurement, and wrong model hash were rejected before
input release. The VMs were stopped and verified `TERMINATED` after testing.
This is evidence for this measured workload and test configuration, not for
ordinary OpenAI, Anthropic, Gemini, or OpenRouter providers; those remain
`hosted_opaque` without independently verifiable execution evidence.

| Model | Pinned image digest | Valid remote inference | Wrong nonce | Wrong image | Wrong model hash |
| --- | --- | --- | --- | --- | --- |
| Qwen3-0.6B Q8_0 | `sha256:deb5a7d649d28b2be75dcea922131da7e351582dc505327632844e3548ce4d75` | PASS | PASS | PASS | PASS |
| Phi-4 Mini Q8_0 | `sha256:e3c5377a86660ad406ca4d4a850747724a376a268502c89323730f90dc04b589` | PASS | PASS | PASS | PASS |

Phi ran on a VM whose `gov-sub-qwen-attested` name was stale; its workload
metadata selected the pinned Phi image digest. A later correctly named Phi VM
was stopped without another test run. Both workloads used the same governance
assertions. The cloud-resource deletion status was not independently verified
after the Google APIs were disabled; termination of the VMs was verified.

## Fixed test target

| Item | Tested value |
| --- | --- |
| Service | Google Compute Engine Confidential Space production image and Google Cloud Attestation; Artifact Registry held two workload images |
| Hardware | AMD SEV Confidential VM, `n2d-standard-4` (4 vCPU, 16 GiB), CPU inference only |
| Zone | `us-west1-b`; `us-central1-a` and `us-central1-b` lacked capacity during setup |
| Workload | One OCI image for Qwen and one for Phi, built from the same `deploy/confidential-space/Dockerfile` and `confidential_space_worker.py` |
| Qwen artifact | Official `Qwen/Qwen3-0.6B-GGUF` Q8_0 file, SHA-256 `12fae8b8f78f0360b498d04c8db7d33aff29ab7d8080231f93a17c18119e6735` |
| Phi artifact | Official `microsoft/Phi-4-mini-instruct` weights converted with the already pinned `llama.cpp` revision, Q8_0 output SHA-256 `3e81a3ad900b6d67df011d42ef14bad63354a3516fbd229b9bf29755363b25ee` |

The image digests above were pinned in the provider grants. Model artifacts
were checked against the listed hashes before image build and by the measured
worker at startup. Governance and test assertions were shared across models.

The worker served HTTPS through an IAP tunnel. Each image contained a throwaway
test certificate and key, so TLS was not the trust root for governed input.
The trusted driver independently encrypted input to a fresh workload-generated
exchange key bound into the Google-verified attestation token. Neither model
artifact was downloaded by the worker. The completed case matrix was identical
for Qwen and Phi:

1. Valid Google-signed attestation, pinned image and model hashes, one governed
   request, real local inference inside the remote workload, signed result,
   and accepted governed output.
2. Wrong nonce: no governed bytes transmitted.
3. Wrong pinned image/runtime measurement: no governed bytes transmitted.
4. Wrong pinned model hash: no governed bytes transmitted.

The negative cases changed the substrate's expected policy while using the
live workload and authentic Google tokens. The trusted driver recorded zero
governed-input releases for each rejected case. No synthetic token or mock
is counted in the results above.

## Evidence boundary

The valid cases prove that this substrate path withheld input until it verified
the Google token and expected workload/model binding, then accepted a signed
result from real inference. The negative cases prove those three mismatches
were denied before input release in the tested cloud configuration. This does
not prove general hosted-provider internals or semantic correctness of the
model output. Actual cloud charges and resource deletion were not independently
verified in this report.

References: [Confidential Space deployment](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads),
[token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims),
[external relying-party verification](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources).
