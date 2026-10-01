# Kubernetes Runtime Evaluation

## Result

Phase 7 adds a Kubernetes implementation of the existing runtime-neutral
supervisor contract. The same real suite passed in both target environments:

| Environment | Supervisor conformance | Runtime enforcement |
| --- | ---: | ---: |
| Kind 0.33.0 / Kubernetes 1.36.4 / Calico 3.32.2 | 3 passed | 2 passed |
| GKE Autopilot / Kubernetes 1.35.8 | 3 passed | 2 passed |

The completed job and sanitized runtime manifest are in the
[Phase 7 CI run](https://github.com/electricwolfemarshmallowhypertext/gov-substrate/actions/runs/36761111887).
The job used real Kubernetes Pods, the real substrate, the real supervisor, and
the same hostile Rust worker and shared assertions used by the other backends.
It used no mocked Kubernetes client, fake stop result, model, or paid model API.
The managed run used code commit
`5a30f704bc8ab06e58747226989dba7fd084a628`; its sanitized manifest is
[`evaluation/results/kubernetes-managed-gke.json`](../evaluation/results/kubernetes-managed-gke.json).

## Recorded environment

- GitHub-hosted Ubuntu 24.04.5, Linux `6.17.0-1022-azure`, x86_64
- runner image `ubuntu24` version `20260920.314.1`
- Kind `0.33.0`
- Kubernetes client and server `1.36.4`
- two Debian 13 Kind nodes using containerd `2.3.4`
- Calico `3.32.2`, with both node agents running
- namespace Pod Security enforcement: `restricted`, version `v1.36`
- namespace NetworkPolicy: deny all ingress and egress
- worker image supplied by immutable SHA-256 digest

The managed repetition recorded:

- GKE Autopilot in `us-central1`
- Kubernetes server `1.35.8-gke.1225000`
- Container-Optimized OS node, Linux `6.12.94+`
- containerd `2.2.7`
- namespace Pod Security enforcement: `restricted`, version `v1.35`
- namespace NetworkPolicy: deny all ingress and egress
- the same immutable probe image digest

The temporary managed cluster and Artifact Registry repository were deleted
immediately after the assertions passed. The account and ephemeral node
identifiers are redacted from the committed manifest.

The CI job verified official Kind, kubectl, and Calico downloads before use,
recorded the environment before the assertions ran, and removed the disposable
cluster afterward.

## Worker boundary

`KubernetesRuntimeSupervisor` launches one Pod per generation. Before creation,
it verifies that the namespace enforces restricted Pod Security and contains
the expected deny-all ingress and egress NetworkPolicy. The worker Pod has:

- no service-account token or Kubernetes API credential;
- no host network, PID, or IPC namespace;
- no service-link environment injection;
- no inherited provider or host environment;
- non-root UID and GID 65534;
- `RuntimeDefault` seccomp;
- a read-only root filesystem;
- all Linux capabilities dropped;
- privilege escalation disabled;
- explicit CPU, memory, process-lifetime, and ephemeral-storage bounds;
- fresh size-limited `/tmp` and memory-backed `/dev/shm` volumes; and
- an optional model PVC mounted read-only.

The supervisor accepts only digest-pinned worker images. A generation is bound
to the exact Pod UID returned by the Kubernetes API. Stop operations use that
UID as a deletion precondition, wait until the Pod is absent, and reject a Pod
name that reappears with a different UID. Reconciliation lists only Pods with
the deployment owner and managed labels and applies the same exact-identity
stop path.

## Shared proof

The unchanged shared suite proved that the Kubernetes backend:

1. launched a real untrusted worker Pod;
2. supplied only sealed governed context;
3. returned output as a governed object with exact parents and inherited classification;
4. rejected altered and replayed execution grants;
5. stopped the exact Pod during a circuit trip and verified removal;
6. rejected late completion from the stopped worker;
7. reconciled a labeled orphan after supervisor restart;
8. blocked the probed network, filesystem, process, IPC, socket, secret, and persistence paths; and
9. preserved sealed standard input plus fresh private temporary storage.

For the network assertion, a real target Pod and Service existed in the same
cluster. The trusted test harness reached the target through Kubernetes
port-forwarding, while the worker's real connection attempt to the Service IP
was denied by the active cluster network-policy enforcement.

## Defect exposed during real execution

The first CI run loaded the probe image into Kind under a mutable local tag but
started the Pod with the required digest reference. Containerd did not associate
that digest-qualified name with the imported tag, so kubelet attempted a
registry pull and reported `ImagePullBackOff`. This was test-cluster image
provisioning failure before worker execution, not a substrate decision failure.

The CI setup now registers the already loaded image under the exact immutable
digest reference on every Kind node. The supervisor requirement was not
weakened. After that correction, the same shared suite passed **3 + 2**.

The first GKE Autopilot attempt exposed a second real portability defect.
Autopilot adjusted the worker's small CPU, memory, and ephemeral-storage
requests after admission. The supervisor compared the complete admitted
container shape with its expected manifest and rejected the mutated Pod before
worker execution.

The supervisor now requests the exact values GKE admitted: `50m` CPU, `52Mi`
memory, and `10Mi` ephemeral storage, with the existing CPU and memory limits
and a `10Mi` ephemeral-storage limit. Exact post-admission comparison remains
enabled for the complete resource block and every isolation field. No mutation
is ignored. The unchanged shared suite then passed **3 + 2** on GKE.

## Limits

This evidence applies only to the recorded disposable Kind/Calico and GKE
Autopilot configurations. It does not prove other managed Kubernetes services,
Kubernetes or CNI versions, admission controllers, service meshes, node
hardening, workload identity, cloud metadata policy, or registry
configurations. NetworkPolicy enforcement depends on the installed cluster
network implementation. The trusted kubeconfig, Kubernetes API server, cluster
control plane, nodes, container runtime, kernel, supervisor, and substrate
remain inside the trusted computing base.
