# Governance Substrate v0.7.1

2026-11-23

Evaluated implementation: `908311810edd7a086aa37a9d43faa56b1924a9ac`.

- An operator can approve an escalated persistent write only while the originating authority remains live. The runtime checks the original actor's session, task liveness and circuit state in the override transaction. A stale approval is denied and audited.
- In two scripted H-001 housing referrals, the analyst's closure request was denied, the approved referral persisted, and a replacement analyst continued after revocation. Both runs used the same human decision. All 120 recorded events matched their respective witness histories, with zero provider calls. [Evaluation and verification instructions](../evaluations/Housing-Referral-Evaluation.md) · [Evidence ZIP](../evidence/H-001-evidence.zip)
- The Linux force-kill, protected-file read and protected-file overwrite checks passed. The full default suite recorded 203 passes, 27 environment-gated skips and zero failures.
- Since v0.7.0, OpenShell CI prepares pinned images before gateway startup. The worker also submits overflow tool calls for authorization and audit without executing them. These changes predate the housing evaluation.

The housing evaluation measures operational authorization in one synthetic workflow on a shared administrative host. Live-model behavior, legal correctness and regulatory compliance were outside its scope.
