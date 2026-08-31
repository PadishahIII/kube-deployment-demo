# kube-security — Design Document

A single-node kind cluster that demonstrates **defense-in-depth Kubernetes security**,
gated by a **Jenkins policy gate** — CI tests the Kyverno policies and every
developer-contributed tenant manifest, then installs the policy set — while **Kyverno**
enforces admission in-cluster. **Deployment (CD) is deliberately out of scope**: this is
a policy-gate demo owned by the cluster operator, not an operations demo (§13).

This document is the source of truth for the repo layout, the security controls, and
the gate design. `SETUP_DEMO.md` covers environment setup; `README.md` covers usage.

---

## 1. Goals

1. **Show, don't tell.** Every security control has a *demonstrable failure mode*:
   a non-compliant pod is rejected with a readable message, an unverified image is
   blocked, a cross-tenant request is denied, an anonymous kubelet request gets a 401.
2. **The gate is the only trusted path for policy.** Policies and tenant deployment
   manifests live in this repo; nothing is installed in the cluster, and nothing is
   mergeable, unless it clears the gate's checks first. Images are produced by the
   application repo's pipeline (build → trivy scan → cosign sign → push — out of scope
   here; SETUP_DEMO.md shows how to produce the demo signed images). Deploying is the
   cluster operator's own concern — but whatever gets deployed, by whoever, is still
   validated by Kyverno at admission.
3. **Multi-tenant realism.** Two tenant namespaces with isolated RBAC, network
   policies, and service accounts — the policies apply to tenants, not to the
   platform namespaces (a realistic two-tier governance model).
4. **Testable policies.** Every Kyverno policy has offline unit tests (`kyverno test`)
   that run in CI before anything touches a cluster.

## 2. Scope

| In scope | Out of scope (see §13) |
| --- | --- |
| Kyverno admission policies (13) + unit tests | DAST (covered by sibling repo `devsecops-demo`) |
| Image governance **as a gate can enforce it**: trust list, digest pinning, attestation-annotation + digest-match checks | Image build/push/scan pipeline — the application repo's job (SETUP_DEMO.md shows how to produce the demo signed images); cosign verify itself is a deploy-time concern |
| Developer-owned Helm chart (`resources/helm/`) rendered + checked by the gate | **CD / deployment pipeline** — the cluster operator's job (§13; the demo's former `Jenkinsfile.cd` lives only in git history) |
| Multi-tenant namespaces, RBAC, NetworkPolicies | PodSecurityAdmission labels (mentioned as alternative) |
| External API authentication (OIDC via dex) | Node hardening beyond kind defaults (kube-bench used for evidence) |
| Kubelet access restriction + verification | Secrets management (SOPS/SealedSecrets), GitOps (ArgoCD) |
| Jenkins CI = **the policy gate**: policy tests + manifest conformance + IaC scan + **policy install** | Gate framework (sibling repo) — this repo hardcodes failure gates (tool exit codes) |

## 3. Architecture

```
   app repo pipeline (OUT OF SCOPE — see SETUP_DEMO.md):
   build → trivy image scan (CRITICAL,HIGH) → cosign sign → push docker.io/padishahiii/*

                            developer PR: policies / chart / values-<tenant>.yaml
  git push                ┌──────────────── Jenkins (local, :8081) ────────────────────┐
  ┌────────┐  gate        │            workflows/Jenkinsfile.ci = THE POLICY GATE       │
  │ GitHub │─────────────▶│  ┌──────────────────────────────────────────────────────┐   │
  │  repo  │  (PR check)  │  │ policy unit tests  : kyverno test tests/policies     │   │
  └────────┘              │  │ policy conformance : render values-<tenant>.yaml →   │   │
                          │  │   kyverno apply policies/ -r <rendered>  (dev's app  │   │
                          │  │   manifests must pass all 13 policies)               │   │
                          │  │ IaC scan           : trivy config --exit-code 1      │   │
                          │  │ policy schema lint : kubectl apply --dry-run=server  │   │
                          │  │ POLICY INSTALL     : kubectl apply -f policies/      │   │
                          │  │   + wait Ready  ← only path by which policy ships    │   │
                          │  └───────────────────────────────┬──────────────────────┘   │
                          └──────────────────────────────────┼──────────────────────────┘
                                                             ▼
   ┌──────────────────────────────────────────────────────────────────────────────────┐
   │  kind cluster (single node)                                                      │
   │                                                                                  │
   │  kube-apiserver : --oidc-issuer-url=http://dex.platform.svc:5556                 │
   │                   --authorization-mode=Node,RBAC                                 │
   │  kubelet        : anonymous auth OFF · read-only port 0 · webhook authorization  │
   │                                                                                  │
   │  Kyverno (kyverno ns) ── 13 ClusterPolicies, Enforce, scoped to ns label         │
   │        │                             tenancy.io/tenant                           │
   │        └─ admission-validates every Pod created by ANY path                      │
   │          (the operator's CD, kubectl, a controller — the gate is not in the       │
   │           request path; the policies it installed are)                           │
   │                                                                                  │
   │   platform ns          tenant-a ns                 tenant-b ns                   │
   │   ┌───────────┐        ┌──────────────────┐        ┌──────────────────┐          │
   │   │ dex (OIDC)│        │ shop  :8080      │        │ analytics :9090  │          │
   │   │  :5556    │        │ PVC /data (logs) │        │ PVC /data        │          │
   │   └───────────┘        │ SA: shop         │        │ SA: analytics    │          │
   │                        │ NetPol deny-all  │        │ NetPol deny-all  │◀── allow │
   │                        │  +allow-dns      │        │  +allow-dns      │   a→:9090│
   │                        │  +allow-same-ns  │        │  +allow-from-a   │          │
   │                        └──────────────────┘        └──────────────────┘          │
   │                                                                                  │
   │  rogue: resources/admission/pod.attacker.yaml (bitnami/kubectl, root, no ctx)    │
   │          └─▶ REJECTED at admission: image not in governed trust list (+9 rules)  │
   └──────────────────────────────────────────────────────────────────────────────────┘
```

**Control flow — a policy change or a new app deployment:**

1. The application repo's pipeline builds the distroless image, Trivy-scans it
   (fail on CRITICAL/HIGH), cosign-signs it, and pushes it to the governed registry
   (`docker.io/padishahiii/*`). Out of scope for this repo — SETUP_DEMO.md walks
   through exactly this for the demo apps ("Producing the demo signed images").
2. A developer opens a PR against this repo: policies, chart, `values-<tenant>.yaml`
   (carrying their digest-pinned image + attestation annotations), or plain manifests.
3. **The gate runs** (`Jenkinsfile.ci`): policy unit tests, conformance (render the
   developer's chart values and apply every policy to the result), the Trivy IaC scan,
   and the server-side schema lint. Any non-zero exit blocks the merge.
4. **The gate installs the policies** — `kubectl apply -f policies/` + wait for
   `Ready`. This is the policy execution stage: only policies that linted clean and
   passed their tests reach the cluster. Violation paths are proven offline by
   `kyverno test`, not re-asserted in-cluster.
5. The cluster operator — **outside this demo** — deploys the gate-passed manifests
   with whatever tooling they run, verifying the image signature at deploy time.
6. **Kyverno validates every Pod at admission** — the attestation annotations, image
   digest, and security contexts must satisfy all 13 policies or the Pod is rejected,
   no matter who applied it.
7. Operator-side evidence (`tests/verify.sh`, positive-only, run once workloads
   exist): PolicyReports, RBAC `can-i` matrix, kubelet anonymous-access check,
   NetworkPolicy behaviour.

## 4. Multi-tenant model

| Namespace | Label `tenancy.io/tenant` | Contents |
| --- | --- | --- |
| `platform` | — | dex (OIDC provider). Managed by platform team, outside tenant policy tier. |
| `kyverno` | — | Kyverno controllers. Excluded from tenant policies (self-hosted tooling tier). |
| `tenant-a` | `"true"` | `shop` app (nodejs distroless web server, port 8080, PVC for logs). |
| `tenant-b` | `"true"` | `analytics` app (nodejs API, port 9090, PVC for data). |

- **Policy scoping:** every tenant ClusterPolicy matches
  `namespaceSelector.matchLabels: {tenancy.io/tenant: "true"}`. Adding a tenant =
  create namespace + label + values file; no policy edits.
- **Identities:**
  - `alice` — OIDC user, group `tenant-a` (via dex static-password connector).
  - `bob` — OIDC user, group `tenant-b`.
  - App workloads run under per-app ServiceAccounts (`shop`, `analytics`) with
    **zero API permissions** and `automountServiceAccountToken: false`.
  - The **gate** authenticates with the kind admin kubeconfig (the "cluster operator"
    identity) — its only cluster-touching step is installing the policies it just
    tested. Deployment identities belong to the operator's own CD, out of scope here.
- **RBAC (least privilege, no cluster-admin for humans):**
  - `alice` → Role `tenant-a-pods` (create/delete/get/list on `pods`) +
    ClusterRole `view` in `tenant-a` only. She can create pods, but only
    Kyverno-compliant ones.
  - `bob` → symmetric Role in `tenant-b`.
  - Cross-tenant access is denied by construction (no bindings across namespaces).
- **Network isolation:** default-deny ingress+egress per tenant namespace; explicit
  allows only (DNS egress; same-ns ingress; tenant-a → tenant-b:9090 cross-tenant
  allow, simulating a frontend→backend production topology).

## 5. Security control → implementation map

| # | Requirement (user) | Mechanism | Artifact(s) |
| --- | --- | --- | --- |
| P1 | No root processes | Kyverno: `runAsNonRoot: true` | `policies/require-non-root.yaml` |
| P2 | No privilege escalation | Kyverno: `allowPrivilegeEscalation: false` | `policies/disallow-privilege-escalation.yaml` |
| P3 | Read-only root filesystem | Kyverno: `readOnlyRootFilesystem: true` | `policies/require-readonly-rootfs.yaml` |
| P4 | Default (masked) /proc | Kyverno: reject `procMount: Unmasked` | `policies/require-default-proc-mount.yaml` |
| P5 | No host network/process space | Kyverno: `hostNetwork/hostPID/hostIPC` false | `policies/disallow-host-namespaces.yaml` |
| P6 | Eliminate unused capabilities | Kyverno: `capabilities.drop` contains `ALL` | `policies/require-drop-all-capabilities.yaml` |
| P7 | SELinux options | Kyverno: require `seLinuxOptions.level` | `policies/require-selinux-options.yaml` |
| P8 | Dedicated ServiceAccount per app | Kyverno: `serviceAccountName` set, ≠ `default` | `policies/require-dedicated-serviceaccount.yaml` |
| P9 | No SA credentials if API not needed | Kyverno: `automountServiceAccountToken: false` | `policies/require-automount-sa-token-false.yaml` |
| P10 | No privileged containers (defense in depth) | Kyverno: `privileged: false` | `policies/disallow-privileged-containers.yaml` |
| C1 | Governed images only (trust list) | Kyverno: image repo must match trust list | `policies/require-image-allowlist.yaml` |
| C2 | Only scanned/verified images admitted | App pipeline: trivy scan before cosign sign (SETUP_DEMO). Operator verifies the signature at deploy time and stamps the annotations. Gate + Kyverno: annotation present + attested digest == running digest | `policies/require-image-attestation.yaml`, `policies/require-image-digest.yaml`, gate conformance stage |
| K1 | External API authentication | kube-apiserver OIDC → dex (static users, groups) | `kind/cluster-config.yaml`, `resources/cluster/dex.yaml` |
| K2 | Use RBAC properly | Per-tenant Roles/RoleBindings, no cluster-admin, app SAs have zero perms | `resources/cluster/rbac.yaml` |
| K3 | Limit access to kubelets | anonymous auth off, read-only port 0, webhook authz; verified with kube-bench + negative curl | `kind/cluster-config.yaml`, `tests/verify.sh` |
| N1 | Network policies (prod-like) | default-deny + explicit allows per tenant | chart `templates/networkpolicy-*.yaml` |
| S1 | Developer-owned deployment definitions, checked before merge | one chart; the gate renders each tenant values file and runs all 13 policies against the render | `resources/helm/webapp/`, gate conformance stage |

## 6. Kyverno policies

All policies: `apiVersion: kyverno.io/v1`, `kind: ClusterPolicy`,
`validationFailureAction: Enforce`, `background: true` (generates PolicyReports),
scoped to tenant namespaces via the label selector in §4. One file per rule — each
file is small, reviewable, and has its own unit test directory.

### 6.1 Example: `require-non-root.yaml` (full)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
  annotations:
    policies.kyverno.io/title: Require non-root
    policies.kyverno.io/category: Pod Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Application processes must not run as root. Pods must set
      spec.securityContext.runAsNonRoot=true.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-run-as-non-root
      match:
        resources:
          kinds: [Pod]
          namespaceSelector:
            matchLabels:
              tenancy.io/tenant: "true"
      validate:
        message: "Pods must set spec.securityContext.runAsNonRoot=true (no root processes)."
        pattern:
          spec:
            securityContext:
              runAsNonRoot: true
```

### 6.2 Example: `require-image-allowlist.yaml` (full)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-allowlist
  annotations:
    policies.kyverno.io/title: Governed image allowlist
    policies.kyverno.io/category: Supply Chain
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Only images from the governed trust list may run in tenant namespaces.
      The trust list is the set of registries/orgs the platform builds and
      scans (see variables below).
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-image-in-trust-list
      match:
        resources:
          kinds: [Pod]
          namespaceSelector:
            matchLabels:
              tenancy.io/tenant: "true"
      validate:
        message: >-
          Image is not in the governed image trust list. Only images built and
          scanned by the platform pipeline may be admitted.
        cel:
          variables:
          - name: trustedRepos
            # ── GOVERNED IMAGE TRUST LIST ────────────────────────────────
            # Add a registry/org here (and in CI) when the platform starts
            # building + scanning images from it. This is the "private trust
            # list" — versioned, reviewed, unit-tested like code.
            expression: '["docker.io/padishahiii"]'
          expressions:
          - expression: >
              variables.trustedRepos.exists(r,
                object.spec.containers.all(c,
                  (c.image.startsWith("docker.io/") ? c.image : "docker.io/" + c.image)
                    .startsWith(r + "/")))
            messageExpression: >-
              "Image " + object.spec.containers.map(c, c.image).join(", ") +
              " is not in the governed image trust list."
```

> **Design note — trust list in the policy vs. ConfigMap.** In `kyverno.io/v1`,
> CEL rules can only see `object`, `parameters`, and `variables` declared under
> `validate.cel.variables` — they cannot read a ConfigMap (that is a JMESPath
> `context` feature, invisible to CEL). So the trust list lives in the policy's
> `cel.variables`: changing the list is a *policy change*, reviewed and committed
> like code and unit-tested offline by `kyverno test`. A production org that must
> change the list *without* a policy redeploy would migrate to the CEL-native
> `policies.kyverno.io/v1` engine (ValidatingPolicy), where `spec.variables` can be
> ConfigMap-backed.
>
> **Deprecation note:** Kyverno 1.19 warns that `kyverno.io/v1` ClusterPolicy is
> deprecated in favour of `policies.kyverno.io/v1` (ValidatingPolicy /
> ImageValidatingPolicy / ...). We stay on `kyverno.io/v1` deliberately: it is the
> most widely documented form, it drives PolicyReports, and the `kyverno test` CLI
> harness is mature against it. The migration is a known follow-on.

### 6.3 Example: `require-image-attestation.yaml` (full)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-attestation
  annotations:
    policies.kyverno.io/title: Require image attestation
    policies.kyverno.io/category: Supply Chain
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Only cosign-verified images may run; the attested digest must match the image
      digest. The deploy step (cluster operator) cosign-verifies the image and stamps
      the pod template with attestation annotations; this policy enforces their
      presence and that the attested digest matches the image actually being run.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-attestation-annotation
      match:
        resources:
          kinds: [Pod]
          namespaceSelector:
            matchLabels:
              tenancy.io/tenant: "true"
      validate:
        message: >-
          Pod is missing the image attestation (security.devsecops.io/image-verified=cosign).
          Only images verified by the cluster operator's deployment pipeline may run.
        pattern:
          metadata:
            annotations:
              "security.devsecops.io/image-verified": "cosign"
    - name: check-attested-digest-matches
      match:
        resources:
          kinds: [Pod]
          namespaceSelector:
            matchLabels:
              tenancy.io/tenant: "true"
      validate:
        message: >-
          The attested image digest does not match the image digest. The image was
          likely re-tagged or replaced after verification — re-verify and re-deploy.
        cel:
          expressions:
          - expression: >
              object.spec.containers.all(c,
                c.image.contains("@sha256:")
                && object.metadata.annotations["security.devsecops.io/image-digest"]
                   == c.image.substring(c.image.indexOf("@") + 1))
```
### 6.4 Remaining policies (summary)

| Policy | Validation (sketch) |
| --- | --- |
| `disallow-privileged-containers` | CEL: no container has `securityContext.privileged == true` |
| `disallow-privilege-escalation` | pattern: every container `allowPrivilegeEscalation: false` |
| `require-readonly-rootfs` | pattern: every container `readOnlyRootFilesystem: true` |
| `require-default-proc-mount` | CEL: no container has `procMount == "Unmasked"` (absent or `Default` is OK) |
| `disallow-host-namespaces` | pattern: `hostNetwork: false`, `hostPID: false`, `hostIPC: false` |
| `require-drop-all-capabilities` | CEL: every container `capabilities.drop` contains `"ALL"` |
| `require-selinux-options` | CEL: every container has `securityContext.seLinuxOptions.level` set |
| `require-dedicated-serviceaccount` | CEL: `serviceAccountName` non-empty and ≠ `"default"` |
| `require-automount-sa-token-false` | pattern: `automountServiceAccountToken: false` |
| `require-image-digest` | CEL: every image reference contains `@sha256:` (no mutable tags) |

**Known limitation (SELinux on kind):** the kind node runs without SELinux enabled,
so `seLinuxOptions` is accepted in the spec but not enforced by the runtime. The
policy still enforces *spec-level* conformance (the field must be present and
sane), which is what the demo shows; on an SELinux-enabled node the same policy
plus the runtime gives real enforcement. This is stated honestly in the README.

## 7. Kubernetes component security

### 7.1 External API authentication (K1) — OIDC via dex

- **dex** is deployed in the `platform` namespace (`resources/cluster/dex.yaml`) with
  a static-password connector:
  - `alice` / email `alice@tenant-a.local` / groups `[tenant-a]`
  - `bob`   / email `bob@tenant-b.local`   / groups `[tenant-b]`
  - (demo password documented in SETUP_DEMO.md — not a secret)
- The **kind cluster config** (`kind/cluster-config.yaml`) starts kube-apiserver with:
  ```yaml
  apiServer:
    extraArgs:
      oidc-issuer-url: http://dex.platform.svc:5556
      oidc-client-id: kubernetes
      oidc-username-claim: email
      oidc-groups-claim: groups
  ```
  The apiserver delegates token validation to the external issuer; identities and
  groups flow into RBAC. Built-in cert auth still works (the admin kubeconfig is a
  client cert — the platform operator identity).
- **Login UX:** `kubectl port-forward -n platform svc/dex 5556:5556` then
  `kubectl oidc-login login` (plugin) → a kubeconfig for `alice`/`bob` used by
  `tests/verify.sh` and the demo script.
- **Production note:** dex would sit behind a load balancer with TLS
  (`--oidc-ca-file` pinned); the lab uses in-cluster HTTP. Documented, not hidden.
- **Fallback:** if OIDC proves flaky on the lab host, the token-webhook variant
  (`--authentication-token-webhook-config-file` pointing at a small in-cluster
  validator) is the documented alternative. Same RBAC story either way.

### 7.2 RBAC properly (K2)

- No human has `cluster-admin`. Bindings are per-namespace (§4).
- App ServiceAccounts exist per app, have **no RoleBindings at all**, and
  `automountServiceAccountToken: false` (policy P9) — they cannot talk to the API
  even if they wanted to.
- Demo evidence: `kubectl auth can-i` matrix in `tests/verify.sh`
  (alice: read tenant-a ✔, read tenant-b ✘, create non-compliant pod → Kyverno ✘).

### 7.3 Kubelet access restriction (K3)

kind's kubelet already runs with sane defaults; the cluster config makes them
**explicit** (KubeletConfiguration patch) so the intent is visible and auditable:

```yaml
kubeadmConfigPatches:
  - kind: KubeletConfiguration
    apiVersion: kubelet.config.k8s.io/v1beta1
    authentication:
      anonymous:
        allowed: false
      webhook:
        cacheTTL: 2m
        cacheAuthorizedTTL: 2m
        cacheUnauthorizedTTL: 10s
    readOnlyPort: 0
```

Verification (in `tests/verify.sh`):
- `curl -k https://<node>:10250/healthz` **without** credentials → 401/403 (anonymous
  rejected, no read-only port).
- `kube-bench node` (CIS 4.x) — the workspace has a `kube-bench` build at
  `../kube-bench`; output is archived as evidence.

## 8. Container security & supply chain

### 8.1 Governed images (C1)

- The only trusted registry/org: **`docker.io/padishahiii`** (private Docker Hub
  org, same as the sibling project). The trust list lives in
  `require-image-allowlist.yaml` (§6.2) — strict by default: everything else is
  rejected. The attacker pod (`bitnami/kubectl:latest`) is the canonical rejection.

### 8.2 Verified images (C2) — cosign as the trust anchor

Division of labor: **the application repo's pipeline owns build + scan + sign** (out of
scope for this repo — SETUP_DEMO.md shows how to produce the demo signed images).
**The cluster operator owns verify + deploy** — also out of scope for this repo, which
is why there is no `cosign verify` step here. What this repo *does* own is the
admission-time contract that makes a skipped verification visible. The cosign signature
is the trust anchor: an image is only signed after a passing Trivy scan, so *verified ⇒
scanned*, and the annotation pair below is the in-cluster proof that verification
happened.

```
app repo pipeline (out of scope — SETUP_DEMO.md)
────────────────────────────────────────────────
build (distroless) → trivy image scan (fail on CRITICAL/HIGH)
  → cosign sign --key <private key> → push to docker.io/padishahiii/*

operator deploy step (out of scope — this repo's gate stops at the contract)
───────────────────────────────────────────────────────────────────────────
cosign verify --key <cosign.pub> IMAGE@sha256:...      (fail = no deploy)
  → stamp the pod template:
      security.devsecops.io/image-verified: cosign
      security.devsecops.io/image-digest:   sha256:...
  → helm upgrade / kubectl apply ─────▶ Kyverno require-image-attestation
                                        (annotation present AND digest == image digest)

this repo's gate (IN SCOPE)
──────────────────────────
renders resources/helm/webapp/values-<tenant>.yaml (developer-owned: fullRef +
annotations.image*) → kyverno apply policies/ -r <rendered>
  → enforces the same shape offline: digest-pinned reference, annotation present,
    attested digest == fullRef digest. A manifest that fails cannot merge.
```

- **Digest pinning** (`require-image-digest`): every image reference must be a full
  `repo@sha256:...` reference — never a mutable tag. The gate checks this in the
  developer's rendered manifest; admission checks it on every Pod.
- **Digest match check** closes the re-tagging hole: if the registry image is
  re-tagged after verification, the attested digest no longer matches and admission
  fails.
- **Honest limitation:** the attestation annotations are mutable by anyone with update
  rights on the pod template. Mitigations in this design: (a) RBAC — tenant Deployments
  are updated only by the operator; (b) the digest-match check; (c) the operator
  cosign-verifies *before* stamping, so a valid annotation implies a verified
  signature. The stronger production variant is cosign verification at admission itself
  (out of scope here). Note the gate **cannot** cosign-verify — that needs registry
  credentials and network at check time; it enforces the contract's shape, Kyverno
  enforces its presence.

### 8.3 The Helm chart (S1) — developer-owned input the gate checks

One chart, `resources/helm/webapp/`, rendered once per tenant values file (`shop` in
tenant-a, `analytics` in tenant-b). Developers own `values-<tenant>.yaml`; the operator
owns the policy set. The gate is where those two meet:

- The **conformance stage** runs `helm template` per tenant, stamps the namespace
  (`kubectl create --dry-run=client`), and applies all 13 policies to the render. If a
  values change — a new image, a dropped capability, a missing annotation — breaks
  policy, the build goes red before anything merges.
- **No signing here.** Chart provenance (GPG `helm package --sign` + `helm verify`) is
  a *delivery* concern of the operator's CD, not a policy concern; it lived in the
  removed `Jenkinsfile.cd` (git history). What the gate checks instead is the manifest
  content itself — which is strictly the property that matters for "may this run?".
- The archived `reports/conformance-rendered/*.yaml` are the exact bytes that cleared
  the gate — a convenient handoff for the operator's deploy step, though nothing in
  this repo consumes them.

**Chart contents (templates/):** `serviceaccount.yaml`, `deployment.yaml` (security
context: non-root, runAsUser 1000, fsGroup 1000, readOnlyRootFilesystem, drop ALL,
procMount Default, seLinuxOptions level, automountServiceAccountToken false; image
`repository@digest`; attestation annotations on the **pod template** — not on the
Deployment metadata, since only pod-template annotations propagate to Pods),
`service.yaml`, `pvc.yaml`, `networkpolicy-default-deny.yaml`,
`networkpolicy-allow-dns.yaml`, `networkpolicy-allow-ingress.yaml` (per-tenant peer
rules from values), `role.yaml` (empty/minimal placeholder — app SAs get no perms).

**Per-tenant values** (`values-tenant-a.yaml`, `values-tenant-b.yaml`): name, port,
PVC size, ingress-allow peers (tenant-b allows from tenant-a), and the developer-owned
image + attestation (digest-pinned `image.fullRef` + `annotations.imageVerified/
imageDigest` — the same shape the operator stamps per deploy, see §8.2). The gate
renders these files as-is; no app data lives in the pipeline.

## 9. Demo applications

| App | Tenant | Image | Port | PVC | Notes |
| --- | --- | --- | --- | --- | --- |
| `shop` | tenant-a | `docker.io/padishahiii/kube-sec-shop` | 8080 | 100Mi, `/data` (access logs) | The "prod-like" web server. Node.js HTTP server, zero npm deps, `/health` endpoint. |
| `analytics` | tenant-b | `docker.io/padishahiii/kube-sec-analytics` | 9090 | 100Mi, `/data` (report storage) | Second app: proves multi-app, multi-tenant; target of the cross-tenant allow rule. |
| `attacker` (pod) | tenant-b | `bitnami/kubectl:latest` | — | — | **Rogue artifact** (`resources/admission/pod.attacker.yaml`): not in trust list, runs as root, no security context → rejected by multiple policies. The demo's villain. |

- The app source lives in `demo-apps/` (top-level) — it is used to **produce** the
  signed demo images (SETUP_DEMO.md). Nothing in this repo deploys anything; the gate
  checks the manifests that reference those image digests.
**Dockerfile (`demo-apps/shop/Dockerfile`, representative):**

```dockerfile
FROM gcr.io/distroless/nodejs22
COPY server.js /app/server.js
USER node            # uid 1000 — distroless nodejs ships a non-root user
EXPOSE 8080
CMD ["node", "/app/server.js"]
```

- Distroless: no shell, no package manager, minimal attack surface; non-root user;
  listens on 8080 (non-root cannot bind <1024).
- `server.js`: plain `http` server; writes one access-log line per request to
  `/data/access.log` (the PVC — proves the volume is writable; `fsGroup: 1000`
  makes the local-path volume group-writable for uid 1000).
- `demo-apps/analytics/server.js`: same shape, `/metrics`-style JSON endpoint on 9090.

## 10. Jenkins — the policy gate

Jenkins runs locally (`java -jar jenkins.war --httpPort=8081`, same as the sibling
project). **One** Pipeline job with SCM script path `workflows/Jenkinsfile.ci`.
(Multibranch + GitHub App is the sibling project's setup and works here too, but is
not required.)

**Credentials:** `kind-kubeconfig` (Secret file) — used by the schema-lint and policy
install stages. That is the whole list: the gate pulls no images, verifies no
signatures, and deploys nothing.
**Plugins:** Pipeline Aggregator, Credentials Binding, Workspace Cleanup, Timestamper,
Git.

CD (`workflows/Jenkinsfile.cd`) was removed from this repo — it is out of scope for a
policy-gate demo (§13). What existed lives in git history.

### 10.1 Stages

```
cleanup → checkout
  → tool setup         : bootstrap version-pinned kyverno + helm binaries into .tools/ (no official CLI docker image)
  → policy unit tests  : .tools/kyverno test tests/policies
  → policy conformance : for each resources/helm/webapp/values-<tenant>.yaml (developer-owned,
                         incl. image.fullRef + annotations.image*): helm template | kubectl create
                         --dry-run=client (namespace stamp) → .tools/kyverno apply policies/ -r <rendered>/
                         -f <rendered>/values.yaml (namespaceSelector rebuilt from the same tenant files)
  → IaC scan           : docker run aquasec/trivy:<ver> config --severity CRITICAL,HIGH --exit-code 1 --skip-dirs admission resources/
  → policy schema lint : kubectl apply --dry-run=server -f policies/   (kind-kubeconfig; CRD strict-decode)
  → policy install     : kubectl apply -f policies/            (kind-kubeconfig credential)
  → policy ready       : kubectl wait --for=condition=Ready clusterpolicy --all --timeout=120s
post: archive reports/kyverno-test.txt, kyverno-conformance.txt, trivy-config.txt,
      conformance-rendered/ (the per-tenant manifests that passed — the operator's
      deploy input)
```

Offline checks (unit tests, conformance, IaC) run **first** — they need no cluster and
catch most issues. The cluster checks (lint → install → ready) run last, so a downed
cluster cannot prevent the offline signal from being produced.

Two tooling notes (verified):

- **No `kyverno/kyverno` CLI docker image exists** (the controller image is not the CLI).
  CI bootstraps the version-pinned binary from the GitHub release (`kyverno-cli_v<ver>_<os>_<arch>.tar.gz`),
  reusing a matching local install to avoid the ~52MB download.
- **The `aquasec/trivy` image entrypoint is already `trivy`**, so the subcommand is `config`
  (not `trivy config`). `--skip-dirs admission` excludes the attacker pod (an intentional
  rejection target, not a deployable resource).

The last two stages are the **policy execution stage** — the only path by which
policies enter the cluster:

- `policy install` runs **only after** lint + unit tests + conformance + IaC scan pass
  (declarative pipeline semantics: a non-zero exit in any earlier stage aborts the build).
- `kubectl apply --dry-run=server` runs the real CRD structural schema (catches
  unknown fields / bad shapes) without creating anything. It does **not** compile
  CEL — that is the job of the unit-test stage.
- **Two offline checks, two different signals** (both need the namespace labels
  injected, or they vacuously pass for label-scoped policies):
  - `kyverno test tests/policies` — **assertions** (expected pass/fail). The primary
    gate: proves each rule's *behaviour* both directions (compliant passes, violating
    denied) and is the CEL compile-error net. The attacker pod is a `result: fail`
    fixture here (an *expected* denial).
  - `kyverno apply policies/ -r <rendered>/ -f <rendered>/values.yaml` — **conformance**
    (the official dry-run). Proves the *actual* developer manifests pass all 13; exit 0.
    The app manifests are **rendered from the webapp chart at CI time** (helm
    template → `kubectl create --dry-run=client` namespace stamp), not stored as
    hand-written fixtures — the chart is the single source of truth developers
    contribute, so a security-context change to the chart or a values file flips
    conformance in the same commit instead of drifting in a stale copy under tests/.
    Deployments are autogen-expanded to Pods, mirroring the real admission path;
    per-tenant renders land in `reports/conformance-rendered/` (under the gitignored
    `reports/`, archived as build artifacts). CI is app-agnostic: it iterates the developer-owned
    `resources/helm/webapp/values-<tenant>.yaml` files (which carry `image.fullRef` +
    `annotations.image*`) and rebuilds the namespaceSelector values file from the same
    files — adding an app = adding one values file, no pipeline edits.
  - Without `-f values.yaml` (or `kyverno test`'s `variables:`), `namespaceSelector`
    rules are silently *Excluded* offline → `pass: 0, fail: 0` (a vacuous green).
    Verified: with `-f`, the compliant app pod passes all 14 rules; the attacker pod
    trips 13.
- The admission webhook is a single generic, policy-agnostic endpoint (verified:
  one webhook matching all Pods/Deployments/...), so there is no per-policy
  webhook to wait for. `kubectl wait --for=condition=Ready` blocks until the policy
  object is accepted and compiled into Kyverno's policy cache; enforcement was
  measured live at ~1s after apply. The wait is cheap insurance against the
  (unmeasured-here) cache-sync window on larger clusters.
- **Compile-error net:** `Ready=True` does **not** prove the CEL compiles
  (verified: a broken CEL expression still reports `Ready=True reason=Succeeded`).
  In-cluster a broken CEL rule fails *closed* — it denies every request in the
  matched namespaces (an availability outage, not a security hole). So
  `kyverno test` (stage above) is the real compile-error net: a broken expression
  flips a `pass` fixture to `fail` and the build fails before install.
- **Null-safety for DELETE / status updates (verified, cost us a stuck cluster):**
  Kyverno's resource validating webhook is registered for `CONNECT, CREATE, DELETE,
  UPDATE` — not just create/update. In a **DELETE** admission request (and in a Pod
  **status** subresource update) the `object` has **no `spec`**, so any CEL expression
  that references `object.spec.*` raises `no such key: spec`. Because a CEL error
  fails *closed*, every such policy **denied all pod deletions** in the tenant
  namespaces — rollouts and manual cleanup deadlocked (a pod that can't be deleted
  also pins its RWO PVC, so the replacement pod can't schedule). Fix: guard every
  `validate.cel` expression with `!has(object.spec) || ( ... )`. The guard is
  vacuously true when there is no spec to validate (DELETE / status update) and is a
  no-op for CREATE/UPDATE, so enforcement is unchanged — `kyverno test` and the
  conformance run still pass 28/28. `validate.pattern` rules are **not** affected
  (they were observed to pass DELETE through), which is why the two pattern-based
  policies needed no change.
- Idempotent: re-applying unchanged policies is a no-op; a changed policy is hot-
  swapped in the cluster on the next CI run.

- **No gate framework** (unlike the sibling repo): each tool's exit code *is* the
  gate — `kyverno test` non-zero → build fails; `trivy --exit-code 1` with
  CRITICAL/HIGH findings → build fails. The scenario is simple enough that a
  findings-normalization layer would be overhead.
- **Alternative:** a dedicated `Jenkinsfile.policies` job (or ArgoCD) would separate
  policy governance from app CI. Kept in CI here because policies and their tests
  live in one tree and change together.

### 10.2 Why there is no CD section

An earlier revision of this repo carried `workflows/Jenkinsfile.cd`: cosign-verify a
digest-pinned `IMAGE` against the `cosign-pub` credential, stamp the attestation
annotations into per-build values, `helm package --sign` the chart (GPG provenance,
verified with the committed `public.asc`), `helm upgrade --install` into the tenant
namespace, then collect in-cluster evidence. It was removed because **deploying is
operations, and this repo demonstrates a policy gate** — every mechanism CD exercised
(cosign verify, chart signing, rollout checks) proves things this demo does not need to
prove, and it blurred the ownership story (the operator owns deployment; this repo owns
policy + the gate). The interesting invariants survive without it:

- "An unverified image never runs" is still enforced — by the operator's deploy-time
  verify plus `require-image-attestation` at admission.
- "A non-compliant manifest never merges" is still enforced — harder, actually: the
  gate checks the developer's real render *before* merge, which CD used to discover
  only at deploy time.
- "The pipeline is the only trusted path" became "**the policies are the only trusted
  boundary**" — admission validates every Pod from every path, including (and
  especially) ones the operator did not automate.

The `helm-signing-key` / `cosign-pub` / `dockerhub` Jenkins credentials and
`tools/generate-helm-signing-key.sh` were removed with it; SETUP_DEMO.md §8-§9 list
what a stale Jenkins instance must clean up.

## 11. Tests

```
tests/
├── policies/
│   ├── require-non-root/
│   │   ├── kyverno-test.yaml      # cli.kyverno.io/v1alpha1 Test — policies + resources + results
│   │   ├── values.yaml            # namespaceSelector labels (required, else rules are "Excluded")
│   │   ├── pod-compliant.yaml     # expected: pass
│   │   └── pod-root.yaml          # expected: fail (also the guard: a broken selector can't satisfy "fail")
│   ├── disallow-privilege-escalation/ ...   (one dir per policy: ≥1 pass + ≥1 fail fixture)
│   └── ...
└── verify.sh                      # operator-side cluster evidence collector
```

- **Unit (offline):** `kyverno test tests/policies` — every policy has at least one
  compliant fixture (`result: pass`) and one violating fixture (`result: fail`).
  Runs in the gate; no cluster needed.
- **Conformance (offline):** the gate renders each developer-owned
  `resources/helm/webapp/values-<tenant>.yaml` and applies the whole policy set to the
  render (§10.1) — the real manifests, not fixtures.
- **Admission behaviour (offline):** `kyverno test` is where denials are asserted —
  one dir per policy, ≥1 pass + ≥1 fail fixture. No in-cluster negative tests.
- **`verify.sh` (operator evidence, positive-only):**
  1. all 13 ClusterPolicies installed, `Enforce`, and `Ready=True`;
  2. both apps Running; PolicyReports in the tenant namespaces show **0 fail**;
  3. RBAC matrix via alice/bob oidc kubeconfigs (can-i table);
  4. kubelet anonymous curl → 401/403; kube-bench node output archived;
  5. netpol: `shop` pod → `analytics:9090` succeeds (explicit allow),
     `shop` pod → external host fails (default-deny egress).

  Items 2 and 5 need deployed workloads — this repo no longer deploys anything, so on
  a gate-only cluster those sections report/skip accordingly (1, 3, 4 pass on their
  own). Run the full script after the operator's tooling has deployed the apps.

## 12. Directory layout

```
kube-security/
├── README.md                    # usage: structure, adding apps, policies, scope
├── SETUP_DEMO.md                # prerequisites: kind, jenkins, dex, credentials
├── docs/
│   └── DESIGN.md                # this document
├── kind/
│   └── cluster-config.yaml      # kind config: OIDC args, kubelet hardening
├── policies/                    # 13 Kyverno ClusterPolicies (one file per rule)
├── demo-apps/                   # demo app source — for PRODUCING the signed images
│   ├── shop/                    #   (SETUP_DEMO.md); nothing here deploys images
│   │   └── Dockerfile + server.js (nodejs distroless web server, :8080)
│   └── analytics/               #   Dockerfile + server.js (:9090)
├── resources/
│   ├── cluster/
│   │   ├── namespaces.yaml      # tenant-a / tenant-b (+ tenancy.io/tenant label)
│   │   ├── dex.yaml             # platform ns + dex deployment/service
│   │   └── rbac.yaml            # demo user roles & bindings
│   ├── helm/
│   │   └── webapp/              # the developer-owned chart the gate renders+checks
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       ├── values-tenant-a.yaml   # per-tenant: image fullRef + attestation
│   │       ├── values-tenant-b.yaml   #   annotations + port + peers (developer-owned)
│   │       └── templates/       # sa, deployment, service, pvc, netpols, role
│   └── admission/
│       └── pod.attacker.yaml    # rogue pod — manual demo rejection target
├── tests/
│   ├── policies/<policy>/       # kyverno-test.yaml + fixtures per policy
│   └── verify.sh                # operator-side cluster evidence (post-deploy)
└── workflows/
    └── Jenkinsfile.ci           # THE POLICY GATE (the only pipeline in this repo)
```

(Removed with CD: `workflows/Jenkinsfile.cd`, `resources/helm/webapp/keys/public.asc`,
`tools/generate-helm-signing-key.sh`.)

## 13. Out of scope (and why)

| Item | Reason / where it lives |
| --- | --- |
| **CD / deployment pipeline** | This is a policy-gate demo, not an operations demo. The gate decides what *may* run and installs the enforcing policies; running it is the cluster operator's job. The previous `Jenkinsfile.cd` (cosign verify → GPG-signed chart → deploy → rollout checks) is preserved in git history — §10.2 explains what its removal does and does not weaken. |
| Chart provenance signing (GPG `helm package --sign` / `helm verify`) | A delivery-integrity concern of the operator's CD, not a policy property of the manifest. Removed with CD. |
| cosign verify at check time | The gate has no registry credentials/network by design; it enforces the manifest *shape* (digest pinning, attestation annotations + digest match) and Kyverno enforces it at admission. |
| DAST (ZAP) | Sibling repo `devsecops-demo` already demonstrates in-cluster DAST + DAST-aware gate. |
| Image build/push/scan pipeline | The application repo's job. SETUP_DEMO.md walks through producing the demo signed images (build → trivy → cosign sign → push). cosign *signing* is demonstrated in `devsecops-demo`. |
| PodSecurityAdmission labels | Complementary, not alternative — PSS `restricted` ≈ policies P1–P6. Mentioned in README; explicit policies chosen for per-rule granularity and readable rejection messages. |
| Audit logging / etcd hardening | kind manages etcd; audit policy is a kube-apiserver flag demo, lower value than the controls above. |
| Service mesh / mTLS | Different layer; netpols are the demo's network control. |
| Secrets management, GitOps, quotas | Realistic additions, not core to the security story; listed as future work. |
| Gate framework (findings normalization) | Sibling repo's tools/gate.py pattern; this repo hardcodes failure gates (tool exit codes) in the pipeline — the scenario is simpler. |

## 14. Demo script (interview narrative)

1. **Green gate** — run the CI job: `kyverno test` 28/28, conformance on the rendered
   tenant manifests, IaC scan clean, 13 policies installed + Ready. "Policy is code,
   and the gate is the only path policy takes into the cluster."
2. **Red gate (the negative control, zero cluster impact)** — point a tenant values
   file at `bitnami/kubectl:latest` (mutable tag, off-list) or drop the attestation
   annotations; the conformance stage fails and the PR cannot merge. "A non-compliant
   deployment is rejected *before* it reaches anybody's cluster."
3. **Admission denial, live** — `kubectl apply -f resources/admission/pod.attacker.yaml`
   → rejected by ~10 policies. Read the message: image not in trust list. "And if
   someone skips the gate entirely, admission still says no."
4. **Unverified image** — hand-apply a Deployment with a compliant image but no
   attestation annotations → rejected by `require-image-attestation`. "The
   cosign-verify contract is enforced at admission, even without a pipeline in the
   request path."
5. **Multi-tenant RBAC** — log in as `alice` via `kubectl oidc-login`: read tenant-a ✔,
   read tenant-b ✘, create a root pod → RBAC allows, Kyverno denies.
6. **Component hardening** — kubelet anonymous curl → 401; kube-bench node output;
   "external auth: the apiserver validates tokens against dex, and RBAC scopes what
   each identity can do."
7. **Network isolation** (needs the operator's deployed apps) — from the shop pod:
   `curl analytics.tenant-b.svc:9090` ✔ (explicit allow), `curl <external>` ✘
   (default-deny egress).

## 15. Key design decisions & trade-offs

| Decision | Rationale | Trade-off |
| --- | --- | --- |
| Kyverno over OPA/Gatekeeper | Native k8s API (CRDs), CEL + patterns, built-in PolicyReports, first-class CLI for offline testing | Less "standard" in some enterprises; Conftest/OPA is the alternative |
| One policy per rule (13) | Each user requirement maps 1:1 to a file + test dir; readable rejection messages per rule | More files; PSS labels would be one label (but opaque messages, no per-rule granularity) |
| `Enforce` in tenant ns, platform ns excluded | Two-tier governance is realistic; platform tooling (dex, kyverno) isn't PSA-restricted | Platform tier needs its own controls (out of scope) |
| Trust list in policy `variables` | Offline-testable, versioned, reviewed | Not hot-updatable without policy redeploy (ConfigMap+apiCall is the prod variant) |
| Gate renders the developer chart instead of storing fixtures | The values file is the single source of truth; a change to it flips conformance in the same commit | Conformance needs `helm` + a namespace-stamp trick (§10.1) |
| **No CD pipeline in this repo** | It's a policy-gate demo; deployment is the operator's domain. CD's supply-chain story (cosign verify, chart signing) either stays a deploy-time concern or is re-enforced at admission — nothing policy-relevant is lost | The end-to-end "verified image actually running" loop isn't demonstrated in-repo; §10.2 lists what survives; git history keeps the old CD |
| Annotation-based attestation (stamped by the operator after cosign verify) | Simple, no extra infrastructure; digest-match check closes re-tagging; the gate checks the shape pre-merge | Annotations are mutable — mitigated by RBAC + digest check; cosign-at-admission is the stronger variant |
| dex over HTTP in-cluster | Minimal moving parts for the lab | No TLS — documented; production would use LB + `--oidc-ca-file` |
| kind admin kubeconfig for the gate | Simplest cluster-operator identity; the gate's only writes are ClusterPolicy objects | Real org: dedicated gate ServiceAccount with `kyverno.io`-only permissions (noted in README) |
| cosign signature as image trust anchor | Scan happens in the app pipeline before signing (verified ⇒ scanned); the operator verifies with the public key at deploy time | No in-cluster signature check — attestation annotations + digest match are the admission-time proxy |
| Hardcoded exit-code gates (no gate framework) | Scenario is simple: each tool (kyverno test, kyverno apply, trivy, kubectl) has a binary verdict | No cross-tool findings normalization/reporting (sibling repo has it) |
| Policies installed by **the gate** (the policy execution stage) | Policies + tests live in one tree and change together; the test gate is the precondition for install | CI holds cluster credentials for two purposes (test + install); a dedicated policy job or ArgoCD would isolate that better |
| No in-cluster negative admission test | `kyverno test` already proves each rule's pass/fail behaviour offline; the gate never needs workloads running | A policy that installs but misbehaves in-cluster surfaces via PolicyReports, not a synthetic denial |

## 16. References

- Kyverno policies & CLI: `kyverno.io/docs` (ClusterPolicy, `kyverno test`, CEL validation)
- CIS Kubernetes Benchmark (kube-apiserver 1.2.x OIDC, kubelet 4.1.x)
- Pod Security Standards (baseline/restricted) — the policies P1–P6 mirror `restricted`
- Sibling repo `../devsecops-demo`: `Jenkinsfile.cd` (cosign sign/verify + GPG chart
  signing patterns, fail-closed gate) — the reference for what this repo *used* to do
  before CD was cut from scope
- cosign / sigstore: `github.com/sigstore/cosign` (key-based signature verification)
- distroless: `gcr.io/distroless/nodejs22` (GoogleContainerTools/distroless)
