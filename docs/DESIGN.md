# kube-security — Design Document

A single-node kind cluster that demonstrates **defense-in-depth Kubernetes security**,
enforced by a **Jenkins pipeline** — CI gates the policies and the Helm chart, CD
**verifies cosign-signed images** and deploys them with a **GPG-signed Helm chart** —
while **Kyverno** enforces admission policies in-cluster.

This document is the source of truth for the repo layout, the security controls, and
the pipeline design. `SETUP_DEMO.md` covers environment setup; `README.md` covers
usage.

---

## 1. Goals

1. **Show, don't tell.** Every security control has a *demonstrable failure mode*:
   a non-compliant pod is rejected with a readable message, an unverified image is
   blocked, a cross-tenant request is denied, an anonymous kubelet request gets a 401.
2. **Pipeline is the only trusted path.** Images are produced by the application
   repo's pipeline (build → trivy scan → cosign sign → push — out of scope for this
   repo; SETUP_DEMO.md shows how to produce the demo signed images) and reach the
   cluster only through this repo's CD pipeline (cosign verify → GPG-sign chart →
   deploy). Anything that bypasses them is rejected at admission.
3. **Multi-tenant realism.** Two tenant namespaces with isolated RBAC, network
   policies, and service accounts — the policies apply to tenants, not to the
   platform namespaces (a realistic two-tier governance model).
4. **Testable policies.** Every Kyverno policy has offline unit tests (`kyverno test`)
   that run in CI before anything touches a cluster.

## 2. Scope

| In scope | Out of scope (see §13) |
| --- | --- |
| Kyverno admission policies (13) + unit tests | DAST (covered by sibling repo `devsecops-demo`) |
| Image governance: trust list, digest pinning, cosign verify at deploy | Image build/push/scan pipeline — the application repo's job (SETUP_DEMO.md shows how to produce the demo signed images) |
| Helm chart for CD, GPG-signed (provenance) | Service mesh / mTLS, audit logging, etcd hardening |
| Multi-tenant namespaces, RBAC, NetworkPolicies | PodSecurityAdmission labels (mentioned as alternative) |
| External API authentication (OIDC via dex) | Node hardening beyond kind defaults (kube-bench used for evidence) |
| Kubelet access restriction + verification | Secrets management (SOPS/SealedSecrets), GitOps (ArgoCD) |
| Jenkins CI (policy tests, IaC scan, **policy install**) + CD (cosign verify → signed-chart deploy → verify) | Gate framework (sibling repo) — this repo hardcodes failure gates (tool exit codes) |

## 3. Architecture

```
   app repo pipeline (OUT OF SCOPE — see SETUP_DEMO.md):
   build → trivy image scan (CRITICAL,HIGH) → cosign sign → push docker.io/padishahiii/*

                    ┌─────────────────────────── Jenkins (local, :8081) ────────────────────────────┐
                    │                                                                               │
  git push          │  CI: workflows/Jenkinsfile.ci                CD: workflows/Jenkinsfile.cd     │
  ┌────────┐        │  ┌─────────────────────────────┐            ┌─────────────────────────────┐   │
  │ GitHub │──────▶ │  │ schema lint (dry-run=server)│            │ cosign verify (trust anchor)│   │
  │  repo  │        │  │ policy unit tests           │            │ helm package + GPG sign     │   │
  └────────┘        │  │ trivy config (helm + yaml)  │            │ helm verify (public.asc)    │   │
                    │  │ POLICY INSTALL (kubectl     │            │ helm upgrade --install ─────┼───┼──┐
                    │  │   apply + Ready wait)       │            │ rollout + verify            │   │  │
                    │  └──────────────┬──────────────┘            └─────────────────────────────┘   │  │
                    └─────────────────┼─────────────────────────────────────────────────────────────┘  │
                                      │ policies that passed their tests                               │
                                      │ are the only ones that reach the cluster                       │
                                      ▼                                                                ▼
   ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
   │  kind cluster (single node)                                                                      │
   │                                                                                                  │
   │  kube-apiserver : --oidc-issuer-url=http://dex.platform.svc:5556   --authorization-mode=Node,RBAC│
   │  kubelet        : anonymous auth OFF · read-only port 0 · webhook authorization                  │
   │                                                                                                  │
   │  Kyverno (kyverno ns) ── 13 ClusterPolicies, Enforce, scoped to ns label tenancy.io/tenant      │
   │        │                                                                                         │
   │        └─ admission-validates every Pod created by ANY path (pipeline OR kubectl OR controller)  │
   │                                                                                                  │
   │   platform ns          tenant-a ns                 tenant-b ns                                   │
   │   ┌───────────┐        ┌──────────────────┐        ┌──────────────────┐                          │
   │   │ dex (OIDC)│        │ shop  :8080      │        │ analytics :9090  │                          │
   │   │  :5556    │        │ PVC /data (logs) │        │ PVC /data        │                          │
   │   └───────────┘        │ SA: shop         │        │ SA: analytics    │                          │
   │                        │ NetPol deny-all  │        │ NetPol deny-all  │◀─── cross-tenant allow   │
   │                        │  +allow-dns      │        │  +allow-dns      │     tenant-a → :9090     │
   │                        │  +allow-same-ns  │        │  +allow-from-a   │                          │
   │                        └──────────────────┘        └──────────────────┘                          │
   │                                                                                                  │
   │  rogue: resources/admission/pod.attacker.yaml (bitnami/kubectl, root, no ctx)                    │
   │          └─▶ REJECTED at admission: image not in governed trust list (+ 8 other rules)           │
   └──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Control flow for a compliant deployment:**

1. The application repo's pipeline builds the distroless image, Trivy-scans it
   (fail on CRITICAL/HIGH), cosign-signs it, and pushes it to the governed registry
   (`docker.io/padishahiii/*`). Out of scope for this repo — SETUP_DEMO.md walks
   through exactly this for the demo apps ("Producing the demo signed images").
2. Developer pushes a change to this repo (policies, chart, values, manifests).
3. CI lints the Kyverno policies, runs the policy unit tests (`kyverno test`), and
   Trivy-scans the Helm chart + manifests. Any non-zero exit fails the build.
4. **CI installs the policies** — `kubectl apply -f policies/`. This is the policy
   execution stage: only policies that linted clean and passed their unit tests reach
   the cluster. (Violation paths are proven offline by `kyverno test`, so the
   pipeline does not re-assert them in-cluster.)
5. CD verifies the image signature with the committed cosign public key
   (`cosign-pub` credential) — the trust anchor. Unsigned or tampered image → no deploy.
6. CD packages the chart, GPG-signs it, verifies the signature with the committed
   public key, and `helm upgrade --install`s it into the tenant namespace. The
   deployment carries the attestation annotations (verified-by + digest).
7. **Kyverno validates every Pod at admission** — the annotations, image digest,
   and security contexts must satisfy all 13 policies or the Pod is rejected.
8. Post-deploy verification (in-cluster, positive only): rollout status, PolicyReports
   for the deployed workloads, NetworkPolicy behavior, RBAC `can-i` matrix, kubelet
   anonymous-access check.

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
  - The CD pipeline authenticates with the kind admin kubeconfig (the "platform
    operator" identity). In a real org this would be a dedicated CD ServiceAccount
    with a minimal per-tenant Role — noted in the README.
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
| C2 | Only scanned images admitted (Trivy) | App pipeline: trivy scan before cosign sign (SETUP_DEMO). CD: cosign verify → attestation annotations. Kyverno: annotation + digest-match | `policies/require-image-attestation.yaml`, `policies/require-image-digest.yaml`, CD pipeline |
| K1 | External API authentication | kube-apiserver OIDC → dex (static users, groups) | `kind/cluster-config.yaml`, `resources/cluster/dex.yaml` |
| K2 | Use RBAC properly | Per-tenant Roles/RoleBindings, no cluster-admin, app SAs have zero perms | `resources/cluster/rbac.yaml` |
| K3 | Limit access to kubelets | anonymous auth off, read-only port 0, webhook authz; verified with kube-bench + negative curl | `kind/cluster-config.yaml`, `tests/verify.sh` |
| N1 | Network policies (prod-like) | default-deny + explicit allows per tenant | chart `templates/networkpolicy-*.yaml` |
| S1 | Helm chart for CD, signed | one chart, GPG provenance sign + verify before deploy | `resources/helm/webapp/`, CD pipeline |

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
      Only images that passed the platform verification may run. The CD pipeline
      cosign-verifies the image and stamps the pod template with attestation
      annotations; this policy enforces their presence and that the attested
      digest matches the image actually being run.
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
          Only images verified by the CD pipeline may run.
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
          likely re-tagged or replaced after verification — re-run the pipeline.
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

Division of labor: **the application repo's pipeline owns build + scan + sign**
(out of scope for this repo — SETUP_DEMO.md shows how to produce the demo signed
images). **This repo's CD owns verify + deploy.** The cosign signature is the trust
anchor: an image is only signed after a passing Trivy scan, so *verified ⇒ scanned*.

```
app repo pipeline (out of scope — SETUP_DEMO.md)
────────────────────────────────────────────────
build (distroless) → trivy image scan (fail on CRITICAL/HIGH)
  → cosign sign --key <private key> → push to docker.io/padishahiii/*

this repo's CD
──────────────
cosign verify --key cosign-pub IMAGE@sha256:...     (fail = no deploy)
  → write rendered/values-image.yaml:
      image: docker.io/padishahiii/kube-sec-shop@sha256:...
      attestation.verifiedBy: cosign
      attestation.digest: sha256:...
  → helm template → pod template annotations:
      security.devsecops.io/image-verified: cosign
      security.devsecops.io/image-digest: sha256:...
  → helm upgrade --install ───────────▶ Kyverno require-image-attestation
                                        (annotation present AND digest == image digest)
```

- **Digest pinning** (`require-image-digest`): the CD `IMAGE` parameter is a full
  `repo@sha256:...` reference — never a mutable tag.
- **Digest match check** closes the re-tagging hole: if the registry image is
  re-tagged after verification, the attested digest no longer matches and admission
  fails.
- **Honest limitation:** the attestation annotations are mutable by anyone with
  update rights on the pod template. Mitigations in this design: (a) RBAC — only
  the platform operator (CD) updates tenant Deployments; (b) the digest-match check;
  (c) CD cosign-verifies the image *before* stamping, so a valid annotation implies
  a verified signature. The stronger production variant is cosign verification at
  admission itself (out of scope here).
### 8.3 Helm chart for CD (S1) — signed

One chart, `resources/helm/webapp/`, deployed as two releases (`shop` in tenant-a,
`analytics` in tenant-b). Pattern borrowed from `../devsecops-demo/Jenkinsfile.cd`:

- `helm package --sign --key <identity> --keyring <dearmored private key>` →
  `webapp-<ver>.tgz` + `.prov`.
- **Verify with the committed public key only** (`keys/public.asc`) before any
  deploy: `helm verify webapp-<ver>.tgz --keyring <pubring>`.
- The signed `.tgz` is the deploy artifact; `helm upgrade --install` is idempotent
  with `--create-namespace`, followed by bounded `kubectl rollout status`.
- Key management: `tools/generate-helm-signing-key.sh` writes `public.asc`
  (committed) + private key (gitignored); the private key is a Jenkins Secret-file
  credential `helm-signing-key`. Helm 4 signs with its built-in Go openpgp — the
  pipeline dearmors first (same gotcha as the sibling project).

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
imageDigest` — the same shape CD stamps per build in `rendered/values-image.yaml`,
see §8.2). CI renders these files as-is; no app data lives in the pipeline.

## 9. Demo applications

| App | Tenant | Image | Port | PVC | Notes |
| --- | --- | --- | --- | --- | --- |
| `shop` | tenant-a | `docker.io/padishahiii/kube-sec-shop` | 8080 | 100Mi, `/data` (access logs) | The "prod-like" web server. Node.js HTTP server, zero npm deps, `/health` endpoint. |
| `analytics` | tenant-b | `docker.io/padishahiii/kube-sec-analytics` | 9090 | 100Mi, `/data` (report storage) | Second app: proves multi-app, multi-tenant; target of the cross-tenant allow rule. |
| `attacker` (pod) | tenant-b | `bitnami/kubectl:latest` | — | — | **Rogue artifact** (`resources/admission/pod.attacker.yaml`): not in trust list, runs as root, no security context → rejected by multiple policies. The demo's villain. |

- The app source lives in `demo-apps/` (top-level) — it is used to **produce** the
  signed demo images (SETUP_DEMO.md); the pipeline deploys images, not code.
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

## 10. Jenkins pipelines

Jenkins runs locally (`java -jar jenkins.war --httpPort=8081`, same as the sibling
project). Two **Pipeline** jobs with SCM script paths: `workflows/Jenkinsfile.ci`
and `workflows/Jenkinsfile.cd`. (Multibranch + GitHub App is the sibling project's
setup and works here too, but is not required.)

**Credentials:** `dockerhub` (Username/Password), `cosign-pub` (Secret file — same
credential ID as the sibling repo), `kind-kubeconfig` (Secret file — used by CI's
policy install stage and by CD for deploys), `helm-signing-key` (Secret file).
**Plugins:** Pipeline Aggregator, Docker Pipeline, Credentials Binding, Workspace
Cleanup, Timestamper, Git.

### 10.1 CI — `workflows/Jenkinsfile.ci`

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
post: archive reports/kyverno-test.txt, kyverno-conformance.txt, trivy-config.txt

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

- `policy install` runs **only after** lint + unit tests + IaC scan pass (declarative
  pipeline semantics: a non-zero exit in any earlier stage aborts the build).
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
    (the official dry-run). Proves the *actual* app resources pass all 13; exit 0.
    The app manifests are **rendered from the webapp chart at CI time** (helm
    template → `kubectl create --dry-run=client` namespace stamp), not stored as
    hand-written fixtures — the chart is the single source of truth CD deploys, so
    a security-context change to the chart flips conformance in the same commit
    instead of drifting in a stale copy under tests/. Deployments are autogen-
    expanded to Pods, mirroring the real admission path; per-tenant renders land in
    `reports/conformance-rendered/` (gitignored). CI is app-agnostic: it iterates
    the developer-owned `resources/helm/webapp/values-<tenant>.yaml` files (which
    carry `image.fullRef` + `annotations.image*`) and rebuilds the namespaceSelector
    values file from the same files — adding an app = adding one values file, no
    pipeline edits.
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

### 10.2 CD — `workflows/Jenkinsfile.cd`

Parameters: `TENANT` (`tenant-a`|`tenant-b`), `IMAGE` (full digest-pinned reference,
default per tenant, e.g. `docker.io/padishahiii/kube-sec-shop@sha256:...`),
`APP_VERSION` (chart/app version label, default `1.0.0`).

```
cleanup → checkout → Initialize (param validation: IMAGE must be a @sha256: reference)
  → verify image     : cosign verify --key <cosign-pub credential> IMAGE
                         (registry auth via dockerhub credential; fail = no deploy)
  → write image values: rendered/values-image.yaml (image ref + attestation annotations), chmod 600
  → package & sign chart: helm package --sign (helm-signing-key credential)
  → verify signature   : helm verify with committed keys/public.asc ONLY
  → deploy             : helm upgrade --install <app> web-<ver>.tgz -n <TENANT>
                         -f values-<TENANT>.yaml -f rendered/values-image.yaml
                         → kubectl rollout status (bounded 5m)
  → verify             : PolicyReports, netpol behavior, RBAC can-i, kubelet check
                         (subset of tests/verify.sh)
post: archive verification evidence, chart .tgz/.prov
```

**IMAGE parameter (digest-pinned):** CD never builds, pushes, or scans images — the
image already exists in the governed registry with a cosign signature (produced per
SETUP_DEMO.md). `IMAGE` is validated to be a `@sha256:` reference, so mutable tags
cannot be deployed.

**Why no in-cluster negative test:** CD asserts only that the compliant path works.
Rejection behaviour (attacker pod, unattested image) is proven offline by
`kyverno test`; duplicating it in the pipeline would add a mutable-resource
apply/cleanup cycle to the deploy job. The rejection is still demonstrated **live
and manually** in the demo script (§14) with `resources/admission/pod.attacker.yaml`,

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
└── verify.sh                      # end-to-end cluster verification
```

- **Unit (offline):** `kyverno test tests/policies` — every policy has at least one
  compliant fixture (`result: pass`) and one violating fixture (`result: fail`).
  Runs in CI; no cluster needed.
- **Admission behaviour (offline):** `kyverno test` is where denials are asserted —
  one dir per policy, ≥1 pass + ≥1 fail fixture. No in-cluster negative tests.
- **`verify.sh` (evidence collector, positive-only):**
  1. all 13 ClusterPolicies installed, `Enforce`, and `Ready=True`;
  2. both apps Running; PolicyReports in the tenant namespaces show **0 fail**;
  3. RBAC matrix via alice/bob oidc kubeconfigs (can-i table);
  4. kubelet anonymous curl → 401/403; kube-bench node output archived;
  5. netpol: `shop` pod → `analytics:9090` succeeds (explicit allow),
     `shop` pod → external host fails (default-deny egress).

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
│   ├── shop/                    #   (SETUP_DEMO.md); the pipeline deploys images, not code
│   │   └── Dockerfile + server.js (nodejs distroless web server, :8080)
│   └── analytics/               #   Dockerfile + server.js (:9090)
├── resources/
│   ├── cluster/
│   │   ├── namespaces.yaml      # tenant-a / tenant-b (+ tenancy.io/tenant label)
│   │   ├── dex.yaml             # platform ns + dex deployment/service
│   │   └── rbac.yaml            # demo user roles & bindings
│   ├── helm/
│   │   └── webapp/              # the CD chart
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       ├── values-tenant-a.yaml
│   │       ├── values-tenant-b.yaml
│   │       ├── keys/public.asc  # committed GPG public key
│   │       └── templates/       # sa, deployment, service, pvc, netpols, role
│   └── admission/
│   └── pod.attacker.yaml    # rogue pod — manual demo rejection target
├── tests/
│   ├── policies/<policy>/       # kyverno-test.yaml + fixtures per policy
│   └── verify.sh
├── workflows/
│   ├── Jenkinsfile.ci
│   └── Jenkinsfile.cd
└── tools/
    └── generate-helm-signing-key.sh
```

## 13. Out of scope (and why)

| Item | Reason / where it lives |
| --- | --- |
| DAST (ZAP) | Sibling repo `devsecops-demo` already demonstrates in-cluster DAST + DAST-aware gate. |
| Image build/push/scan pipeline | The application repo's job. SETUP_DEMO.md walks through producing the demo signed images (build → trivy → cosign sign → push). cosign *signing* is demonstrated in `devsecops-demo`. |
| PodSecurityAdmission labels | Complementary, not alternative — PSS `restricted` ≈ policies P1–P6. Mentioned in README; explicit policies chosen for per-rule granularity and readable rejection messages. |
| Audit logging / etcd hardening | kind manages etcd; audit policy is a kube-apiserver flag demo, lower value than the controls above. |
| Service mesh / mTLS | Different layer; netpols are the demo's network control. |
| Secrets management, GitOps, quotas | Realistic additions, not core to the security story; listed as future work. |
| Gate framework (findings normalization) | Sibling repo's tools/gate.py pattern; this repo hardcodes failure gates (tool exit codes) in the pipeline — the scenario is simpler. |

## 14. Demo script (interview narrative)

1. **Green CD** — run CD with `TENANT=tenant-a` + `IMAGE=...@sha256:...`: cosign
   verify → GPG sign → deploy → rollout OK. "The pipeline is the only trusted path."
2. **Admission denial** — `kubectl apply -f resources/admission/pod.attacker.yaml`
   → rejected. Read the message: image not in trust list. "A pod that bypasses the
   pipeline cannot run."
3. **Unverified image** — hand-apply a Deployment with a compliant image but no
   attestation annotations → rejected by `require-image-attestation`. "Verification
   is enforced at admission, not just in the pipeline."
4. **Multi-tenant RBAC** — log in as `alice` via `kubectl oidc-login`: read
   tenant-a ✔, read tenant-b ✘, create a root pod → RBAC allows, Kyverno denies.
5. **Component hardening** — kubelet anonymous curl → 401; kube-bench node output;
   "external auth: the apiserver validates tokens against dex, and RBAC scopes what
   each identity can do."
6. **Network isolation** — from the shop pod: `curl analytics.tenant-b.svc:9090`
   ✔ (explicit allow), `curl <external>` ✘ (default-deny egress).

## 15. Key design decisions & trade-offs

| Decision | Rationale | Trade-off |
| --- | --- | --- |
| Kyverno over OPA/Gatekeeper | Native k8s API (CRDs), CEL + patterns, built-in PolicyReports, first-class CLI for offline testing | Less "standard" in some enterprises; Conftest/OPA is the alternative |
| One policy per rule (13) | Each user requirement maps 1:1 to a file + test dir; readable rejection messages per rule | More files; PSS labels would be one label (but opaque messages, no per-rule granularity) |
| `Enforce` in tenant ns, platform ns excluded | Two-tier governance is realistic; platform tooling (dex, kyverno) isn't PSA-restricted | Platform tier needs its own controls (out of scope) |
| Trust list in policy `variables` | Offline-testable, versioned, reviewed | Not hot-updatable without policy redeploy (ConfigMap+apiCall is the prod variant) |
| Annotation-based attestation (stamped after cosign verify) | Simple, no extra infrastructure; CD verifies before stamping; digest-match check closes re-tagging | Annotations are mutable — mitigated by RBAC + digest check; cosign-at-admission is the stronger variant |
| dex over HTTP in-cluster | Minimal moving parts for the lab | No TLS — documented; production would use LB + `--oidc-ca-file` |
| kind admin kubeconfig for CD | Simplest platform-operator identity | Real org: dedicated CD ServiceAccount + minimal per-tenant Role (noted in README) |
| cosign signature as image trust anchor | Scan happens in the app pipeline before signing (verified ⇒ scanned); CD verifies with the committed public key (`cosign-pub`) | No in-cluster signature check — attestation annotations + digest match are the admission-time proxy |
| Hardcoded exit-code gates (no gate framework) | Scenario is simple: each tool (kyverno test, trivy, cosign verify, helm verify) has a binary verdict | No cross-tool findings normalization/reporting (sibling repo has it) |
| Policies installed by **CI** (the policy execution stage) | Policies + tests live in one tree and change together; the test gate is the precondition for install | CI holds cluster credentials for two purposes (test + install); a dedicated policy job or ArgoCD would isolate that better |
| No in-cluster negative admission test | `kyverno test` already proves each rule's pass/fail behaviour offline; keeps CD deploy-only | A policy that installs but misbehaves in-cluster surfaces via PolicyReports, not a synthetic denial |

## 16. References

- Kyverno policies & CLI: `kyverno.io/docs` (ClusterPolicy, `kyverno test`, CEL validation)
- CIS Kubernetes Benchmark (kube-apiserver 1.2.x OIDC, kubelet 4.1.x)
- Pod Security Standards (baseline/restricted) — the policies P1–P6 mirror `restricted`
- Sibling repo `../devsecops-demo`: `Jenkinsfile.cd` (GPG chart signing + cosign
  sign/verify patterns, fail-closed gate), `SETUP_DEMO.md` (Jenkins/kind conventions)
- cosign / sigstore: `github.com/sigstore/cosign` (key-based signature verification)
- distroless: `gcr.io/distroless/nodejs22` (GoogleContainerTools/distroless)
