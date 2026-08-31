# kube-security — Setup Guide

Take a fresh host from zero to "ready to run the demo". This covers everything
the two pipelines (`workflows/Jenkinsfile.ci`, `workflows/Jenkinsfile.cd`) and
the live demo need from the **environment**: the hardened kind cluster (with
Kyverno), Docker Hub, the signing keys (with the commands that generate them),
Jenkins + credentials + jobs, producing the cosign-signed demo images, and the
demo script itself.

**In scope:** cluster, credentials, key generation, Jenkins, image production,
demo walkthrough, troubleshooting.

**Out of scope:** installing tool binaries (`docker`, `kind`, `kubectl`,
`helm`, `gpg`, `python3`, `git`). The CI pipeline bootstraps its own `kyverno`
and `trivy` (version-pinned); `helm`/`kubectl`/`gpg`/`docker` are expected on
the agent.

---

## 1. Architecture

```
                     ┌───────────────────────────────────────────────┐
   push              │                Jenkins (local)                │
 ┌────────┐          │  ┌─────────────┐           ┌────────────────┐ │
 │ GitHub │──────────┼─▶│ CI job      │           │ CD job         │ │
 │  repo  │  webhook  │  │Jenkinsfile.ci│          │ Jenkinsfile.cd │ │
 └────────┘          │  │ kyverno test│           │ cosign verify  │ │
                     │  │ + conformance│          │ → chart GPG    │ │
                     │  │ + trivy cfg │           │   sign+verify  │ │
                     │  │ → install   │           │ → helm deploy  │ │
                     │  │   policies  │           │ → verify       │ │
                     │  └──────┬──────┘           └───────┬────────┘ │
                     └─────────┼──────────────────────────┼──────────┘
                               ▼                          ▼
                     ┌─────────────────┐        ┌────────────────────┐
                     │  Docker Hub     │        │ kind cluster       │
                     │ signed images   │───────▶│ tenant-a / tenant-b│
                     │ (cosign sigs)   │        │ + platform (dex)   │
                     └─────────────────┘        │ Kyverno enforces   │
                                                │ 13 ClusterPolicies │
                                                └────────────────────┘
```

Two pipelines, one repo, **one division of labour** (the core of the story):

- **CI** (`Jenkinsfile.ci`) — the *policy* pipeline. Bootstraps a pinned
  `kyverno` + `trivy`, runs the offline gates (`kyverno test` assertions +
  `kyverno apply` conformance), scans the repo's IaC, then — and only then —
  installs the 13 ClusterPolicies into the cluster and waits for `Ready`.
  **No credentials except the cluster kubeconfig.**
- **CD** (`Jenkinsfile.cd`) — the *deployment* pipeline. It does **not** build,
  push, or scan images (that is the application repo's job). It takes a
  digest-pinned `IMAGE`, **cosign-verifies** it against the committed public
  key, stamps the attestation annotations, packages + **GPG-signs** the Helm
  chart, verifies the signature, and deploys into the tenant namespace. A
  tampered or unsigned image never reaches the cluster.

The cluster is **multi-tenant**: `tenant-a` (shop) and `tenant-b` (analytics)
carry the `tenancy.io/tenant: "true"` label that scopes every policy; the
`platform` namespace (dex OIDC) is deliberately *unlabeled* — two-tier
governance.

---

## 2. Prerequisites (agent host)

- **Docker** (daemon + CLI) — runs `trivy`, `cosign` (the cosign image is
  distroless; we always `docker run` it) and hosts the kind node.
- **kind** (v0.20+), **kubectl**, **helm** (v3.14+), **gpg** (GnuPG 2.x),
  **python3**, **git**.
- **Jenkins** — the demo runs a local instance:
  `java -jar jenkins.war --httpPort=8081` (see §7).
- Network egress to `docker.io` (base images, demo images, trivy/cosign
  images), `ghcr.io` (cosign image), `gcr.io` (distroless base), and
  `github.com` (kyverno CLI bootstrap in CI).
- A Docker Hub account — the demo default user is `padishahiii` (§3).

> `kyverno` and `trivy` do **not** need to be installed: CI bootstraps pinned
> copies into `.tools/` (reusing a matching local `kyverno` when present).

---

## 3. Docker Hub

1. Use (or create) the Docker Hub account **`padishahiii`** — the governed
   image trust list in `policies/require-image-allowlist.yaml` is
   `["docker.io/padishahiii"]`, so **only** images from this org may run.
2. Create the two image repositories the demo produces (§9):
   - `padishahiii/kube-sec-shop`
   - `padishahiii/kube-sec-analytics`
3. Create an **access token**: Docker Hub → Account Settings → Security →
   New Access Token (read/write on both repos).

**Jenkins credential** `dockerhub` (Username with password):

- Username: `padishahiii`
- Password: `<access token>`

CD uses it for registry auth during `cosign verify` (via
`COSIGN_REGISTRY_*` env vars — never CLI flags).

---

## 4. kind cluster (hardened) + Kyverno

The cluster is created **from a config** so the hardening is visible and
auditable (§4.1). You cannot add these args to a running cluster — this must
be a fresh one.

### 4.1 Create the cluster

```bash
cd kube-security

# 1. Create the hardened cluster. The name must be `kind` (default) —
#    verify.sh and the CD pipeline assume the node container
#    `kind-control-plane`.
kind create cluster --name kind --config kind/cluster-config.yaml

# 2. Generate the kubeconfig.
kind get kubeconfig --name kind > kind-kubeconfig.yaml

# 3. Verify.
kubectl --kubeconfig kind-kubeconfig.yaml get nodes
```

What `kind/cluster-config.yaml` does (the "cluster hardening" story):

- **kube-apiserver**: `--authorization-mode=Node,RBAC` (RBAC is the only real
  authorizer) + **OIDC via dex** (`--oidc-issuer-url=http://dex.platform.svc:5556`,
  client `kubernetes`, username claim `email`). In-cluster HTTP for the demo;
  production would use a TLS-terminated issuer URL.
- **kubelet**: anonymous auth **disabled**, webhook authorization **enabled**,
  read-only port (10255) **disabled** — verified live by `tests/verify.sh`
  (anonymous `/healthz` → 401).

### 4.2 Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace
kubectl -n kyverno wait --for=condition=Ready pod -l app.kubernetes.io/name=kyverno --timeout=300s
```

### 4.3 Apply the cluster resources

```bash
# Tenant + platform namespaces (the tenancy.io/tenant label is the boundary),
# dex (OIDC provider, hardened: config in a Secret, non-root, read-only rootfs),
# and the least-privilege RBAC (alice → read tenant-a, bob → read tenant-b).
kubectl apply -f resources/cluster/
```

> The policies themselves are installed **by the CI pipeline** — that is the
> point of the demo (policy as code, gated by tests). Don't `kubectl apply -f
> policies/` by hand; run the CI job (§10.1).

### 4.4 Jenkins credential

**`kind-kubeconfig`** (Secret file): upload `kind-kubeconfig.yaml`.

> The API-server port changes when the cluster is recreated — re-run
> `kind get kubeconfig` and update the credential.

---

## 5. Signing keys

### 5.1 cosign — image signing (the trust anchor for CD)

The **application repo** signs images after scanning; CD only **verifies**.
Generate a key pair (the cosign image is distroless — no shell, so run the
subcommand directly; its entrypoint is already `cosign`):

```bash
mkdir -p keys
docker run --rm \
  -v "$PWD/keys:/wd" -w /wd \
  -e COSIGN_PASSWORD="" \
  ghcr.io/sigstore/cosign/cosign:v2.5.0 \
  generate-key-pair
# → keys/cosign.key (private) + keys/cosign.pub (public)
```

- **`keys/cosign.key`** stays in the *application* repo's CI (never in this
  repo, never in CD).
- **`keys/cosign.pub`** → Jenkins credential **`cosign-pub`** (Secret file).
  CD verifies against it; it is the trust anchor.

> Use an **empty passphrase** (`COSIGN_PASSWORD=""`) — the pipeline signs
> non-interactively.

### 5.2 Helm chart signing — GPG provenance

```bash
./tools/generate-helm-signing-key.sh "kube-security chart signing" "charts@devsecops.local"
```

The script:

1. Generates an RSA key **with the `sign,cert` usage flags** — the `sign` flag
   is **required**: Helm 4's go-crypto matches signatures via
   `KeysByIdUsage(issuerKeyId, KeyFlagSign)`, so a `cert`-only key loads but
   never matches (`signature made by unknown entity`).
2. Prints the **armored private key** — copy it into Jenkins credential
   **`helm-signing-key`** (Secret file).
3. Writes the public key to `resources/helm/webapp/keys/public.asc` — the repo
   already ships one (committed); if you regenerate, commit the new public key
   and keep the private key only in Jenkins.

CD dearmors both keys at runtime (Helm 4 rejects armored keyrings) and derives
the `--key` identity from the committed public key.

---

## 6. (No GitHub App needed)

Unlike the sibling repo, this demo does not use GitHub Checks or a GitHub App
— the jobs are plain Pipelines (§8). A GitHub push webhook (or manual "Build
now") is enough.

---

## 7. Jenkins

Run a local instance:

```bash
java -jar jenkins.war --httpPort=8081
```

**Plugins** (Manage Jenkins → Plugins → Available):

- **Pipeline** (workflow-aggregator) — the jobs are scripted Pipelines.
- **Credentials Binding** — `withCredentials` (both jobs).
- **Kubernetes** is *not* required (the pipelines use the `kubectl`/`helm`
  CLIs with the `kind-kubeconfig` file credential).

---

## 8. Jenkins credentials (summary)

All at **System** (global) scope. Four credentials total:

| ID               | Kind                   | Value / source                          |
| ---------------- | ---------------------- | --------------------------------------- |
| `dockerhub`      | Username with password | Docker Hub user + access token (§3)     |
| `cosign-pub`     | Secret file            | `keys/cosign.pub` (§5.1)                |
| `kind-kubeconfig`| Secret file            | `kind get kubeconfig --name kind` (§4)  |
| `helm-signing-key` | Secret file          | armored private key from `tools/generate-helm-signing-key.sh` (§5.2) |

---

## 9. Jenkins jobs

Two **Pipeline** jobs pointing at this repo.

### 9.1 CI job

- New Item → **Pipeline** → name e.g. `kube-security-ci`
- **Pipeline** → Definition: *Pipeline script from SCM* → your repo →
  **Script Path:** `workflows/Jenkinsfile.ci`
- No parameters. Trigger: webhook on push, or manual.

### 9.2 CD job

- New Item → **Pipeline** → name e.g. `kube-security-cd`
- **Pipeline** → Definition: *Pipeline script from SCM* → same repo →
  **Script Path:** `workflows/Jenkinsfile.cd`

CD parameters (set at build time):

| Parameter     | Default                              | Meaning                                                            |
| ------------- | ------------------------------------ | ------------------------------------------------------------------ |
| `TENANT`      | `tenant-a`                           | `tenant-a` = shop :8080, `tenant-b` = analytics :9090              |
| `IMAGE`       | `docker.io/padishahiii/kube-sec-shop@sha256:REPLACE…` | **Digest-pinned** reference — validated; mutable tags are rejected |
| `APP_VERSION` | `1.0.0`                              | app version label (valid docker tag, ≤63 chars)                    |

---

## 10. Producing the demo signed images

This simulates the **application repo's** pipeline (build → scan → sign →
push). CD in this repo only *verifies* the result. Run it once per image.

```bash
cd kube-security

# --- 1. Build (distroless nodejs, non-root, read-only rootfs) ------------
docker build -t docker.io/padishahiii/kube-sec-shop:1.0.0 demo-apps/shop/
docker build -t docker.io/padishahiii/kube-sec-analytics:1.0.0 demo-apps/analytics/

# --- 2. Scan (the app repo's gate — clean before signing) ----------------
docker run --rm aquasec/trivy:0.74.0 image \
  --severity CRITICAL,HIGH --exit-code 1 \
  docker.io/padishahiii/kube-sec-shop:1.0.0
docker run --rm aquasec/trivy:0.74.0 image \
  --severity CRITICAL,HIGH --exit-code 1 \
  docker.io/padishahiii/kube-sec-analytics:1.0.0

# --- 3. Push --------------------------------------------------------------
docker login   # padishahiii + access token
docker push docker.io/padishahiii/kube-sec-shop:1.0.0
docker push docker.io/padishahiii/kube-sec-analytics:1.0.0

# --- 4. Sign (cosign — signature manifests go to the registry) -----------
docker run --rm \
  -v "$PWD/keys:/keys" \
  -e COSIGN_PASSWORD="" \
  -e COSIGN_REGISTRY_USERNAME="padishahiii" \
  -e COSIGN_REGISTRY_PASSWORD="<token>" \
  ghcr.io/sigstore/cosign/cosign:v2.5.0 \
  sign --key /keys/cosign.key docker.io/padishahiii/kube-sec-shop:1.0.0
docker run --rm \
  -v "$PWD/keys:/keys" \
  -e COSIGN_PASSWORD="" \
  -e COSIGN_REGISTRY_USERNAME="padishahiii" \
  -e COSIGN_REGISTRY_PASSWORD="<token>" \
  ghcr.io/sigstore/cosign/cosign:v2.5.0 \
  sign --key /keys/cosign.key docker.io/padishahiii/kube-sec-analytics:1.0.0

# --- 5. Capture the digest-pinned references (for the CD IMAGE param) -----
docker buildx imagetools inspect docker.io/padishahiii/kube-sec-shop:1.0.0 | grep -m1 Digest
docker buildx imagetools inspect docker.io/padishahiii/kube-sec-analytics:1.0.0 | grep -m1 Digest
# → docker.io/padishahiii/kube-sec-shop@sha256:<64 hex>
```

> **The digest is the contract.** CD validates `IMAGE` against
> `@sha256:[a-f0-9]{64}`, stamps `image.fullRef` + the attestation annotations
> (`security.devsecops.io/image-verified=cosign`, `image-digest=<digest>`),
> and the Kyverno `require-image-attestation` policy checks the annotation
> equals the image's digest. A re-tagged image breaks the match → denied.

---

## 11. Running the demo

### 11.1 CI (policy pipeline)

Build `kube-security-ci`. Expected: **green**, with the stages

`tool setup → policy unit tests (28/28) → policy conformance (chart-rendered,
28 pass) → IaC scan (trivy config, clean) → policy schema lint (13) → policy
install (kubectl apply + wait for 13/13 Ready)`. The install stage is the only
path by which policies enter the cluster — it runs only after every gate passes.

> The conformance stage renders the webapp chart per tenant (helm template +
> `kubectl create --dry-run=client` namespace stamp) and applies the policies to
> the result — no hand-written app fixtures to drift out of sync with the chart.
by which policies enter the cluster — it runs only after every gate passes.

Artifacts: `reports/kyverno-test.txt`, `reports/kyverno-conformance.txt`,
`reports/trivy-config.txt`.

> The IaC scan skips `resources/admission/` — the attacker pod is an
> *intentional* rejection target, not a finding.

### 11.2 CD (deployment pipeline)

Build `kube-security-cd` with, e.g.:

- `TENANT=tenant-a`
- `IMAGE=docker.io/padishahiii/kube-sec-shop@sha256:<digest from §10>`
- `APP_VERSION=1.0.0`

Expected: **green**, with the stages

`cleanup → checkout → Initialize (IMAGE validated) → verify image - cosign →
write image values → package & sign chart (GPG) → deploy (helm + rollout) →
verify (PolicyReports / RBAC / netpol / node evidence)`.

Then deploy the second tenant: `TENANT=tenant-b`,
`IMAGE=docker.io/padishahiii/kube-sec-analytics@sha256:<digest>`.

**The negative control (by hand):** build CD with an *unsigned* or *wrong*
digest → the `verify image - cosign` stage fails (`no matching signatures`)
and nothing is deployed. That is the supply-chain gate working.

### 11.3 Cluster verification

```bash
./tests/verify.sh
```

Positive-only evidence collector: 13 policies Enforce+Ready, both apps
Running, PolicyReports 0 fail, kubelet anonymous → 401, netpol
(shop→analytics:9090 allowed, shop→external denied). With
`ALICE_KUBECONFIG`/`BOB_KUBECONFIG` set (§11.5) it also runs the RBAC matrix.
Exit 0 = all non-skipped checks passed.

### 11.4 Live admission rejection (the money shot)

```bash
kubectl apply -f resources/admission/pod.attacker.yaml -n tenant-a
```

Expected:

```
Error: admission webhook "validate.kyverno.svc-fail" denied the request:
resource Pod/tenant-a/attacker was blocked due to the following policies
  disallow-privileged-containers: ...
  require-image-allowlist: ... (bitnami/kubectl is not in the trust list)
  ... (multiple policies)
```

The pod is `bitnami/kubectl:latest` with `privileged: true`, host namespaces,
root, and mutable tag — it trips a dozen policies. This is proven offline by
`kyverno test` in CI; here it is shown live.

### 11.5 RBAC matrix (dex OIDC)

```bash
# 1. Expose dex to the host (in-cluster HTTP for the demo).
kubectl port-forward -n platform svc/dex 5556:5556 &

# 2. Log in as each demo user (plugin: kubectl-oidc-login).
#    dex users: alice/alice (tenant-a), bob/bob (tenant-b).
#    --url is the local callback the plugin listens on; the browser reaches
#    dex through the port-forward above.
kubectl oidc-login login \
  --url http://127.0.0.1:18001/callback \
  --oidc-issuer-url http://127.0.0.1:5556 > alice.kubeconfig
# (repeat for bob with a different callback port, e.g. 18002)

# 3. Run the matrix.
ALICE_KUBECONFIG=$PWD/alice.kubeconfig \
BOB_KUBECONFIG=$PWD/bob.kubeconfig \
./tests/verify.sh
```

Expected: alice reads tenant-a ✔ / tenant-b ✘ / create ✘ (read-only role);
bob mirrored. Identities are the dex **emails** (`alice@example.com`) — the
RoleBindings in `resources/cluster/rbac.yaml` match on them.

> **Honest note:** this is the one part of the demo that can be flaky on a lab
> host. dex's configured issuer is the in-cluster name `dex.platform.svc:5556`
> (what the apiserver validates); the browser reaches dex only through the
> port-forward, so the issuer URL must be reachable from the browser for the
> redirect to complete. If it doesn't cooperate, the documented alternative is
> a token-webhook validator (same RBAC story). The demo works without OIDC —
> the RBAC matrix is the only section that skips.

---

## 12. Troubleshooting / gotchas

- **`KIND_NODE` / node container mismatch** — the cluster must be named
  `kind` so the node container is `kind-control-plane` (verify.sh's kubelet
  check `docker exec`s into it). Recreate with the default name otherwise.
- **Stale kubeconfig port** — recreating the cluster changes the API-server
  port. Re-run `kind get kubeconfig --name kind`, update `kind-kubeconfig`.
- **cosign "no shell" / `exec: "sh": not found`** — the cosign image is
  distroless. Never wrap it in a shell script; pass the subcommand directly
  (`... cosign:v2.5.0 verify --key ...`). Registry auth via
  `COSIGN_REGISTRY_*` env vars, not flags.
- **cosign "invalid private key" / passphrase prompt** — the key must be
  passphrase-less (`COSIGN_PASSWORD=""`). Regenerate with empty passwords.
- **helm "signature made by unknown entity"** — the GPG key lacks the **sign**
  usage flag. Regenerate with `tools/generate-helm-signing-key.sh` (uses
  `rsa2048 sign,cert`). Also: Helm 4 needs **binary** keyrings — the pipeline
  dearmors; a hand-run `helm verify` must `gpg --dearmor` first.
- **helm "private key not found"** — `helm-signing-key` must be the **armored**
  private key (the pipeline dearmors it), and
  `resources/helm/webapp/keys/public.asc` must match it.
- **CD deploys but the pod is `ImagePullBackOff`** — the `IMAGE` digest must
  be the **registry** manifest digest (§10 step 5), and the image must be
  pushed + signed. If you're testing with a locally-`kind load`ed image, the
  node-store digest differs from the build digest (OCI rewrite) — add the
  alias: `docker exec kind-control-plane ctr -n k8s.io images tag
  <repo:tag> <repo@sha256:<store-digest>>`.
- **Pods stuck `Pending` after a deploy** — usually the previous pod pins the
  RWO PVC. Delete the stale pod (the policies allow deletion — see below) or
  `helm upgrade` to recreate the PVC.
- **Pod deletions denied by Kyverno** — if you see `no such key: spec` in a
  webhook denial on a DELETE, your policies are missing the
  `!has(object.spec) || (...)` guard (Kyverno's webhook is registered for
  DELETE too). The policies in this repo carry the guard — don't strip it
  when forking. See DESIGN.md §10.1.
- **`kyverno apply` shows `pass: 0, fail: 0`** — two known causes: you forgot the
  namespaceSelector values file (labels not injected — CI rebuilds it from the tenant
  values files), or the
  rendered app resources carry no `metadata.namespace` — `helm template` does not
  stamp one, and namespaceSelector rules silently Exclude without it. The CI
  stage handles both (values file + `kubectl create --dry-run=client -n <ns>`);
  if you hand-roll the render, keep both steps.
