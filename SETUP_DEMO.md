# kube-security — Setup Guide

Take a fresh host from zero to "ready to run the demo". This covers everything the
**policy gate** (`workflows/Jenkinsfile.ci`) and the live demo need from the
**environment**: the hardened kind cluster (with Kyverno), Docker Hub, the cosign key
used to sign the demo images (with the commands that generate it), Jenkins + credentials
+ the job, producing the cosign-signed demo images, and the demo script itself.

**In scope:** cluster, credentials, key generation, Jenkins, image production,
demo walkthrough, troubleshooting.

**Out of scope:** **the deployment pipeline (CD).** This repo is a Kubernetes *policy
gate* demo, not an operations demo — see README.md § *What's not included*. Also out of
scope: installing tool binaries (`docker`, `kind`, `kubectl`, `helm`, `python3`, `git`).
The CI pipeline bootstraps its own `kyverno`, `trivy` and `helm` (version-pinned);
`helm`/`kubectl`/`docker` are expected on the agent.

---

## 1. Architecture

```
                     ┌───────────────────────────────────────────────┐
   push              │                Jenkins (local)                 │
 ┌────────┐          │                                                 │
 │ GitHub │──────────┼─▶  THE POLICY GATE            ┌──────────────┐  │
 │  repo  │  webhook  │  ┌──────────────────────┐    │  (operator's │  │
 └────────┘          │  │ Jenkinsfile.ci        │    │   own CD —   │  │
                     │  │ kyverno test          │    │   NOT part   │  │
                     │  │ + conformance         │    │   of this    │  │
                     │  │ + trivy config        │    │   demo)      │  │
                     │  │ → INSTALL POLICIES    │    └──────────────┘  │
                     │  └──────────┬───────────┘                       │
                     └─────────────┼───────────────────────────────────┘
                                   ▼
                     ┌──────────────────────────┐
                     │ kind cluster             │
                     │ tenant-a / tenant-b      │
                     │ + platform (dex)         │
                     │ Kyverno enforces         │
                     │ 13 ClusterPolicies       │
                     └──────────────────────────┘
```

**One pipeline, one job** — the division of labour that makes the story coherent:

- **The gate** (`Jenkinsfile.ci`) — owns *policy*. It bootstraps pinned `kyverno` +
  `trivy` + `helm`, runs the offline gates (`kyverno test` assertions + `kyverno apply`
  conformance against the developer's rendered manifests), scans the repo's IaC, lints
  the policy schemas, and only then installs the 13 ClusterPolicies into the cluster and
  waits for `Ready`. **Its only credential is the cluster kubeconfig.**
- **Developers** contribute application deployments to `resources/helm/` (a values file
  per tenant). A non-compliant manifest fails the conformance stage and the PR cannot
  merge — the gate rejects it *before* any cluster is involved.
- **Deployment (CD) is deliberately absent.** Once a gate is green, whatever the operator
  runs to deploy is outside this demo. Kyverno admission enforcement does not care who
  deployed what: any Pod created by any path is validated against the installed policies.

The cluster is **multi-tenant**: `tenant-a` (shop) and `tenant-b` (analytics) carry the
`tenancy.io/tenant: "true"` label that scopes every policy; the `platform` namespace (dex
OIDC) is deliberately *unlabeled* — two-tier governance.

---

## 2. Prerequisites (agent host)

- **Docker** (daemon + CLI) — runs `trivy` (the CI IaC scan) and hosts the kind node.
- **kind** (v0.20+), **kubectl**, **helm** (v3.14+), **python3**, **git**.
- **Jenkins** — the demo runs a local instance:
  `java -jar jenkins.war --httpPort=8081` (see §7).
- Network egress to `docker.io` (base images, demo images, trivy image), `gcr.io`
  (distroless base), and `github.com` (kyverno CLI bootstrap in CI).
- A Docker Hub account — the demo default user is `padishahiii` (§3).

> `kyverno`, `trivy` and `helm` do **not** need to be installed for CI: the pipeline
> bootstraps pinned copies into `.tools/` (reusing a matching local `kyverno` when
> present). `gpg` is **no longer needed** — chart GPG signing left with the CD pipeline.

---

## 3. Docker Hub

1. Use (or create) the Docker Hub account **`padishahiii`** — the governed image trust
   list in `policies/require-image-allowlist.yaml` is `["docker.io/padishahiii"]`, so
   **only** images from this org may run.
2. Create the two image repositories the demo produces (§10):
   - `padishahiii/kube-sec-shop`
   - `padishahiii/kube-sec-analytics`
3. Create an **access token**: Docker Hub → Account Settings → Security → New Access
   Token (read/write on both repos).

This is used **by hand** in §10 (`docker login`, `cosign sign`) to produce and sign the
demo images. **Jenkins needs no registry credential** — the gate never pulls, pushes, or
cosign-verifies images; it checks the digests and attestation annotations written in the
developer's values file, and Kyverno enforces them at admission.

---

## 4. kind cluster (hardened) + Kyverno

The cluster is created **from a config** so the hardening is visible and auditable
(§4.1). You cannot add these args to a running cluster — this must be a fresh one.

### 4.1 Create the cluster

```bash
cd kube-security

# 1. Create the hardened cluster. The name must be `kind` (default) —
#    verify.sh assumes the node container is `kind-control-plane`.
kind create cluster --name kind --config kind/cluster-config.yaml

# 2. Generate the kubeconfig.
kind get kubeconfig --name kind > kind-kubeconfig.yaml

# 3. Verify.
kubectl --kubeconfig kind-kubeconfig.yaml get nodes
```

What `kind/cluster-config.yaml` does (the "cluster hardening" story):

- **kube-apiserver**: `--authorization-mode=Node,RBAC` (RBAC is the only real authorizer)
  + **OIDC via dex** (`--oidc-issuer-url=http://dex.platform.svc:5556`, client
  `kubernetes`, username claim `email`). In-cluster HTTP for the demo; production would
  use a TLS-terminated issuer URL.
- **kubelet**: anonymous auth **disabled**, webhook authorization **enabled**, read-only
  port (10255) **disabled** — verified live by `tests/verify.sh` (anonymous `/healthz` →
  401).

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

> The **policies** themselves are installed **by the CI gate** — that is the point of the
> demo (policy as code, gated by tests). Don't `kubectl apply -f policies/` by hand; run
> the CI job (§9).

### 4.4 Jenkins credential

**`kind-kubeconfig`** (Secret file): upload `kind-kubeconfig.yaml`.

> The API-server port changes when the cluster is recreated — re-run
> `kind get kubeconfig` and update the credential. This is the **only** Jenkins
> credential the gate needs.

---

## 5. cosign key — signing the demo images

The **application repo** signs images after scanning them; the gate never verifies
signatures (that is a deploy-time concern of the operator). You need a cosign key only to
*produce* the demo images in §10 so that the tenant values files can reference real
digest-pinned, signed images.

```bash
mkdir -p keys
docker run --rm \
  -v "$PWD/keys:/wd" -w /wd \
  -e COSIGN_PASSWORD="" \
  ghcr.io/sigstore/cosign/cosign:v2.5.0 \
  generate-key-pair
# → keys/cosign.key (private) + keys/cosign.pub (public)
```

- **`keys/cosign.key`** belongs to whoever signs images (the app repo's CI). `keys/` is
  gitignored — never commit it, and in this demo it never enters Jenkins either.
- **`keys/cosign.pub`** is what a *deployer* would verify against. Keep it for §10 + the
  optional live demonstration; the gate itself does not consume it.
- `cosign.key`/`cosign.pub` were previously wired into Jenkins as the `cosign-pub` and
  `helm-signing-key` credentials for the CD pipeline. **Both credentials are gone.**

> Use an **empty passphrase** (`COSIGN_PASSWORD=""`) so signing runs non-interactively.

---

## 6. (No GitHub App needed)

Unlike the sibling repo, this demo does not use GitHub Checks or a GitHub App — the job is
a plain Pipeline (§8). A GitHub push webhook (or manual "Build now") is enough.

---

## 7. Jenkins

Run a local instance:

```bash
java -jar jenkins.war --httpPort=8081
```

**Plugins** (Manage Jenkins → Plugins → Available):

- **Pipeline** (workflow-aggregator) — the job is a scripted Pipeline.
- **Credentials Binding** — `withCredentials` (the kubeconfig).
- **Workspace Cleanup** — `cleanWs()`.
- **Timestamper** — readable stage timestamps.

The gate runs `kubectl`/`helm` CLIs directly on the agent with the `kind-kubeconfig` file
credential (no Docker Pipeline plugin needed — only `trivy` runs as a container).

---

## 8. Jenkins credentials (summary)

**One** credential, at **System** (global) scope:

| ID                | Kind        | Value / source                                   |
| ----------------- | ----------- | ------------------------------------------------ |
| `kind-kubeconfig` | Secret file | `kind get kubeconfig --name kind` (§4.4)         |

Removed together with the CD pipeline: `dockerhub` (registry auth for `cosign verify`),
`cosign-pub` (the image trust anchor), and `helm-signing-key` (chart GPG provenance).

---

## 9. Jenkins jobs

One **Pipeline** job pointing at this repo.

### 9.1 CI job — the policy gate

- New Item → **Pipeline** → name e.g. `kube-security-ci`
- **Pipeline** → Definition: *Pipeline script from SCM* → your repo →
  **Script Path:** `workflows/Jenkinsfile.ci`
- No parameters. Trigger: webhook on push, or manual.

### 9.2 CD job — removed

There is no `workflows/Jenkinsfile.cd` any more. **Delete or disable any Jenkins job still
pointing at that script path**, or it will fail with a "script not found" error, and delete
the three credentials listed in §8.

---

## 10. Producing the demo signed images

This simulates the **application repo's** pipeline (build → scan → sign → push). Do it once
per image. The point is to obtain real, registry-pushed, cosign-signed images whose
**digests** you then write into `resources/helm/webapp/values-<tenant>.yaml` so those
manifests pass `require-image-allowlist`, `require-image-digest` and
`require-image-attestation`.

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

# --- 5. Capture the digest-pinned references (→ values-<tenant>.yaml) ----
docker buildx imagetools inspect docker.io/padishahiii/kube-sec-shop:1.0.0 | grep -m1 Digest
docker buildx imagetools inspect docker.io/padishahiii/kube-sec-analytics:1.0.0 | grep -m1 Digest
# → docker.io/padishahiii/kube-sec-shop@sha256:<64 hex>
```

Put each digest into its tenant values file — **both places must match**:

```yaml
image:
  fullRef: docker.io/padishahiii/kube-sec-shop@sha256:<digest>
annotations:
  imageVerified: cosign
  imageDigest: sha256:<digest>          # same digest as fullRef
```

> **The digest is the contract.** `require-image-digest` rejects mutable tags;
> `require-image-attestation` requires `imageVerified: cosign` **and** that the annotated
> digest equals the image digest actually being run. A re-tagged image breaks the match →
> denied at admission. The gate checks this shape offline; Kyverno checks it live.

---

## 11. Running the demo

### 11.1 The gate (CI)

Build `kube-security-ci`. Expected: **green**, with the stages

`tool setup → policy unit tests (28/28) → policy conformance (chart-rendered, 28 pass) →
IaC scan (trivy config, clean) → policy schema lint (13) → policy install (kubectl apply +
wait for 13/13 Ready)`. The install stage is the only path by which policies enter the
cluster — it runs only after every gate passes.

> The conformance stage renders the webapp chart per tenant (`helm template` +
> `kubectl create --dry-run=client` namespace stamp) and applies the policies to the result
> — no hand-written app fixtures to drift out of sync with the chart.

Artifacts: `reports/kyverno-test.txt`, `reports/kyverno-conformance.txt`,
`reports/trivy-config.txt`, and `reports/conformance-rendered/*.yaml` — the exact per-tenant
manifests that cleared the gate, which is what an operator's deployment tooling would consume.

> The IaC scan skips `resources/admission/` — the attacker pod is an *intentional* rejection
> target, not a finding.

### 11.2 The negative control (the gate says NO)

This is the demo's tension, and it needs no cluster:

```bash
# Point a tenant values file at a non-governed image (or drop the annotations),
# then run the conformance check locally:
kyverno test tests/policies          # per-policy pass/fail assertions — includes denials
```

Expect `require-image-allowlist: fail` for the offending render. Commit that and the CI job
goes **red at the conformance stage** → the PR cannot merge. Revert the values file.

Equivalently, `tests/policies/*/pod-violating.yaml` are the checked-in *expected denials* —
each is asserted `result: fail` by `kyverno test`, so every rule's deny path is proven on
every build.

### 11.3 Cluster verification (operator evidence, optional)

```bash
./tests/verify.sh
```

Positive-only evidence collector: 13 policies Enforce+Ready, PolicyReports 0 fail, kubelet
anonymous → 401, netpol (shop→analytics:9090 allowed, shop→external denied). With
`ALICE_KUBECONFIG`/`BOB_KUBECONFIG` set (§11.5) it also runs the RBAC matrix. Exit 0 = all
non-skipped checks passed.

> **This script presumes workloads are running.** It belongs to the operator, not to the
> gate: sections *2. Workloads Running* and *5. NetworkPolicies* need live `shop`/`analytics`
> Deployments, which this repo no longer creates. On a cluster where only the gate has run,
> expect section 2 to report failures for the missing deployments (section 5 skips cleanly);
> the policy, RBAC, and kubelet sections pass on their own. Run it after your deployment
> tooling has put the two apps in place.

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

The pod is `bitnami/kubectl:latest` with `privileged: true`, host namespaces, root, and a
mutable tag — it trips a dozen policies. This is proven offline by `kyverno test` in the
gate; here it is shown live, and it makes the key point: **admission enforcement does not
depend on the pipeline being involved.** Whoever and whatever applies it, Kyverno denies it.

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

Expected: alice reads tenant-a ✔ / tenant-b ✘ / create ✘ (read-only role); bob mirrored.
Identities are the dex **emails** (`alice@example.com`) — the RoleBindings in
`resources/cluster/rbac.yaml` match on them.

> **Honest note:** this is the one part of the demo that can be flaky on a lab host. dex's
> configured issuer is the in-cluster name `dex.platform.svc:5556` (what the apiserver
> validates); the browser reaches dex only through the port-forward, so the issuer URL must
> be reachable from the browser for the redirect to complete. If it doesn't cooperate, the
> documented alternative is a token-webhook validator (same RBAC story). The demo works
> without OIDC — the RBAC matrix is the only section that skips.

---

## 12. Troubleshooting / gotchas

- **`KIND_NODE` / node container mismatch** — the cluster must be named `kind` so the node
  container is `kind-control-plane` (verify.sh's kubelet check `docker exec`s into it).
  Recreate with the default name otherwise.
- **Stale kubeconfig port** — recreating the cluster changes the API-server port. Re-run
  `kind get kubeconfig --name kind`, update `kind-kubeconfig`.
- **Jenkins job fails with "script not found"** — a leftover job still points at the removed
  `workflows/Jenkinsfile.cd`. Delete/disable it (§9.2).
- **cosign "no shell" / `exec: "sh": not found`** — the cosign image is distroless. Never
  wrap it in a shell script; pass the subcommand directly
  (`... cosign:v2.5.0 sign --key ...`). Registry auth via `COSIGN_REGISTRY_*` env vars, not
  flags.
- **cosign "invalid private key" / passphrase prompt** — the key must be passphrase-less
  (`COSIGN_PASSWORD=""`). Regenerate with empty passwords.
- **Gate passes but the manifest looks wrong** — check the render: the conformance stage
  writes each tenant's manifests to `reports/conformance-rendered/` (archived as build
  artifacts). Anything not in that render is not what was checked.
- **`kyverno apply` shows `pass: 0, fail: 0`** — two known causes: you forgot the
  namespaceSelector values file (labels not injected — CI rebuilds it from the tenant values
  files), or the rendered app resources carry no `metadata.namespace` — `helm template` does
  not stamp one, and namespaceSelector rules silently Exclude without it. The CI stage
  handles both (values file + `kubectl create --dry-run=client -n <ns>`); if you hand-roll
  the render, keep both steps.
- **Pod deletions denied by Kyverno** — if you see `no such key: spec` in a webhook denial on
  a DELETE, your policies are missing the `!has(object.spec) || (...)` guard (Kyverno's
  webhook is registered for DELETE too). The policies in this repo carry the guard — don't
  strip it when forking. See DESIGN.md §10.1.
