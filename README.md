# kube-security

A demo of **defense-in-depth Kubernetes security** on a single-node kind cluster,
enforced by a **Jenkins pipeline** — CI gates the Kyverno policies and the Helm
chart, CD **verifies cosign-signed images** and deploys them with a **GPG-signed
Helm chart** — with an **image trust list**, multi-tenant RBAC, NetworkPolicies, and
**external API authentication** (OIDC via dex).

The core idea: **the pipeline is the only trusted path.** Images are produced by the
application repo's pipeline (build → Trivy scan → **cosign sign** → push —
SETUP_DEMO.md walks through producing the demo signed images) and reach the cluster
only through this repo's CD pipeline (**cosign verify** → GPG-signed chart → deploy).
Anything that bypasses it is rejected at admission with a readable message.

- 📐 Design: [`docs/DESIGN.md`](docs/DESIGN.md)
- 🛠 Setup: [`SETUP_DEMO.md`](SETUP_DEMO.md)

## Quick demo

```bash
# 1. Compliant app deploys green via the CD pipeline (TENANT=tenant-a)

# 2. Rogue pod is rejected at admission
kubectl apply -f resources/admission/pod.attacker.yaml
# Error: ... image "bitnami/kubectl:latest" is not in the governed image trust list ...

# 3. Tenant isolation: log in as alice (OIDC), try to read tenant-b
kubectl oidc-login login
kubectl auth can-i get pods -n tenant-b   # no
```

## Directory Structure

```
kube-security/
├── README.md                    # this file
├── SETUP_DEMO.md                # prerequisites: kind cluster, Jenkins, dex, credentials,
│                                #   + producing the demo signed images (build → trivy → cosign sign)
├── docs/
│   └── DESIGN.md                # full design: architecture, controls, pipelines, trade-offs
├── kind/
│   └── cluster-config.yaml      # kind config: OIDC (external auth) args + kubelet hardening
├── policies/                    # Kyverno ClusterPolicies — one file per security rule
├── resources/
│   ├── cluster/                 # tenant namespaces, dex (OIDC), demo-user RBAC
│   ├── helm/
│   │   └── webapp/              # the Helm chart used by CD (GPG-signed at deploy time)
│   └── admission/
│       └── pod.attacker.yaml    # rogue pod — the demo's rejection target
├── demo-apps/                   # demo app source — for PRODUCING the signed images
│   ├── shop/                    # tenant-a: nodejs distroless web server :8080 + PVC (logs)
│   └── analytics/               # tenant-b: nodejs API :9090 + PVC (report data)
├── tests/
│   ├── policies/<policy>/       # kyverno test files: ≥1 pass + ≥1 fail fixture per policy
│   ├── admission/               # in-cluster negative manifests
│   └── verify.sh                # end-to-end cluster verification (RBAC matrix, kubelet, netpol)
├── workflows/
│   ├── Jenkinsfile.ci           # policy lint + policy unit tests + trivy IaC scan (exit-code gates)
│   └── Jenkinsfile.cd           # cosign verify → GPG-signed chart deploy → verify → negative test
└── tools/
    └── generate-helm-signing-key.sh
```

## How to add an application deployment

The pipeline deploys **one app per run** (`TENANT` parameter selects the target).
Images are built and signed by the application repo's pipeline — for the demo, that
is the one-time "Producing the demo signed images" section in SETUP_DEMO.md. To add
a new app (or a new tenant):

1. **Write the app** under `demo-apps/<app>/`:
   - `Dockerfile` from `gcr.io/distroless/nodejs22` (or another governed base),
     `USER node` (non-root), listen on a port **> 1023** (non-root can't bind <1024).
   - No shell, no setuid — distroless keeps the surface small.
2. **Produce the signed image** (SETUP_DEMO.md): build → `trivy image --severity
   CRITICAL,HIGH --exit-code 1` → `cosign sign` → push to the governed org
   (`padishahiii/…` on Docker Hub). Note the image **digest**.
3. **Add tenant values** — copy `resources/helm/webapp/values-tenant-a.yaml` to
   `values-<tenant>.yaml` and set: `name`, `port`, PVC size, and the ingress-allow
   peers (which namespaces may call this app).
   - If it's a **new tenant**: add the namespace (labeled `tenancy.io/tenant: "true"`
     in `resources/cluster/namespaces.yaml`) and a per-tenant Role/RoleBinding in
     `resources/cluster/rbac.yaml`. That's all — the policies pick up the new
     namespace automatically via the label selector.
4. **Run the CD pipeline** with `TENANT=<tenant>` and
   `IMAGE=padishahiii/<app>@sha256:<digest>`: it cosign-verifies the image,
   GPG-signs the chart, and `helm upgrade --install`s it (stamping the attestation
   annotations). Kyverno validates the resulting Pods at admission.
5. **Add tests**:
   - If your app needs a new cross-tenant network allow, update the netpol fixtures
     and `tests/verify.sh` expectations.
   - Policy tests live per-policy under `tests/policies/` — add fixtures there only
     if you changed a policy.
6. **Do NOT** hand-`kubectl apply` into tenant namespaces — that bypasses the
   attestation and will be rejected by `require-image-attestation`.

## Policies introduction & security considerations

All policies are Kyverno `ClusterPolicy` resources with `validationFailureAction:
Enforce`, scoped to namespaces labeled `tenancy.io/tenant: "true"` (tenant tier —
platform namespaces like `kyverno`/`platform` are governed separately). Every policy
has offline unit tests (`kyverno test tests/policies`) that run in CI.

| Policy file | Security consideration |
| --- | --- |
| `require-non-root.yaml` | Application processes must not run as root (`runAsNonRoot: true`). |
| `disallow-privilege-escalation.yaml` | `allowPrivilegeEscalation: false` on every container (blocks e.g. setuid binaries, `CAP_SYS_PTRACE`-style escalation). |
| `require-readonly-rootfs.yaml` | `readOnlyRootFilesystem: true` — a compromised process can't drop tools, persist, or tamper with its own filesystem. Writable state goes to explicit volumes (PVC). |
| `require-default-proc-mount.yaml` | Rejects `procMount: Unmasked` — the default (masked) /proc hides kernel memory and other processes' `/proc/<pid>/mem`. |
| `disallow-host-namespaces.yaml` | No `hostNetwork`/`hostPID`/`hostIPC`. Host networking would also silently bypass NetworkPolicies — the pod would talk on the host's interfaces. |
| `require-drop-all-capabilities.yaml` | `capabilities.drop: [ALL]` — no unused Linux capabilities; add back only what a workload provably needs. |
| `require-selinux-options.yaml` | Requires `seLinuxOptions.level` — fine-grained MAC labels. *Honest caveat:* the kind node doesn't run SELinux, so this enforces spec-level conformance in the lab; on an SELinux-enabled node the runtime enforces it for real. |
| `require-dedicated-serviceaccount.yaml` | Each app gets its own ServiceAccount; the shared `default` SA is forbidden (no identity sharing, clean audit trail). |
| `require-automount-sa-token-false.yaml` | Apps that don't call the Kubernetes API get no mounted SA credentials — removes a classic lateral-movement artifact. |
| `disallow-privileged-containers.yaml` | Defense in depth: `privileged: true` is never allowed (full device access + most caps). |
| `require-image-allowlist.yaml` | **Governed image trust list** — only images from `docker.io/padishahiii/*` (the org the platform builds & scans) may run. The list is a versioned `variables` block in the policy, reviewed like code. (Production variant: ConfigMap + `apiCall` for hot updates — see DESIGN.md §6.2.) |
| `require-image-digest.yaml` | Images must be referenced by `@sha256:` digest — no mutable tags in deployments. |
| `require-image-attestation.yaml` | **Only verified images admitted.** The application pipeline Trivy-scans the image *before* cosign-signing it; CD cosign-verifies it and stamps the pod template with `security.devsecops.io/image-verified=cosign` + the attested digest; this policy requires both the annotation **and** that the attested digest matches the running image (closes the re-tag-after-verify hole). |

**Cluster-level controls** (not Kyverno):

- **External API authentication** — kube-apiserver validates bearer tokens against
  an external OIDC issuer (dex in `platform` ns); identities + groups flow into RBAC.
  See `kind/cluster-config.yaml` and SETUP_DEMO.md.
- **RBAC properly** — no human has cluster-admin; per-tenant Role/RoleBindings
  (alice→tenant-a, bob→tenant-b); app ServiceAccounts have *zero* API permissions.
- **Kubelet access limited** — anonymous auth off, read-only port 0, webhook
  authorization; verified by `tests/verify.sh` (anonymous curl → 401) and kube-bench.
- **NetworkPolicies** — default-deny ingress+egress per tenant; explicit allows only
  (DNS; same-ns; tenant-a → tenant-b:9090, simulating frontend→backend).

**Security considerations baked into the pipeline** (see DESIGN.md §10):

- **Hardcoded gates, no gate framework:** each tool's exit code fails the build —
  `kyverno test`, `trivy --exit-code 1`, `cosign verify`, `helm verify`. The scenario
  is simple enough that a findings-normalization layer (sibling repo) would be overhead.
- **Digest-pinned images:** CD takes an `IMAGE` parameter that must be a
  `repo@sha256:...` reference — it never builds, pushes, or scans images; that is
  the application repo's job.
- Helm chart is GPG-signed and verified (committed public key only) before deploy —
  provenance for the deploy artifact.
- Negative admission test in CD: the attacker pod *must* be rejected, and a
  "successful" apply fails the build.

## What's included

- 13 Kyverno ClusterPolicies (pod security, image governance) + per-policy unit tests
- Multi-tenant model: 2 tenant namespaces, per-tenant RBAC, per-app ServiceAccounts,
  default-deny NetworkPolicies with explicit cross-tenant allow
- Demo apps: nodejs **distroless** web servers with PVCs (shop, analytics) + a rogue
  attacker pod
- Jenkins **CI**: policy lint, `kyverno test`, Trivy IaC/config scan — hardcoded
  exit-code gates
- Jenkins **CD**: cosign verify (trust anchor) → GPG-signed Helm chart → deploy →
  verification → negative admission test
- Image trust anchor: **cosign signature verification** (committed public key,
  `cosign-pub` credential — same ID as the sibling repo)
- Component hardening: external API auth (OIDC/dex), least-privilege RBAC, restricted
  kubelet (verified with kube-bench + negative requests)

## What's not included

- **DAST** — covered by the sibling repo `devsecops-demo` (in-cluster ZAP + DAST-aware gate)
- **Image build/push/scan pipeline** — the application repo's job; SETUP_DEMO.md
  walks through producing the demo signed images (build → trivy → cosign sign → push).
  cosign *signing* itself is demonstrated in `devsecops-demo`.
- **Gate framework** (sibling repo's findings normalization) — this repo hardcodes
  failure gates (tool exit codes) in the pipeline
- **PodSecurityAdmission labels** — complementary to these policies (PSS `restricted`
  ≈ P1–P6); explicit per-rule policies were chosen for granularity and readable
  rejection messages
- **Audit logging, etcd hardening, node hardening** — kind-managed or lower demo
  value; kube-bench is used for evidence, not as a control
- **Service mesh / mTLS, secrets management (SOPS/SealedSecrets), GitOps (ArgoCD),
  ResourceQuota/LimitRange, DR** — realistic additions, listed as future work in
  DESIGN.md §13
