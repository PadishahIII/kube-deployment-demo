# kube-security

A single-node kind cluster demonstrating **defense-in-depth Kubernetes security**, with
**Jenkins CI as a Kubernetes policy gate**: the only path by which Kyverno cluster policy
is tested and installed.

**Scope: this repo is the policy gate, not the deployment pipeline.** It is owned by the
**cluster operator**. Developers contribute application deployments under
`resources/helm/`; this repo's CI decides whether each manifest may run in a tenant
namespace, and then installs the policies that made that decision. Deploying workloads is
the operator's job, so **no CD pipeline ships here** — see *What's not included*.

The core idea: **policy is code, and the gate is the only trusted path.** Policies live in
this repo with offline unit tests; a policy that has not passed its tests is never
installed, and a developer manifest that violates the installed set never gets through CI.
Whatever finally runs in-cluster is admitted or rejected by those policies — regardless of
who or what deployed it.

- 📐 Design: [`docs/DESIGN.md`](docs/DESIGN.md)
- 🛠 Setup: [`SETUP_DEMO.md`](SETUP_DEMO.md)

## Quick demo

```bash
# 1. Run the gate (offline stages need no cluster; install does)
kyverno test tests/policies                      # every policy's pass AND deny behaviour
kyverno apply policies/ -r <rendered manifests>  # conformance — see §How to add a deployment

# 2. Jenkins version of the same thing (SETUP_DEMO.md §9): the CI job, expected GREEN:
#    tool setup → policy unit tests → policy conformance → IaC scan
#    → policy schema lint → policy install

# 3. A rogue pod is rejected at admission (the gate installed these policies as Enforce)
kubectl apply -f resources/admission/pod.attacker.yaml -n tenant-a
# Error: ... image "bitnami/kubectl:latest" is not in the governed image trust list ...

# 4. Tenant isolation: log in as alice (OIDC), try to read tenant-b
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
│   └── DESIGN.md                # full design: architecture, controls, the gate, trade-offs
├── kind/
│   └── cluster-config.yaml      # kind config: OIDC (external auth) args + kubelet hardening
├── policies/                    # Kyverno ClusterPolicies — one file per security rule
├── resources/
│   ├── cluster/                 # tenant namespaces, dex (OIDC), demo-user RBAC
│   ├── helm/
│   │   └── webapp/              # developer-owned deployments — the gate renders + checks these
│   └── admission/
│       └── pod.attacker.yaml    # rogue pod — manual demo rejection target
├── demo-apps/                   # demo app source — for PRODUCING the signed images
│   ├── shop/                    # tenant-a: nodejs distroless web server :8080 + PVC (logs)
│   └── analytics/               # tenant-b: nodejs API :9090 + PVC (report data)
├── tests/
│   ├── policies/<policy>/       # kyverno test files: ≥1 pass + ≥1 fail fixture per policy
│   └── verify.sh                # operator-side cluster evidence (policies, RBAC, kubelet, netpol)
└── workflows/
    └── Jenkinsfile.ci           # THE GATE: policy tests + conformance + IaC scan → install policies
```

## How to add an application deployment

You are a **developer**. The cluster operator owns this repo, the policies, and the
cluster; you contribute your deployment through a PR, and **the gate is what merges you**.

Your image is built and signed by your application repo's pipeline (build → Trivy scan →
cosign sign → push → note the **digest**). For the demo apps, SETUP_DEMO.md §10 walks
through producing those signed images once.

1. **Write the app** in your application repo — build the image, pass your own dev-side CI
   (see <https://github.com/PadishahIII/devsecops-demo>), push it to the governed registry,
   and **cosign sign** it. The image digest is the contract you hand over.
2. **Add a tenant values file** — copy `resources/helm/webapp/values-tenant-a.yaml` to
   `values-<tenant>.yaml` and set: `nameOverride`, `service.port` / `containerPort`, PVC
   size, the ingress-allow peers (which namespaces may call this app), and your
   developer-owned image + attestation: digest-pinned `image.fullRef` plus
   `annotations.imageVerified: cosign` and `annotations.imageDigest: <digest>`.
   - If it's a **new tenant**: add the namespace (labeled `tenancy.io/tenant: "true"`) in
     `resources/cluster/namespaces.yaml` and a per-tenant Role/RoleBinding in
     `resources/cluster/rbac.yaml`. That's all — the policies pick up the new namespace
     automatically via the label selector, and the conformance stage picks up the new
     `values-<tenant>.yaml` automatically (no pipeline edits).
3. **Open a PR against this repo.** Jenkins CI runs the gate and blocks the merge if
   anything fails:
   - `kyverno test tests/policies` — every policy's pass *and* deny behaviour,
   - `kyverno apply policies/ -r <your rendered manifests>` — **your** deployment must pass
     all 13 policies, rendered straight from your values file,
   - `trivy config --exit-code 1 resources/` — IaC scan of your files.

   The gate needs no app-specific knowledge: it discovers `values-<tenant>.yaml` and renders
   it as-is, so your values file is the single source of truth for what gets checked. The
   rendered manifests that passed are archived with the build
   (`reports/conformance-rendered/`).
4. **The operator merges.** The gate's final stage installs `policies/` into the cluster
   (`kubectl apply` + wait for `Ready`) — the only path by which policy enters the cluster.
   Your manifest is now known-compatible with the installed policy set, and the archived
   build artifacts (including the rendered manifests that passed) are what the operator's
   deployment tooling consumes.
5. **Add tests** only when you changed a policy: fixtures live per-policy under
   `tests/policies/`. If your app needs a new cross-tenant network allow, update the netpol
   fixtures and `tests/verify.sh` expectations.
6. **Do NOT** hand-`kubectl apply` into tenant namespaces. That bypasses the attestation and
   is rejected by `require-image-attestation` — by design, not by accident.

## Policies introduction & security considerations

All policies are Kyverno `ClusterPolicy` resources with `validationFailureAction: Enforce`,
scoped to namespaces labeled `tenancy.io/tenant: "true"` (tenant tier — platform namespaces
like `kyverno`/`platform` are governed separately). Every policy has offline unit tests
(`kyverno test tests/policies`) that run in the gate, and **the gate is the policy execution
stage**: only policies that lint clean and pass their tests get `kubectl apply`-ed to the
cluster (DESIGN.md §10.1). Denials are asserted offline by `kyverno test` — not re-derived by
applying violating pods in-cluster.

| Policy file                             | Security consideration |
| --------------------------------------- | ---------------------- |
| `require-non-root.yaml`                 | Application processes must not run as root (`runAsNonRoot: true`). |
| `disallow-privilege-escalation.yaml`    | `allowPrivilegeEscalation: false` on every container (blocks e.g. setuid binaries, `CAP_SYS_PTRACE`-style escalation). |
| `require-readonly-rootfs.yaml`          | `readOnlyRootFilesystem: true` — a compromised process can't drop tools, persist, or tamper with its own filesystem. Writable state goes to explicit volumes (PVC). |
| `require-default-proc-mount.yaml`       | Rejects `procMount: Unmasked` — the default (masked) /proc hides kernel memory and other processes' `/proc/<pid>/mem`. |
| `disallow-host-namespaces.yaml`         | No `hostNetwork`/`hostPID`/`hostIPC`. Host networking would also silently bypass NetworkPolicies — the pod would talk on the host's interfaces. |
| `require-drop-all-capabilities.yaml`    | `capabilities.drop: [ALL]` — no unused Linux capabilities; add back only what a workload provably needs. |
| `require-selinux-options.yaml`          | Requires `seLinuxOptions.level` — fine-grained MAC labels. _Honest caveat:_ the kind node doesn't run SELinux, so this enforces spec-level conformance in the lab; on an SELinux-enabled node the runtime enforces it for real. |
| `require-dedicated-serviceaccount.yaml` | Each app gets its own ServiceAccount; the shared `default` SA is forbidden (no identity sharing, clean audit trail). |
| `require-automount-sa-token-false.yaml` | Apps that don't call the Kubernetes API get no mounted SA credentials — removes a classic lateral-movement artifact. |
| `disallow-privileged-containers.yaml`   | Defense in depth: `privileged: true` is never allowed (full device access + most caps). |
| `require-image-allowlist.yaml`          | **Governed image trust list** — only images from `docker.io/padishahiii/*` (the org the platform builds & scans) may run. The list is a versioned `variables` block in the policy, reviewed like code. (Production variant: ConfigMap + `apiCall` for hot updates — see DESIGN.md §6.2.) |
| `require-image-digest.yaml`             | Images must be referenced by `@sha256:` digest — no mutable tags in deployments. |
| `require-image-attestation.yaml`        | **Only verified images admitted.** The application pipeline Trivy-scans the image _before_ cosign-signing it; the deployment step cosign-verifies it and stamps the pod template with `security.devsecops.io/image-verified=cosign` + the attested digest; this policy requires both the annotation **and** that the attested digest matches the running image (closes the re-tag-after-verify hole). |

**Cluster-level controls** (not Kyverno):

- **External API authentication** — kube-apiserver validates bearer tokens against
  an external OIDC issuer (dex in `platform` ns); identities + groups flow into RBAC.
  See `kind/cluster-config.yaml` and SETUP_DEMO.md.
- **RBAC properly** — no human has cluster-admin; per-tenant Role/RoleBindings
  (alice→tenant-a, bob→tenant-b); app ServiceAccounts have _zero_ API permissions.
- **Kubelet access limited** — anonymous auth off, read-only port 0, webhook
  authorization; verified by `tests/verify.sh` (anonymous curl → 401) and kube-bench.
- **NetworkPolicies** — default-deny ingress+egress per tenant; explicit allows only
  (DNS; same-ns; tenant-a → tenant-b:9090, simulating frontend→backend).

**Security considerations baked into the gate** (see DESIGN.md §10):

- **Hardcoded gates, no gate framework:** each tool's exit code fails the build —
  `kyverno test`, `kyverno apply`, `trivy --exit-code 1`. The scenario is simple enough
  that a findings-normalization layer (sibling repo) would be overhead.
- **Policy execution stage:** after lint + unit tests + conformance + IaC scan pass, the gate
  applies `policies/` to the cluster and waits for `Ready` — so a policy can never be enforced
  before it was tested.
- **The gate renders what it checks.** Conformance renders the real chart per tenant
  (`helm template`) instead of trusting hand-written fixtures, so a security-context change in
  a developer's manifest flips the gate in the same commit.
- **Image governance is checked as far as a gate can check it.** The gate cannot cosign-verify
  (that needs registry credentials and network access at check time), so it enforces the
  digest pinning and attestation-annotation shape in the manifest, and Kyverno enforces the
  annotation/digest match at admission. Verifying the signature itself is a deploy-time
  concern of the operator.
- **Rejection paths are proven offline** (`kyverno test`, one dir per policy) and shown
  **live** in the manual demo — the gate never requires a deployment to exist.

## What's included

- 13 Kyverno ClusterPolicies (pod security, image governance) + per-policy unit tests
- Jenkins **CI — the policy gate**: `kyverno test` (assertions), `kyverno apply` against the
  developer's chart-rendered manifests (conformance), Trivy IaC/config scan, server-side
  schema lint, then the **policy install stage** (`kubectl apply -f policies/` + `Ready` wait)
- Gate evidence archived per build: policy test + conformance + IaC reports, plus the
  per-tenant rendered manifests that passed — the artifact a cluster operator's deployment
  tooling consumes
- Multi-tenant model: 2 tenant namespaces, per-tenant RBAC, per-app ServiceAccounts,
  default-deny NetworkPolicies with explicit cross-tenant allow
- Demo apps: nodejs **distroless** web servers with PVCs (shop, analytics) + a rogue
  attacker pod
- Image governance **as far as a policy gate enforces it**: trust list, digest pinning, and
  the attestation annotation + digest-match check at admission (`require-image-attestation`)
- Component hardening: external API auth (OIDC/dex), least-privilege RBAC, restricted
  kubelet (verified with kube-bench + unauthenticated requests)
- `tests/verify.sh`: operator-side evidence collector (policy readiness, RBAC matrix, kubelet,
  NetworkPolicy behaviour) — run it whenever the cluster holds deployed workloads

## What's not included

- **CD / deployment pipeline** — deliberately omitted. This repo is a **Kubernetes policy gate
  demo, not an operations demo**: it decides what *may* run, and installs the policies that
  enforce that decision. A `workflows/Jenkinsfile.cd` existed during development (cosign
  verify → GPG-signed chart → `helm upgrade --install` → rollout verification); it was removed
  as out of scope, and the git history is the record of how it worked. The cluster operator's
  own deployment tooling is the consumer of a green gate.
  - Removed with it: chart **GPG provenance signing** — `helm package --sign`, the Jenkins
    `helm-signing-key` credential, `resources/helm/webapp/keys/public.asc`, and
    `tools/generate-helm-signing-key.sh`. Chart signing is a delivery concern, not a policy
    concern. Image **cosign** verification likewise stays at deploy time.
- **DAST** — covered by the sibling repo `devsecops-demo` (in-cluster ZAP + DAST-aware gate)
- **Image build/push/scan pipeline** — your application repo's job; SETUP_DEMO.md walks
  through producing the demo signed images (build → trivy → cosign sign → push). cosign
  _signing_ itself is demonstrated in `devsecops-demo`.
- **Gate framework** (sibling repo's findings normalization) — this repo hardcodes failure
  gates (tool exit codes) in the pipeline
- **PodSecurityAdmission labels** — complementary to these policies (PSS `restricted`
  ≈ P1–P6); explicit per-rule policies were chosen for granularity and readable rejection
  messages
- **Audit logging, etcd hardening, node hardening** — kind-managed or lower demo value;
  kube-bench is used for evidence, not as a control
- **Service mesh / mTLS, secrets management (SOPS/SealedSecrets), GitOps (ArgoCD),
  ResourceQuota/LimitRange, DR** — realistic additions, listed as future work in DESIGN.md §13
