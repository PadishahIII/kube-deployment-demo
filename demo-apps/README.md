# demo-apps

Source for the two demo applications. **These are only used to _produce_ the signed
images** — this repo deploys nothing; the gate checks the tenant manifests that
reference these image digests (`resources/helm/webapp/values-<tenant>.yaml`).

| App          | Port | Tenant   | Final image (governed registry)            |
| ------------ | ---- | -------- | ------------------------------------------ |
| `shop/`      | 8080 | tenant-a | `docker.io/padishahiii/kube-sec-shop`      |
| `analytics/` | 9090 | tenant-b | `docker.io/padishahiii/kube-sec-analytics` |

Both are single-file Node.js servers built on `gcr.io/distroless/nodejs22`,
running as the unprivileged `node` user. They are deliberately minimal: no
dependencies, no file writes (read-only root filesystem friendly), logs to
stdout only.

## Producing the signed images (see SETUP_DEMO.md §10)

Run this in the **application repo's** pipeline — that is where build, scan, sign and
push belong. Order matters: push first, then sign the pushed digest, then verify.

```bash
# 1. build
docker build -t docker.io/padishahiii/kube-sec-shop:1.0.0 demo-apps/shop/

# 2. scan (Trivy) — must be clean before signing
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:0.74.0 image --severity CRITICAL,HIGH --exit-code 1 \
  docker.io/padishahiii/kube-sec-shop:1.0.0

# 3. push
docker push docker.io/padishahiii/kube-sec-shop:1.0.0

# 4. capture the registry digest
docker buildx imagetools inspect docker.io/padishahiii/kube-sec-shop:1.0.0 \
  --format '{{json .Manifest.Digest}}'

# 5. sign (cosign) — the signature is what a deployer verifies
cosign sign --key cosign.key docker.io/padishahiii/kube-sec-shop@${DIGEST}

# 6. verify the signature really landed
cosign verify --key cosign.pub docker.io/padishahiii/kube-sec-shop@${DIGEST}
```

Then put the **digest-pinned** reference (`...@sha256:...`) and its digest into your
tenant values file — `image.fullRef` plus `annotations.imageDigest`, which must match.
The policy gate checks that shape before merge (`require-image-digest`,
`require-image-attestation`), and Kyverno enforces it at admission against whatever the
cluster operator actually deploys.
