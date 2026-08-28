# demo-apps

Source for the two demo applications. **These are only used to *produce* the
signed images** — the CD pipeline deploys images, not code.

| App | Port | Tenant | Final image (governed registry) |
| --- | --- | --- | --- |
| `shop/` | 8080 | tenant-a | `docker.io/padishahiii/kube-sec-shop` |
| `analytics/` | 9090 | tenant-b | `docker.io/padishahiii/kube-sec-analytics` |

Both are single-file Node.js servers built on `gcr.io/distroless/nodejs22`,
running as the unprivileged `node` user. They are deliberately minimal: no
dependencies, no file writes (read-only root filesystem friendly), logs to
stdout only.

## Producing the signed images (see SETUP_DEMO.md)

```bash
# 1. build
docker build -t docker.io/padishahiii/kube-sec-shop:1.0.0 demo-apps/shop/
# 2. scan (Trivy) — must pass before signing
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity CRITICAL,HIGH --exit-code 1 \
  docker.io/padishahiii/kube-sec-shop:1.0.0
# 3. sign (cosign) — the signature is what CD trusts
cosign sign --key ... docker.io/padishahiii/kube-sec-shop:1.0.0
# 4. push
docker push docker.io/padishahiii/kube-sec-shop:1.0.0
```

The CD pipeline then deploys the **digest-pinned** reference
(`...@sha256:...`) after `cosign verify` succeeds.
