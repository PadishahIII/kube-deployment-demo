#!/usr/bin/env bash
#
# tests/verify.sh — end-to-end cluster verification + evidence collector.
#
# POSITIVE-ONLY by design: it proves the controls are in place and working.
# Negative admission (a rogue pod being REJECTED) is NOT asserted here — that is
# proven offline by `kyverno test` (CI) and demonstrated live, by hand, in the
# demo (see the reminder printed at the end). Keeping this script positive-only
# means a single flaky negative check can't mask the real evidence.
#
# Usage:
#   ./tests/verify.sh [reports-dir]
#
# Optional environment (enables the RBAC matrix; see SETUP_DEMO.md for how to
# produce these via dex OIDC + kubectl-oidc-login):
#   ALICE_KUBECONFIG=/path/to/alice.kubeconfig
#   BOB_KUBECONFIG=/path/to/bob.kubeconfig
#
# Optional environment (enables the CIS node benchmark; see SETUP_DEMO.md):
#   KUBE_BENCH=/path/to/kube-bench   (or put it on PATH)
#
# Exit code: 0 if every non-skipped check passed, 1 otherwise.

set -uo pipefail

REPORTS="${1:-reports/verify}"
mkdir -p "$REPORTS"

PASS=0; FAIL=0; SKIP=0

# --- tiny reporting helpers -------------------------------------------------
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }
info() { printf '        %s\n' "$1"; }

# check <name> <expected> <actual>  -> ok/bad on match
check() {
  local name="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then ok "$name"; else bad "$name (expected: $expected, got: $actual)"; fi
}

# check_true <name> <actual>  -> ok when actual is non-empty/true-ish
check_true() {
  local name="$1" actual="$2"
  if [ -n "$actual" ] && [ "$actual" != "0" ] && [ "$actual" != "false" ] && [ "$actual" != "no" ]; then
    ok "$name"
  else
    bad "$name (got: ${actual:-<empty>})"
  fi
}

command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found on PATH"; exit 1; }

printf '\n\033[1mkube-security cluster verification\033[0m\n'
printf 'context: %s\n' "$(kubectl config current-context 2>/dev/null || echo '?')"
printf 'reports: %s\n' "$REPORTS"

# ============================================================================
section "1. ClusterPolicies (13 installed, Enforce, Ready)"
# ============================================================================
kubectl get clusterpolicies -o json > "$REPORTS/clusterpolicies.json" 2>/dev/null
read -r TOTAL ENFORCE READY <<EOF2
$(kubectl get clusterpolicies -o json | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d["items"]
total=len(items)
enforce=sum(1 for p in items if p["spec"].get("validationFailureAction")=="Enforce")
ready=sum(1 for p in items if any(c.get("type")=="Ready" and c.get("status")=="True" for c in p.get("status",{}).get("conditions",[])))
print(total,enforce,ready)
')
EOF2
check "clusterpolicies installed (13)" "13" "$TOTAL"
check "all in Enforce mode (13)" "13" "$ENFORCE"
check "all Ready=True (13)" "13" "$READY"

# ============================================================================
section "2. Workloads Running + PolicyReports (0 fail)"
# ============================================================================
for pair in "tenant-a shop" "tenant-b analytics"; do
  set -- $pair
  ns="$1"; app="$2"
  READY_REPLICAS=$(kubectl get deploy "$app" -n "$ns" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
  check_true "$app deployment has a ready replica ($ns)" "$READY_REPLICAS"
done

# Sum the PolicyReport fail counts across both tenant namespaces.
PR_FAILS=$(kubectl get policyreport -n tenant-a -n tenant-b -o json 2>/dev/null | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print("error"); raise SystemExit
fails=sum(r.get("summary",{}).get("fail",0) for r in d.get("items",[]))
print(fails)
')
check "policyreport fail count (0)" "0" "$PR_FAILS"
kubectl get policyreport -n tenant-a -n tenant-b > "$REPORTS/policyreports.txt" 2>/dev/null

# ============================================================================
section "3. RBAC matrix (least privilege per tenant)"
# ============================================================================
# Expectations come from resources/cluster/rbac.yaml: each user may READ their
# own tenant only, and has NO create rights (read-only demo role). Kyverno
# admission rejection of non-compliant pods is a separate control — see the
# manual demo at the end of this script.
run_can_i() {  # <kubeconfig> <verb> <resource> <namespace>
  KUBECONFIG="$1" kubectl auth can-i "$2" "$3" -n "$4" 2>/dev/null || echo "error"
}

if [ -n "${ALICE_KUBECONFIG:-}" ] && [ -n "${BOB_KUBECONFIG:-}" ]; then
  check "alice: get pods in tenant-a (yes)"   "yes" "$(run_can_i "$ALICE_KUBECONFIG" get pods tenant-a)"
  check "alice: get pods in tenant-b (no)"    "no"  "$(run_can_i "$ALICE_KUBECONFIG" get pods tenant-b)"
  check "alice: create pods in tenant-a (no)" "no"  "$(run_can_i "$ALICE_KUBECONFIG" create pods tenant-a)"
  check "bob:   get pods in tenant-b (yes)"   "yes" "$(run_can_i "$BOB_KUBECONFIG" get pods tenant-b)"
  check "bob:   get pods in tenant-a (no)"    "no"  "$(run_can_i "$BOB_KUBECONFIG" get pods tenant-a)"
  check "bob:   create pods in tenant-b (no)" "no"  "$(run_can_i "$BOB_KUBECONFIG" create pods tenant-b)"
  {
    printf 'alice\ttenant-a\tget\tpods\t%s\n'  "$(run_can_i "$ALICE_KUBECONFIG" get pods tenant-a)"
    printf 'alice\ttenant-b\tget\tpods\t%s\n'  "$(run_can_i "$ALICE_KUBECONFIG" get pods tenant-b)"
    printf 'alice\ttenant-a\tcreate\tpods\t%s\n' "$(run_can_i "$ALICE_KUBECONFIG" create pods tenant-a)"
    printf 'bob\ttenant-b\tget\tpods\t%s\n'    "$(run_can_i "$BOB_KUBECONFIG" get pods tenant-b)"
    printf 'bob\ttenant-a\tget\tpods\t%s\n'    "$(run_can_i "$BOB_KUBECONFIG" get pods tenant-a)"
    printf 'bob\ttenant-b\tcreate\tpods\t%s\n' "$(run_can_i "$BOB_KUBECONFIG" create pods tenant-b)"
  } > "$REPORTS/rbac-matrix.tsv"
else
  skip "RBAC matrix — set ALICE_KUBECONFIG and BOB_KUBECONFIG (dex OIDC login, see SETUP_DEMO.md)"
fi

# ============================================================================
section "4. Kubelet access (anonymous rejected)"
# ============================================================================
# The kubelet runs with anonymous auth disabled and no read-only port. From the
# host we may not be able to reach the kind node IP directly (Docker Desktop VM
# networking), so we check from INSIDE the node container against localhost.
NODE_CONTAINER=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NODE_CONTAINER"; then
  KUBELET_CODE=$(docker exec "$NODE_CONTAINER" sh -c \
    'curl -sk -o /dev/null -w "%{http_code}" --max-time 5 https://127.0.0.1:10250/healthz' 2>/dev/null)
  if [ "$KUBELET_CODE" = "401" ] || [ "$KUBELET_CODE" = "403" ]; then
    ok "kubelet /healthz without credentials -> $KUBELET_CODE (anonymous rejected)"
  else
    bad "kubelet /healthz without credentials (expected 401/403, got: ${KUBELET_CODE:-no-response})"
  fi
  printf 'kubelet anonymous /healthz -> %s\n' "$KUBELET_CODE" > "$REPORTS/kubelet-anonymous.txt"
else
  skip "kubelet check — node container '$NODE_CONTAINER' not reachable via docker on this host"
fi

# Optional: CIS node benchmark (archived as evidence when available).
if [ -n "${KUBE_BENCH:-}" ] && [ -x "${KUBE_BENCH:-/nonexistent}" ]; then
  info "running kube-bench node (archiving to $REPORTS/kube-bench-node.txt)..."
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NODE_CONTAINER"; then
    docker cp "${KUBE_BENCH}" "$NODE_CONTAINER:/tmp/kube-bench" 2>/dev/null
    docker exec "$NODE_CONTAINER" sh -c 'chmod +x /tmp/kube-bench && /tmp/kube-bench node -o json' \
      > "$REPORTS/kube-bench-node.txt" 2>&1 \
      && ok "kube-bench node ran (see $REPORTS/kube-bench-node.txt)" \
      || bad "kube-bench node failed (see $REPORTS/kube-bench-node.txt)"
  else
    skip "kube-bench — node container not reachable via docker"
  fi
else
  skip "kube-bench — set KUBE_BENCH=/path/to/kube-bench (see SETUP_DEMO.md)"
fi

# ============================================================================
section "5. NetworkPolicies (explicit allow + default-deny egress)"
# ============================================================================
# The shop pod (tenant-a) has an egress allow to analytics:9090 (tenant-b) and
# DNS only — everything else is denied. The apps are nodejs distroless (no
# shell), so we drive the check with the node runtime's global fetch().
NODE_BIN="/nodejs/bin/node"

if kubectl get deploy shop -n tenant-a >/dev/null 2>&1 && kubectl get deploy analytics -n tenant-b >/dev/null 2>&1; then
  ALLOW_OUT=$(kubectl exec -n tenant-a deploy/shop -- "$NODE_BIN" -e \
    "fetch('http://analytics.tenant-b.svc:9090/').then(r=>{console.log(r.status);process.exit(r.ok?0:1)}).catch(e=>{console.error('ERR',e.message||e.cause?.message||e);process.exit(1)})" \
    2>&1)
  if [ "$ALLOW_OUT" = "200" ]; then
    ok "shop -> analytics:9090 allowed (HTTP 200)"
  else
    bad "shop -> analytics:9090 (expected HTTP 200, got: ${ALLOW_OUT:-no-response})"
  fi

  DENY_OUT=$(kubectl exec -n tenant-a deploy/shop -- "$NODE_BIN" -e \
    "fetch('http://example.com',{signal:AbortSignal.timeout(6000)}).then(r=>{console.log('ALLOWED',r.status);process.exit(1)}).catch(e=>{console.log('BLOCKED');process.exit(0)})" \
    2>&1)
  if [ "$DENY_OUT" = "BLOCKED" ]; then
    ok "shop -> external (example.com) denied by default-deny egress"
  else
    bad "shop -> external (expected BLOCKED, got: ${DENY_OUT:-no-response})"
  fi
  printf 'shop->analytics:9090 = %s\nshop->external = %s\n' "$ALLOW_OUT" "$DENY_OUT" > "$REPORTS/netpol.txt"
else
  skip "networkpolicy checks — shop (tenant-a) / analytics (tenant-b) deployments not found"
fi

# ============================================================================
section "Summary"
# ============================================================================
printf '  \033[32mpass: %d\033[0m   \033[31mfail: %d\033[0m   \033[33mskip: %d\033[0m\n' "$PASS" "$FAIL" "$SKIP"
printf '  evidence archived under: %s/\n' "$REPORTS"

printf '\n\033[1mManual demo — live admission rejection (not asserted above):\033[0m\n'
printf '  kubectl apply -f resources/admission/pod.attacker.yaml -n tenant-a\n'
printf '  -> expect: "admission webhook validate.kyverno.svc-fail denied" (multiple policies)\n'
printf '  This is the negative control; it is proven offline by `kyverno test` in CI.\n'

if [ "$FAIL" -gt 0 ]; then
  printf '\n\033[31mRESULT: FAIL\033[0m\n'
  exit 1
fi
printf '\n\033[32mRESULT: PASS\033[0m\n'
exit 0
