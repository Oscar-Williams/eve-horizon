#!/usr/bin/env bash
# The worker's rights in k8s/base, proved on a throwaway kind cluster:
# applies only the RBAC and admission objects of k8s/base, then makes each
# write the worker needs, and each it must not make, as the worker's service
# account (kubectl --as). Every case prints PASS or FAIL; any FAIL exits 1.
#
#   kind create cluster --name eve-guard --kubeconfig /tmp/eve-guard.kubeconfig
#   KUBECONFIG=/tmp/eve-guard.kubeconfig tests/k8s/worker-guard.kind.sh
#   kind delete cluster --name eve-guard
#
# Refuses to run unless the current context is a kind cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTEXT="$(kubectl config current-context)"
if [[ "$CONTEXT" != kind-* ]]; then
  echo "refusing: context $CONTEXT is not a kind cluster" >&2
  exit 2
fi
K=(kubectl --context "$CONTEXT")
WORKER=(--as=system:serviceaccount:eve:eve-worker)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- The template's RBAC and admission objects only ------------------------
KUBECONFIG=/dev/null kubectl kustomize "$ROOT/k8s/base" > "$WORK/base.yaml"
node -e '
  const fs = require("fs");
  const YAML = require(process.argv[1]);
  const keep = new Set(["Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"]);
  const docs = YAML.parseAllDocuments(fs.readFileSync(process.argv[2], "utf8")).map((d) => d.toJSON()).filter((d) => d && keep.has(d.kind));
  fs.writeFileSync(process.argv[3], docs.map((d) => YAML.stringify(d)).join("---\n"));
' "$ROOT/apps/worker/node_modules/yaml" "$WORK/base.yaml" "$WORK/rbac.yaml"
"${K[@]}" apply -f "$WORK/rbac.yaml" >/dev/null
# Objects an earlier render applied that this one no longer holds (the old
# all-namespace ClusterRoleBinding) would keep their rights: remove them.
for crb in $("${K[@]}" get clusterrolebindings -o jsonpath='{range .items[?(@.subjects[0].name=="eve-worker")]}{.metadata.name}{"\n"}{end}'); do
  grep -q "name: $crb\$" "$WORK/rbac.yaml" || "${K[@]}" delete clusterrolebinding "$crb" >/dev/null
done

# --- Fixtures, as the cluster admin -----------------------------------------
"${K[@]}" delete namespace eve-acme-shop-new --ignore-not-found --wait=true >/dev/null
for ns in eve-acme-shop-prod eve-acme-shop-old acme-foreign; do
  "${K[@]}" create namespace "$ns" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
done
"${K[@]}" label namespace eve-acme-shop-prod eve.env_id=env_prod eve.horizon/managed=true --overwrite >/dev/null
"${K[@]}" label namespace eve-acme-shop-old eve.env_id=env_old --overwrite >/dev/null
"${K[@]}" label namespace eve-acme-shop-old eve.horizon/managed- >/dev/null 2>&1 || true
"${K[@]}" label namespace acme-foreign eve.horizon/managed- >/dev/null 2>&1 || true
"${K[@]}" -n eve-acme-shop-prod create rolebinding other --clusterrole=view --user=user_alice --dry-run=client -o yaml \
  | "${K[@]}" apply -f - >/dev/null

# The policy takes a moment to reach the admission chain.
for _ in $(seq 1 30); do
  if ! "${K[@]}" "${WORKER[@]}" create namespace acme-probe --dry-run=server >/dev/null 2>&1; then break; fi
  sleep 1
done

binding() { # namespace role subject-name
  cat <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: $2-for-$3, namespace: $1 }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: $2 }
subjects: [{ kind: ServiceAccount, name: $3, namespace: eve }]
YAML
}
tenant_binding() { # namespace
  cat <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: eve-worker-tenant, namespace: $1 }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: eve-worker-tenant }
subjects: [{ kind: ServiceAccount, name: eve-worker, namespace: eve }]
YAML
}

failures=0
run() { # expect(allow|deny) description command...
  local expect="$1" what="$2"; shift 2
  local out status
  if out="$("$@" 2>&1)"; then status=allow; else status=deny; fi
  if [[ "$status" == "$expect" ]]; then
    printf 'PASS  %-5s %s\n' "$expect" "$what"
  else
    printf 'FAIL  %-5s %s\n        %s\n' "$expect" "$what" "$(echo "$out" | tail -1)"
    failures=$((failures + 1))
  fi
  [[ "$status" == deny ]] && printf '        %s\n' "$(echo "$out" | tail -1 | cut -c1-200)"
  return 0
}
W=("${K[@]}" "${WORKER[@]}")

echo "== allowed"
run allow "create a namespace labelled managed" "${W[@]}" create -f - <<<'{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"eve-acme-shop-new","labels":{"eve.horizon/managed":"true","eve.env_id":"env_new"}}}'
run allow "bind eve-worker-tenant for the worker in it" "${W[@]}" create -f - <<<"$(tenant_binding eve-acme-shop-new)"
run allow "create a Secret there (through that binding)" "${W[@]}" -n eve-acme-shop-new create secret generic app --from-literal=k=v
run allow "read it back" "${W[@]}" -n eve-acme-shop-new get secret app
run allow "create a Deployment there" "${W[@]}" -n eve-acme-shop-new create deployment web --image=registry.example/web:1
run allow "merge-patch labels on a managed namespace" "${W[@]}" patch namespace eve-acme-shop-prod --type=merge -p '{"metadata":{"labels":{"pod-security.kubernetes.io/warn":"restricted"}}}'
run allow "add the managed label to an env namespace of an earlier release (eve.env_id)" "${W[@]}" patch namespace eve-acme-shop-old --type=merge -p '{"metadata":{"labels":{"eve.horizon/managed":"true"}}}'
run allow "write a ConfigMap in the platform namespace (static binding)" "${W[@]}" -n eve create configmap guard-probe --from-literal=k=v
run allow "write a NetworkPolicy in eve-runners (static binding)" "${W[@]}" -n eve-runners create -f - <<<'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"eve-runner-probe","labels":{"eve.horizon/egress":"runner"}},"spec":{"podSelector":{},"policyTypes":["Egress"]}}'
run allow "delete a managed namespace" "${W[@]}" delete namespace eve-acme-shop-new --wait=false

echo "== refused"
run deny "read a Secret in kube-system" "${W[@]}" -n kube-system get secrets
run deny "list Secrets in every namespace" "${W[@]}" get secrets -A
run deny "create a Secret in an unmanaged namespace" "${W[@]}" -n acme-foreign create secret generic x --from-literal=k=v
run deny "bind eve-worker-tenant in an unmanaged namespace (RBAC allows; the guard refuses)" "${W[@]}" create -f - <<<"$(tenant_binding acme-foreign)"
run deny "create a namespace without the managed label" "${W[@]}" create namespace acme-unlabelled
run deny "add the managed label to a namespace Eve never owned" "${W[@]}" patch namespace acme-foreign --type=merge -p '{"metadata":{"labels":{"eve.horizon/managed":"true"}}}'
run deny "relabel kube-system" "${W[@]}" patch namespace kube-system --type=merge -p '{"metadata":{"labels":{"x":"y"}}}'
run deny "bind a role other than eve-worker-tenant" "${W[@]}" create -f - <<<"$(binding eve-acme-shop-prod admin eve-worker)"
run deny "bind eve-worker-tenant for another subject" "${W[@]}" create -f - <<<"$(binding eve-acme-shop-prod eve-worker-tenant eve-runner)"
run deny "delete a RoleBinding the worker did not make" "${W[@]}" -n eve-acme-shop-prod delete rolebinding other
run deny "delete an unmanaged namespace" "${W[@]}" delete namespace acme-foreign --wait=false
run deny "delete the platform namespace" "${W[@]}" delete namespace eve --wait=false
run deny "create a ClusterRole" "${W[@]}" create clusterrole probe --verb=get --resource=pods
run deny "update a namespace (only patch is granted)" "${W[@]}" replace -f - <<<"$("${K[@]}" get namespace eve-acme-shop-prod -o json)"

"${K[@]}" -n eve delete configmap guard-probe --ignore-not-found >/dev/null
"${K[@]}" -n eve-runners delete networkpolicy eve-runner-probe --ignore-not-found >/dev/null
echo
if [[ $failures -gt 0 ]]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "all cases passed"
