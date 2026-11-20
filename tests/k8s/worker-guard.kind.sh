#!/usr/bin/env bash
# The worker's and the orchestrator's rights in k8s/base and the admission
# policies in k8s/admission, proved on a throwaway kind cluster: applies only
# the RBAC and admission objects, then makes each write they need, and each
# they must not make, as their service accounts (kubectl --as). Workload
# writes are server-side dry runs (admission runs, nothing starts). Every case
# prints PASS or FAIL; any FAIL exits 1. A refusal the admission policies
# must make is checked to come from the named policy.
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
ORCHESTRATOR=(--as=system:serviceaccount:eve:eve-orchestrator)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- The template's RBAC and admission objects only ------------------------
KUBECONFIG=/dev/null kubectl kustomize "$ROOT/k8s/base" > "$WORK/base.yaml"
if [[ -d "$ROOT/k8s/admission" ]]; then
  { echo "---"; KUBECONFIG=/dev/null kubectl kustomize "$ROOT/k8s/admission"; } >> "$WORK/base.yaml"
fi
node -e '
  const fs = require("fs");
  const YAML = require(process.argv[1]);
  const keep = new Set(["Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"]);
  const docs = YAML.parseAllDocuments(fs.readFileSync(process.argv[2], "utf8")).map((d) => d.toJSON()).filter((d) => d && keep.has(d.kind));
  fs.writeFileSync(process.argv[3], docs.map((d) => YAML.stringify(d)).join("---\n"));
  fs.writeFileSync(process.argv[4], docs.filter((d) => d.kind === "ClusterRoleBinding").map((d) => d.metadata.name).join("\n") + "\n");
' "$ROOT/apps/worker/node_modules/yaml" "$WORK/base.yaml" "$WORK/rbac.yaml" "$WORK/crbs.txt"
"${K[@]}" apply -f "$WORK/rbac.yaml" >/dev/null
# ClusterRoleBindings for the worker that an earlier render applied and this
# one no longer holds (the old all-namespace `eve-worker`) would keep their
# rights: remove them. So would a RoleBinding of eve-worker-tenant in eve.
for crb in $("${K[@]}" get clusterrolebindings -o jsonpath='{range .items[?(@.subjects[0].name=="eve-worker")]}{.metadata.name}{"\n"}{end}'); do
  grep -qx "$crb" "$WORK/crbs.txt" || "${K[@]}" delete clusterrolebinding "$crb" >/dev/null
done
if ! grep -q 'name: eve-worker-tenant' <(node -e '
  const fs = require("fs"); const YAML = require(process.argv[1]);
  for (const d of YAML.parseAllDocuments(fs.readFileSync(process.argv[2], "utf8")).map((d) => d.toJSON()))
    if (d && d.kind === "RoleBinding" && d.metadata.namespace === "eve") console.log("name: " + d.metadata.name);
' "$ROOT/apps/worker/node_modules/yaml" "$WORK/rbac.yaml"); then
  "${K[@]}" -n eve delete rolebinding eve-worker-tenant --ignore-not-found >/dev/null
fi

# --- Fixtures, as the cluster admin -----------------------------------------
"${K[@]}" delete namespace eve-acme-shop-new --ignore-not-found --wait=true >/dev/null
# eve-builds: the per-build namespace, a static one the template may not hold.
for ns in eve-acme-shop-prod eve-acme-shop-old acme-foreign eve-builds; do
  "${K[@]}" create namespace "$ns" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
done
"${K[@]}" label namespace eve-acme-shop-prod eve.env_id=env_prod eve.horizon/managed=true --overwrite >/dev/null
"${K[@]}" label namespace eve-acme-shop-old eve.env_id=env_old --overwrite >/dev/null
"${K[@]}" label namespace eve-acme-shop-old eve.horizon/managed- >/dev/null 2>&1 || true
"${K[@]}" label namespace acme-foreign eve.horizon/managed- >/dev/null 2>&1 || true
"${K[@]}" -n eve-acme-shop-prod create rolebinding other --clusterrole=view --user=user_alice --dry-run=client -o yaml \
  | "${K[@]}" apply -f - >/dev/null
# A managed env namespace the worker is bound in, with an app Deployment.
"${K[@]}" label namespace eve-acme-shop-prod pod-security.kubernetes.io/enforce- >/dev/null 2>&1 || true
"${K[@]}" -n eve-acme-shop-prod create deployment web --image=registry.example/web:1 --replicas=1 --dry-run=client -o yaml \
  | "${K[@]}" apply -f - >/dev/null
# A running pod in the platform namespace to try exec on (the pause image is
# on every kind node).
"${K[@]}" -n eve delete pod exec-probe --ignore-not-found --wait=true >/dev/null
"${K[@]}" -n eve run exec-probe --image=registry.k8s.io/pause:3.10 --image-pull-policy=IfNotPresent --restart=Never >/dev/null
"${K[@]}" -n eve wait --for=condition=Ready pod/exec-probe --timeout=90s >/dev/null
# The platform's own objects in eve, which the worker must neither replace
# nor remove (none carries a runner, kaniko or egress label), and a runner pod
# it may remove.
"${K[@]}" -n eve create secret generic eve-app --from-literal=k=v --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" apply -f - >/dev/null <<<'{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"postgres-data-postgres-0","namespace":"eve"},"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}}'
"${K[@]}" apply -f - >/dev/null <<<'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"platform-allow","namespace":"eve"},"spec":{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{}]}}'
"${K[@]}" apply -f - >/dev/null <<<'{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"platform-migrate","namespace":"eve"},"spec":{"suspend":true,"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"main","image":"registry.k8s.io/pause:3.10"}]}}}}'
"${K[@]}" apply -f - >/dev/null <<<'{"apiVersion":"v1","kind":"Pod","metadata":{"name":"eve-runner-fixture","namespace":"eve","labels":{"eve.type":"runner"}},"spec":{"containers":[{"name":"main","image":"registry.k8s.io/pause:3.10","imagePullPolicy":"IfNotPresent"}]}}'

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

# A new or changed policy takes a moment to reach the admission chain: wait
# until it refuses an unlabelled namespace and lets the worker bind itself.
"${K[@]}" create namespace acme-probe-managed --dry-run=client -o yaml \
  | "${K[@]}" label --local -f - eve.horizon/managed=true -o yaml | "${K[@]}" apply -f - >/dev/null
for _ in $(seq 1 60); do
  if ! "${K[@]}" "${WORKER[@]}" create namespace acme-probe --dry-run=server >/dev/null 2>&1 \
    && "${K[@]}" "${WORKER[@]}" create --dry-run=server -f - >/dev/null 2>&1 <<<"$(tenant_binding acme-probe-managed)"; then
    break
  fi
  sleep 2
done
sleep 5
"${K[@]}" delete namespace acme-probe-managed --wait=false >/dev/null

"${K[@]}" apply -f - >/dev/null <<<"$(tenant_binding eve-acme-shop-prod)"

failures=0
# A refusal that must come from one admission policy (its name is in the error).
guard() { # policy description command...
  local policy="$1" what="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    printf 'FAIL  deny  %s\n        allowed\n' "$what"
    failures=$((failures + 1))
  elif grep -q "$policy" <<<"$out"; then
    printf 'PASS  deny  %s\n        %s\n' "$what" "$(echo "$out" | tail -1 | cut -c1-200)"
  else
    printf 'FAIL  deny  %s (not by %s)\n        %s\n' "$what" "$policy" "$(echo "$out" | tail -1 | cut -c1-200)"
    failures=$((failures + 1))
  fi
  return 0
}
# A refusal from one admission policy whose reported message (the error, not
# a Pod Security warning) names a field.
guard_says() { # policy needle description command...
  local policy="$1" needle="$2" what="$3"; shift 3
  local out
  if out="$("$@" 2>&1)"; then
    printf 'FAIL  deny  %s\n        allowed\n' "$what"
    failures=$((failures + 1))
  elif grep -q "$policy" <<<"$out" && tail -1 <<<"$out" | grep -q "$needle"; then
    printf 'PASS  deny  %s\n        %s\n' "$what" "$(echo "$out" | tail -1 | cut -c1-200)"
  else
    printf 'FAIL  deny  %s (not by %s naming %s)\n        %s\n' "$what" "$policy" "$needle" "$(echo "$out" | tail -1 | cut -c1-200)"
    failures=$((failures + 1))
  fi
  return 0
}
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
O=("${K[@]}" "${ORCHESTRATOR[@]}")
DRY=(create --dry-run=server -f -)
WG=eve-worker-workload-guard
NG=eve-worker-namespace-guard
OG=eve-orchestrator-scale-guard
PG=eve-worker-platform-guard

# Pod specs: a JSON pod, or a template inside a workload.
pod() { # namespace name pod-spec-json [labels-json]
  local labels="${4:-}"
  [[ -n "$labels" ]] || labels='{}'
  printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s","namespace":"%s","labels":%s},"spec":%s}' "$2" "$1" "$labels" "$3"
}
workload() { # kind namespace name pod-spec-json
  local podspec="$4"
  # Jobs need restartPolicy Never; Deployments and DaemonSets the default.
  [[ "$1" == Job || "$1" == CronJob ]] && podspec="{\"restartPolicy\":\"Never\",${podspec#\{}"
  local template="{\"metadata\":{\"labels\":{\"app\":\"$3\"}},\"spec\":$podspec}"
  case "$1" in
    Deployment|DaemonSet) printf '{"apiVersion":"apps/v1","kind":"%s","metadata":{"name":"%s","namespace":"%s"},"spec":{"selector":{"matchLabels":{"app":"%s"}},"template":%s}}' "$1" "$3" "$2" "$3" "$template" ;;
    Job) printf '{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"%s","namespace":"%s"},"spec":{"template":%s}}' "$3" "$2" "$template" ;;
    CronJob) printf '{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"%s","namespace":"%s"},"spec":{"schedule":"0 * * * *","jobTemplate":{"spec":{"template":%s}}}}' "$3" "$2" "$template" ;;
  esac
}
C='{"name":"main","image":"registry.example/app:1"}'
claim() { # name [extra spec fields (JSON, without braces)]: a claim in the platform namespace
  printf '{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"%s","namespace":"eve"},"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}%s}}' "$1" "${2:+,$2}"
}
spec() { # extra pod-spec fields (JSON, without braces), containers JSON
  printf '{"containers":[%s]%s}' "${2:-$C}" "${1:+,$1}"
}
KANIKO_JOB='{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"kaniko-probe","namespace":"eve","labels":{"eve.horizon/component":"kaniko-build"}},"spec":{"template":{"metadata":{"labels":{"eve.horizon/component":"kaniko-build"}},"spec":{"restartPolicy":"Never","initContainers":[{"name":"clone","image":"registry.example/git:1","env":[{"name":"GIT_URL","valueFrom":{"secretKeyRef":{"name":"kaniko-cfg-probe","key":"git-url"}}}],"volumeMounts":[{"name":"workspace","mountPath":"/workspace"}]}],"containers":[{"name":"kaniko","image":"registry.example/kaniko:1","volumeMounts":[{"name":"workspace","mountPath":"/workspace"},{"name":"docker-config","mountPath":"/kaniko/.docker","readOnly":true}]}],"volumes":[{"name":"workspace","emptyDir":{}},{"name":"docker-config","secret":{"secretName":"kaniko-cfg-probe"}}]}}}}'
RUNNER_LABELS='{"eve.type":"runner","eve.horizon/runner":"true","eve.horizon/project-id":"proj_shop","eve.horizon/attempt-id":"att_1","eve.horizon/job-class":"job"}'
RUNNER_SPEC="$(spec '"serviceAccountName":"eve-runner","automountServiceAccountToken":false,"volumes":[{"name":"workspace","persistentVolumeClaim":{"claimName":"eve-ws-att-1"}},{"name":"org-fs","persistentVolumeClaim":{"claimName":"eve-org-fs-org-default","readOnly":true}}]')"

echo "== allowed"
run allow "create a namespace labelled managed" "${W[@]}" create -f - <<<'{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"eve-acme-shop-new","labels":{"eve.horizon/managed":"true","eve.env_id":"env_new"}}}'
run allow "bind eve-worker-tenant for the worker in it" "${W[@]}" create -f - <<<"$(tenant_binding eve-acme-shop-new)"
run allow "create a Secret there (through that binding)" "${W[@]}" -n eve-acme-shop-new create secret generic app --from-literal=k=v
run allow "read it back" "${W[@]}" -n eve-acme-shop-new get secret app
run allow "create a Deployment there" "${W[@]}" -n eve-acme-shop-new create deployment web --image=registry.example/web:1
run allow "merge-patch labels on a managed namespace" "${W[@]}" patch namespace eve-acme-shop-prod --type=merge -p '{"metadata":{"labels":{"pod-security.kubernetes.io/warn":"restricted"}}}'
run allow "add the managed label to an env namespace of an earlier release (eve.env_id)" "${W[@]}" patch namespace eve-acme-shop-old --type=merge -p '{"metadata":{"labels":{"eve.horizon/managed":"true"}}}'
run allow "write a NetworkPolicy in eve-runners (static binding)" "${W[@]}" -n eve-runners create -f - <<<'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"eve-runner-probe","labels":{"eve.horizon/egress":"runner"}},"spec":{"podSelector":{},"policyTypes":["Egress"]}}'
run allow "write a runner NetworkPolicy in the platform namespace (plain runner pods)" "${W[@]}" -n eve create -f - <<<'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"eve-runner-probe","labels":{"eve.horizon/egress":"runner"}},"spec":{"podSelector":{},"policyTypes":["Egress"]}}'
run allow "create a kaniko build Secret in the platform namespace" "${W[@]}" -n eve create secret generic kaniko-cfg-probe --from-literal=git-url=https://example.invalid/r.git
run allow "run a kaniko build Job in the platform namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$KANIKO_JOB"
run allow "start an org filesystem runner pod in the platform namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$(pod eve eve-runner-probe "$RUNNER_SPEC" "$RUNNER_LABELS")"
run allow "delete the kaniko build Secret" "${W[@]}" -n eve delete secret kaniko-cfg-probe
run allow "update the runner NetworkPolicy it wrote in the platform namespace" "${W[@]}" -n eve patch networkpolicy eve-runner-probe --type=merge -p '{"metadata":{"labels":{"eve.horizon/spec-hash":"probe"}}}'
run allow "delete that runner NetworkPolicy" "${W[@]}" -n eve delete networkpolicy eve-runner-probe
run allow "create a runner workspace claim in the platform namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$(claim eve-ws-probe)"
run allow "delete a runner pod in the platform namespace (dry run)" "${W[@]}" -n eve delete pod eve-runner-fixture --dry-run=server
run allow "create a Deployment with an env app account in a managed namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-acme-shop-prod web2 "$(spec '"serviceAccountName":"eve-app-env-prod"')")"
run allow "create a migration Job in a managed namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$(workload Job eve-acme-shop-prod migrate "$(spec)")"
run allow "a pod at Pod Security baseline with each setting spelt out, in a managed namespace (dry run)" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"securityContext":{"seccompProfile":{"type":"RuntimeDefault"},"appArmorProfile":{"type":"RuntimeDefault"},"seLinuxOptions":{"type":"container_t"},"sysctls":[{"name":"net.ipv4.ip_unprivileged_port_start","value":"0"}]}' '{"name":"main","image":"registry.example/app:1","securityContext":{"seccompProfile":{"type":"Localhost","localhostProfile":"p.json"},"procMount":"Default","windowsOptions":{"hostProcess":false}}}')")"
run allow "delete a managed namespace" "${W[@]}" delete namespace eve-acme-shop-new --wait=false
run allow "the orchestrator scales a Deployment in a managed namespace to zero (dry run)" "${O[@]}" -n eve-acme-shop-prod patch deployment web --subresource=scale --type=merge -p '{"spec":{"replicas":0}}' --dry-run=server

echo "== refused"
run deny "read a Secret in kube-system" "${W[@]}" -n kube-system get secrets
run deny "list Secrets in every namespace" "${W[@]}" get secrets -A
run deny "create a Secret in an unmanaged namespace" "${W[@]}" -n acme-foreign create secret generic x --from-literal=k=v
# A leftover binding (made by an admin) gives RBAC rights there; the guard still refuses.
"${K[@]}" apply -f - >/dev/null <<<"$(tenant_binding acme-foreign)"
run deny "create a Secret in an unmanaged namespace where a leftover binding grants it" "${W[@]}" -n acme-foreign create secret generic x --from-literal=k=v
"${K[@]}" -n acme-foreign delete rolebinding eve-worker-tenant >/dev/null
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

echo "== refused: the platform namespace"
# A real exec: `kubectl auth can-i create pods/exec` answers yes from the
# client side for anyone who may create pods; the API server refuses.
guard 'cannot create resource "pods/exec"' "exec into a pod in the platform namespace" "${W[@]}" -n eve exec exec-probe -- /pause
run deny "read a Secret in the platform namespace" "${W[@]}" auth can-i get secrets -n eve
run deny "list Secrets in the platform namespace" "${W[@]}" auth can-i list secrets -n eve
run deny "write a ConfigMap in the platform namespace" "${W[@]}" auth can-i create configmaps -n eve
run deny "create a Deployment in the platform namespace" "${W[@]}" auth can-i create deployments -n eve
guard $WG "run a pod as eve-worker in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$(spec '"serviceAccountName":"eve-worker"')")"
guard $WG "label a pod in the platform namespace as a platform workload (eve-api)" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$RUNNER_SPEC" '{"app.kubernetes.io/name":"eve-api","eve.horizon/runner":"true"}')"
guard $WG "mount eve-app in a pod in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$(spec '"serviceAccountName":"eve-runner","volumes":[{"name":"s","secret":{"secretName":"eve-app"}}]')")"
guard $WG "read eve-app through env in a pod in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$(spec '"serviceAccountName":"eve-runner"' '{"name":"main","image":"registry.example/app:1","envFrom":[{"secretRef":{"name":"eve-app"}}]}')")"
guard $WG "mount a platform claim (postgres data) in a pod in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$(spec '"serviceAccountName":"eve-runner","volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"postgres-data-postgres-0"}}]')")"

echo "== refused: RoleBindings in the static namespaces"
# RBAC lets the worker bind eve-worker-tenant anywhere; in eve that would win
# back Secret reads, ConfigMaps and Deployments there.
for ns in eve eve-runners eve-builds; do
  guard $NG "bind eve-worker-tenant for the worker in $ns" "${W[@]}" "${DRY[@]}" <<<"$(tenant_binding "$ns")"
done

echo "== refused: the platform namespace, by name and shape"
guard $PG "create a Secret but kaniko-cfg-* in the platform namespace" "${W[@]}" -n eve create secret generic platform-config --from-literal=k=v --dry-run=server
guard $PG "delete the platform's Secret eve-app" "${W[@]}" -n eve delete secret eve-app --dry-run=server
guard $PG "create a claim but eve-ws-* or eve-org-fs-* in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(claim postgres-copy)"
guard $PG "clone the platform's volume into a runner claim (dataSource)" "${W[@]}" "${DRY[@]}" <<<"$(claim eve-ws-clone '"dataSource":{"kind":"PersistentVolumeClaim","name":"postgres-data-postgres-0"}')"
guard $PG "clone the platform's volume into a runner claim (dataSourceRef)" "${W[@]}" "${DRY[@]}" <<<"$(claim eve-ws-clone '"dataSourceRef":{"kind":"PersistentVolumeClaim","name":"postgres-data-postgres-0"}')"
guard $PG "bind a runner claim to an existing volume (volumeName)" "${W[@]}" "${DRY[@]}" <<<"$(claim eve-ws-bind '"volumeName":"platform-volume"')"
guard $PG "delete the platform's claim" "${W[@]}" -n eve delete pvc postgres-data-postgres-0 --dry-run=server
guard $PG "create a pod without a runner or kaniko label in the platform namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$RUNNER_SPEC")"
guard $PG "delete a platform pod" "${W[@]}" -n eve delete pod exec-probe --dry-run=server
guard $PG "label a platform pod as a runner" "${W[@]}" -n eve patch pod exec-probe --type=merge -p '{"metadata":{"labels":{"eve.type":"runner"}}}' --dry-run=server
guard $PG "create a NetworkPolicy without Eve's egress label in the platform namespace" "${W[@]}" "${DRY[@]}" <<<'{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"platform-open","namespace":"eve"},"spec":{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{}]}}'
guard $PG "delete a platform NetworkPolicy" "${W[@]}" -n eve delete networkpolicy platform-allow --dry-run=server
guard $PG "label a platform NetworkPolicy as Eve's" "${W[@]}" -n eve patch networkpolicy platform-allow --type=merge -p '{"metadata":{"labels":{"eve.horizon/egress":"runner"}}}' --dry-run=server
guard $PG "run a Job without the kaniko label in the platform namespace" "${W[@]}" "${DRY[@]}" <<<'{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"probe","namespace":"eve"},"spec":{"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"main","image":"registry.example/app:1"}]}}}}'
guard $PG "delete a platform Job" "${W[@]}" -n eve delete job platform-migrate --dry-run=server
guard $WG "a runner pod with an ephemeral volume (it could clone a platform claim)" "${W[@]}" "${DRY[@]}" <<<"$(pod eve probe "$(spec '"serviceAccountName":"eve-runner","volumes":[{"name":"e","ephemeral":{"volumeClaimTemplate":{"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}},"dataSource":{"kind":"PersistentVolumeClaim","name":"postgres-data-postgres-0"}}}}}]')" "$RUNNER_LABELS")"
guard $WG "a pod with an ephemeral volume in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"volumes":[{"name":"e","ephemeral":{"volumeClaimTemplate":{"spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}}}}]')")"

echo "== refused: pods and pod templates, in any namespace"
guard $WG "a privileged pod in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '' '{"name":"main","image":"registry.example/app:1","securityContext":{"privileged":true}}')")"
guard $WG "a host-network Deployment in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-acme-shop-prod probe "$(spec '"hostNetwork":true')")"
guard $WG "a host-PID Job in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(workload Job eve-acme-shop-prod probe "$(spec '"hostPID":true')")"
guard $WG "a CronJob mounting a host path" "${W[@]}" "${DRY[@]}" <<<"$(workload CronJob eve-acme-shop-prod probe "$(spec '"volumes":[{"name":"h","hostPath":{"path":"/"}}]')")"
guard $WG "a container adding SYS_ADMIN" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-acme-shop-prod probe "$(spec '' '{"name":"main","image":"registry.example/app:1","securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}')")"
guard $WG "a Deployment as eve-api's account in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-acme-shop-prod probe "$(spec '"serviceAccountName":"eve-api"')")"
guard $WG "a Deployment as eve-worker in the runner namespace" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-runners probe "$(spec '"serviceAccountName":"eve-worker"')")"
echo "== refused: pods and pod templates weaker than Pod Security baseline"
UNCONFINED='{"name":"main","image":"registry.example/app:1","securityContext":{"seccompProfile":{"type":"Unconfined"}}}'
UNCONFINED_INIT='{"name":"init","image":"registry.example/app:1","securityContext":{"seccompProfile":{"type":"Unconfined"}}}'
guard $WG "seccomp Unconfined for the pod" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"securityContext":{"seccompProfile":{"type":"Unconfined"}}')")"
guard $WG "seccomp Unconfined for a container" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '' "$UNCONFINED")")"
guard $WG "seccomp Unconfined for an init container of a Deployment" "${W[@]}" "${DRY[@]}" <<<"$(workload Deployment eve-acme-shop-prod probe "$(spec "\"initContainers\":[$UNCONFINED_INIT]")")"
guard $WG "AppArmor Unconfined for the pod" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"securityContext":{"appArmorProfile":{"type":"Unconfined"}}')")"
guard $WG "AppArmor Unconfined for a container" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '' '{"name":"main","image":"registry.example/app:1","securityContext":{"appArmorProfile":{"type":"Unconfined"}}}')")"
guard $WG "AppArmor unconfined by annotation on a Deployment's pods" "${W[@]}" "${DRY[@]}" <<<'{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"probe","namespace":"eve-acme-shop-prod"},"spec":{"selector":{"matchLabels":{"app":"probe"}},"template":{"metadata":{"labels":{"app":"probe"},"annotations":{"container.apparmor.security.beta.kubernetes.io/main":"unconfined"}},"spec":{"containers":[{"name":"main","image":"registry.example/app:1"}]}}}}'
guard $WG "an unmasked /proc" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"hostUsers":false' '{"name":"main","image":"registry.example/app:1","securityContext":{"procMount":"Unmasked"}}')")"
guard $WG "a sysctl outside the safe set" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"securityContext":{"sysctls":[{"name":"kernel.msgmax","value":"65536"}]}')")"
guard $WG "SELinux type spc_t for the pod" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"securityContext":{"seLinuxOptions":{"type":"spc_t"}}')")"
guard $WG "SELinux type spc_t for a container" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '' '{"name":"main","image":"registry.example/app:1","securityContext":{"seLinuxOptions":{"type":"spc_t"}}}')")"
# The API refuses hostProcess without hostNetwork, which the guard refuses
# anyway: this checks the hostProcess refusal itself is the one reported.
guard_says $WG hostProcess "a Windows host-process pod" "${W[@]}" "${DRY[@]}" <<<"$(pod eve-acme-shop-prod probe "$(spec '"os":{"name":"windows"},"hostNetwork":true,"securityContext":{"windowsOptions":{"hostProcess":true}}')")"
run deny "a DaemonSet in a managed namespace" "${W[@]}" "${DRY[@]}" <<<"$(workload DaemonSet eve-acme-shop-prod probe "$(spec '' )")"
guard $NG "a service account token Secret in a managed namespace" "${W[@]}" "${DRY[@]}" <<<'{"apiVersion":"v1","kind":"Secret","metadata":{"name":"probe","namespace":"eve-acme-shop-prod","annotations":{"kubernetes.io/service-account.name":"default"}},"type":"kubernetes.io/service-account-token"}'
guard $NG "Pod Security enforce=privileged on a managed namespace" "${W[@]}" patch namespace eve-acme-shop-prod --type=merge -p '{"metadata":{"labels":{"pod-security.kubernetes.io/enforce":"privileged"}}}' --dry-run=server
guard $NG "a new namespace with Pod Security enforce=privileged" "${W[@]}" "${DRY[@]}" <<<'{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"eve-acme-shop-priv","labels":{"eve.horizon/managed":"true","pod-security.kubernetes.io/enforce":"privileged"}}}'

echo "== refused: the orchestrator"
run deny "the orchestrator patches a Deployment, not its scale" "${O[@]}" auth can-i patch deployments -n eve-acme-shop-prod
guard $OG "the orchestrator scales a Deployment in a managed namespace up" "${O[@]}" -n eve-acme-shop-prod patch deployment web --subresource=scale --type=merge -p '{"spec":{"replicas":3}}' --dry-run=server
guard $OG "the orchestrator scales a Deployment outside the managed namespaces (kube-system)" "${O[@]}" -n kube-system patch deployment coredns --subresource=scale --type=merge -p '{"spec":{"replicas":0}}' --dry-run=server

"${K[@]}" -n eve delete configmap guard-probe --ignore-not-found >/dev/null
"${K[@]}" -n eve delete secret kaniko-cfg-probe --ignore-not-found >/dev/null
"${K[@]}" -n eve delete pod exec-probe --ignore-not-found --wait=false >/dev/null
"${K[@]}" -n eve delete networkpolicy eve-runner-probe --ignore-not-found >/dev/null
"${K[@]}" -n eve-runners delete networkpolicy eve-runner-probe --ignore-not-found >/dev/null
echo
if [[ $failures -gt 0 ]]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "all cases passed"
