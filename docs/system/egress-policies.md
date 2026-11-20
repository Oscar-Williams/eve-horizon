# Egress policies

Eve limits where tenant pods and job runner pods may connect with Kubernetes
NetworkPolicies. The project rule `egress.default_deny`
([security profiles](security-profiles.md)) decides what is enforced; the
policies themselves live in the cluster and are written by the worker.

What they stop: a tenant pod or job reaching the platform's own services
(other than the API's public port), the metadata server, another tenant's
namespace, or any private address. With the project rule
`egress.allow_hosts` at `strict` and an enforcement provider, they also stop
job code and apps reaching internet hosts the project has not declared (see
[host allow lists](#host-allow-lists)).

NetworkPolicy does nothing on a CNI that does not enforce it. Set the
instance setting `network.policy_enforced` to say whether yours does (see
[enforcement](#enforcement)).

## Env namespaces

Each environment namespace gets, by its project's profile:

| Profile | Policies |
|---|---|
| `legacy` | None. A deploy or reconcile removes any it finds. |
| `audit` | `eve-egress-audit` (allows all egress), then `eve-egress` and `eve-egress-metadata`. Nothing is blocked; mistakes in the strict set show while they are harmless. |
| `strict` | `eve-egress` and `eve-egress-metadata`. `eve-egress-audit` is removed. |

`eve-egress` selects every pod in the namespace and allows:

- DNS to `kube-dns` in `kube-system`, on 53 (UDP and TCP);
- the namespace itself;
- `eve-api` pods in the platform namespace, on the API's public port
  (`4701`) only, never the internal port;
- the ingress controller (`app.kubernetes.io/name: traefik` in `traefik` or
  `kube-system`) on its container ports 8000 and 8443: calls to the
  instance's own public hosts hairpin to its pods, which `ipBlock` cannot
  match;
- `0.0.0.0/0` except `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `100.64.0.0/10`, `169.254.0.0/16` and the CIDRs in
  `network.private_cidrs`;
- the env's managed databases: an IP host as a `/32` on its port, a host
  name as the `/32`s it resolves to at deploy or reconcile, a cluster
  service (`<svc>.<ns>.svc...`) as its namespace on the port;
- the app-link producers the project consumes for this env, as their
  namespaces on the producer service's port.

`eve-egress-metadata` lets only pods labelled `eve.workload_identity=true`
reach the metadata server (`169.254.169.254:80`, `169.254.169.252:988`). The
deployer sets that label on the pods (Deployments and service jobs) of a
service whose service account has GKE Workload Identity (object-store
`workload-identity` mode). No other pod can reach it under `strict`.

The deployer writes these after rendering and before any workload of the
deploy or service job is applied, so new pods start covered. Under `strict`,
a failure to write them fails the deploy; otherwise it is logged.

NetworkPolicy matches the destination pod's port after Service translation,
so every in-cluster port here is a container port.

## Runner pods

Runner pods (job code) fail closed. Every runner pod carries
`eve.horizon/runner=true` from the moment it exists, warm or claimed,
sandbox or plain; a claimed pod also gets `eve.horizon/project-id`.

Two static policies in `k8s/base` (`runner-network-policies.yaml`), in the
runner namespace (`eve-runners`) and, for plain-pod runners (org filesystem
jobs), in the platform namespace:

- `eve-runner-deny` selects every runner pod and allows only DNS and
  `eve-api` on its public port. A warm pod, which has no project yet, can
  reach nothing else. (A deny that waited for the project label would leave
  the pod open in between.)
- `eve-runner-ingress` lets only `eve-worker` pods reach runner pods, only
  on the submit port (4749). Behind it, a submit must still present the
  pod's own key or the worker's pool key (see [runner pods](runner-pods.md)).

Each project then has `eve-runner-<project>` in both namespaces, selecting
`eve.horizon/runner=true` and `eve.horizon/project-id=<project>`. The name is
the project id lowercased with `_` as `-` and 8 hex of its hash (NetworkPolicy
names allow no `_`); the label keeps the real id.

| Profile | Runner policies |
|---|---|
| `legacy` | `eve-runner-<project>-audit` alone (allows all egress): the static deny would otherwise leave the project's jobs DNS and the API. |
| `audit` | `eve-runner-<project>-audit`, then `eve-runner-<project>`. |
| `strict` | `eve-runner-<project>`: DNS, the API's public port, the ingress controller, the internet rule above, the project's own env namespaces (any port, for app APIs) and its app-link producers: for a link with a fixed producer env, that env whether or not the project has environments of its own (jobs resolve such links with none); for a `same` link, the producer env of each of the project's envs. |

The worker writes them at deploy and reconcile. Before it starts a runner
pod, it checks the project's set and writes only when a namespace lacks it or
holds a set the profile no longer wants; a failure there is logged and the
job goes on (the deny still holds). Reconcile removes the runner policies of
deleted projects.

## Host allow lists

The project rule `egress.allow_hosts` limits the internet hosts a project's
runner pods and env pods reach. The hosts come from three places:

- **The manifest:** `x-eve.egress.hosts` at project level (every pod of the
  project's envs, and its runners) and on each service (that service's pods
  only). See [manifest](manifest.md#x-eveegresshosts).
- **The harnesses:** each harness adapter in
  `packages/shared/src/harnesses/adapters` declares the hosts its CLI needs
  (`egressHosts`). Every runner policy carries all of them, since a job may
  name any harness:

  | Harness | Hosts |
  |---|---|
  | `claude`, `mclaude` | `api.anthropic.com` |
  | `zai` | `api.z.ai` |
  | `gemini` | `generativelanguage.googleapis.com` |
  | `codex`, `code` | `api.openai.com`, `chatgpt.com` (ChatGPT sign-in), `auth.openai.com` (its token refresh) |
  | `pi` | `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.z.ai` |

  A custom base URL (`ANTHROPIC_BASE_URL`, `Z_AI_BASE_URL`), another pi
  provider, Vertex AI or a Google sign-in for Gemini goes in the manifest.
- **The repository:** runners also reach the git host of the project's
  `repo_url` (HTTPS on 443, `ssh://` on its port, `git@host:` on 22).

Env pods get the manifest lists only; runner pods get the project list, the
harness hosts and the git host.

### Providers

`EVE_EGRESS_FQDN_PROVIDER` on the worker says what enforces the lists:

- `gke`: the worker writes GKE `FQDNNetworkPolicy` objects
  (`networking.gke.io/v1alpha1`). The cluster needs
  `--enable-fqdn-network-policy` (Dataplane V2). One policy per host and
  port, named `eve-fqdn-<hash>` and labelled `eve.horizon/egress=fqdn` (and
  `eve.horizon/project-id`); the host is in the `eve.horizon/egress-host`
  annotation. One per host keeps each under GKE's limit of 50 resolved
  addresses per policy. In the runner namespaces they select
  `eve.horizon/runner=true` and the project label; in an env namespace the
  project list selects every pod and a service list selects
  `eve.component=<service>`. A deploy or reconcile writes the wanted set
  first, then deletes Eve's others; policies without the label are never
  touched.
- `none` (default): nothing is written, and a project whose
  `egress.allow_hosts` is `strict` cannot deploy, run a service job or
  dispatch a job: "egress allow lists need a provider
  (EVE_EGRESS_FQDN_PROVIDER)".

### By profile

| `egress.allow_hosts` | What changes |
|---|---|
| `legacy` | Nothing. With `gke`, a deploy or reconcile removes Eve's FQDN policies. |
| `audit` | With `gke`, the FQDN policies are written beside the internet rule and the allow-all companions. Rules add up, so nothing is blocked. A finding is recorded at each deploy and reconcile for a project that declares no hosts (`reason: no_declared_hosts`) or has no provider (`no_provider`). |
| `strict` | The internet rule (`0.0.0.0/0` outside private ranges) and every allow-all companion are left out of `eve-egress` and `eve-runner-<project>`, so only the FQDN policies open the internet. Everything else in [env namespaces](#env-namespaces) and [runner pods](#runner-pods) stays. The static `eve-runner-deny` still holds a warm pod to DNS and the API. |

The rule is rule set 3: a profile stamped before it runs it as `audit`, and
under rule set 3 `strict` makes `egress.default_deny` strict too.

Dispatch writes a project's runner FQDN policies when their names differ
from what its manifest, harnesses and repository want (a first job, a
changed list), before the pod starts.

### Leaks

- **Shared addresses:** GKE filters by the addresses a name resolves to, so
  every host on the same addresses is reachable too: allowing
  `generativelanguage.googleapis.com` opens Google's other APIs, and a CDN
  name opens the CDN's other customers.
- **DNS:** lookups succeed for any name, so a pod can still leak data in
  DNS queries to a name server it does not control.
- **The ingress controller:** calls to any public host of this instance
  still reach the ingress controller, as under `egress.default_deny`.

### Audit evidence

Rules add up, so under `audit` nothing is blocked and Eve cannot see what
`strict` would refuse. Log allowed flows for the project's namespaces (GKE:
Dataplane V2 network logging with `allow.log`) and list connections whose
destination is not one of the declared hosts. Fourteen days of that is the
evidence before a project flips.

## Ingress isolation

The project rule `network.ingress_isolation` limits who may connect to an
env namespace's pods. The worker writes the policies with the egress ones
(deploy, service job, reconcile), labelled `eve.horizon/ingress=env`, so
neither sync deletes the other's.

| Profile | Policies |
|---|---|
| `legacy` | None. A deploy or reconcile removes any it finds. |
| `audit` | `eve-ingress-audit` (admits everything), then `eve-ingress`. Nothing is refused. |
| `strict` | `eve-ingress` alone. |

`eve-ingress` selects every pod in the namespace and admits, on any port:

- the ingress controller (`app.kubernetes.io/name: traefik` in `traefik` or
  `kube-system`), for the env's hosts;
- the platform's own services in the platform namespace (`eve-api` fetches
  app API specs and proxies app calls), but no runner pod there (pods
  without `eve.horizon/runner`);
- the project's own env namespaces, this one included;
- the project's runner pods (`eve.horizon/runner=true` and its
  `eve.horizon/project-id`, in `eve-runners` and the platform namespace);
- the env namespaces and runner pods of projects that consume its app links
  through a live API grant for this env: for a `same` link, the consumer's
  env of the same name; for a link fixed to this env, every env of the
  consumer.

Not admitted under `strict`: other tenants' namespaces and runners, and
anything outside the cluster that does not come through the ingress
controller, such as public TCP listeners (`x-eve.tcp_ingress`, through a
load balancer straight to the pods). Kubelet health checks come from the
node and are not subject to these policies on GKE Dataplane V2.

## The API URL apps and runners get

Apps and runner pods get `EVE_API_APP_URL` as their `EVE_API_URL` (default
`http://eve-api.eve.svc.cluster.local:4701`), never the worker's own
`EVE_API_URL`, which points at the internal port where one is set. The
policies allow only that port, so `/internal/*` is out of reach. See
[deployment](deployment.md#internal-api-port).

## Profile changes and reconcile

Setting a profile on a project, an org or the instance makes the worker
reconcile the projects in scope at once, so companions go (or come back)
without a deploy. The profile stands if that fails; the response says so.

`eve system security reconcile` (`POST /system/security/reconcile`) writes
every environment's and project's policies with no workload restart, removes
those of deleted projects, and reports what it wrote, removed and could not
do. Envs never deployed are counted as without a namespace.

## Enforcement

- `network.policy_enforced`: `true` where the CNI enforces NetworkPolicy
  (for example GKE Dataplane V2; an infrastructure template can take it from
  its outputs), `false` where it does not. `eve doctor security` shows it;
  while it is not `true` the report says egress rules are not effective and
  every project's strict checklist is not clean.
- `network.private_cidrs`: more IPv4 CIDRs the internet rule must not reach
  (the node range, VPC peerings, a control plane on a public-looking range).
  Comma or space separated, or a JSON array; `/0` is refused.

```bash
eve system settings set network.policy_enforced true
eve system settings set network.private_cidrs "198.18.0.0/15"
```

## Running it on a managed cluster

- **The worker's rights:** the worker manages NetworkPolicies through
  `eve-worker-tenant`, bound in the namespaces it manages and statically in
  the platform and runner namespaces (see
  [deployment](deployment.md#worker-rights)). Hold its writes in the
  platform and runner namespaces to `eve-runner-<project>` policies with an
  admission policy:
  name prefix `eve-runner-`, not `eve-runner-deny` or `eve-runner-ingress`,
  label `eve.horizon/egress=runner`, `podSelector.matchLabels` with
  `eve.horizon/runner` and `eve.horizon/project-id` and no
  `matchExpressions`, `policyTypes` `[Egress]` only, checked on the old
  object for updates and deletes.
- **Overlays that set one namespace for everything** (`namespace:` in a
  kustomization) would move the runner-namespace copies of the static
  policies into the platform namespace; the build then fails on the duplicate
  names. Apply the runner namespace's objects from their own kustomization.
- **FQDN policies:** the base ClusterRole lets the worker manage
  `fqdnnetworkpolicies.networking.gke.io`; where the CRD is absent the
  rule is inert. Turning on `--enable-fqdn-network-policy` restarts `anetd`
  on each node; do it in an attended window, then set
  `EVE_EGRESS_FQDN_PROVIDER=gke` on the worker.
- **Flow logs:** to see what `strict` would refuse before turning it on,
  log allowed connections for Eve's namespaces (GKE: `NetworkLogging` with
  `allow.log` or `allow.delegate` and the namespace annotation) and compare
  each flow with the strict set.

## Limits

- IPv4 only: the internet rule is `0.0.0.0/0`; IPv6 egress is not allowed
  under `strict`.
- A managed database host name is resolved when the policy is written; if
  its address changes, `strict` blocks it until the next deploy or reconcile.
- DNS is allowed to `kube-dns` pods only; a node-local DNS cache on a
  link-local address is not covered.
- Ingress to tenant namespaces is the rule `network.ingress_isolation`
  (see [ingress isolation](#ingress-isolation)).

## Rollback

The policies are plain Kubernetes objects. A release before them ignores
them, and they keep doing what they did:

- **Env namespaces:** under `audit` the companion keeps everything open, so
  nothing is blocked. Under `strict` the strict set keeps applying, and an
  earlier release neither updates it (a new managed database or app link is
  not added) nor gives apps the public API URL (a redeploy hands them the
  worker's `EVE_API_URL`, the internal port where one is set). So set
  `strict` projects to `audit`, and let the reconcile run, before rolling
  back; or delete `eve-egress` from their namespaces.
- **Runner policies** select only `eve.horizon/runner=true`, which pods from
  earlier releases do not carry, so they affect nothing after a rollback.
- **Ingress isolation (0.1.328):** a release before it ignores
  `eve-ingress` and `eve-ingress-audit`. Under `audit` the companion keeps
  everything open. Under `strict` `eve-ingress` keeps applying with the
  peers it last had, so a new app-link consumer or env is not added: set
  `strict` projects to `audit` and let the reconcile run before rolling
  back, or delete `eve-ingress` (`kubectl delete networkpolicy -A -l
  eve.horizon/ingress=env`).
- **Host allow lists (0.1.328):** a release before them leaves the FQDN
  policies in place. They only allow, so they block nothing; delete them
  with `kubectl delete fqdnnetworkpolicies -A -l eve.horizon/egress=fqdn`
  when tidying. Its first deploy or reconcile of a `strict` project puts
  the internet rule back into `eve-egress` and `eve-runner-<project>` (it
  knows only `egress.default_deny`), so a rollback opens the internet again
  rather than closing anything. Manifests that declare `x-eve.egress` still
  sync there, since earlier releases pass unknown `x-eve` keys through.
