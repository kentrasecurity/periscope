# Reference

Detailed behaviour, configuration and safety model. Start with the [README](../README.md).

## How it works

```
AgentTask (objective, scope, mode)
   │  every interval: health checks, no model calls while healthy
   ▼
incident ──► investigator: evidence + model tool loop ──► ActionPlan (immutable, digest-bound)
                                                            │
                         ActionApproval (human, or automatic) ◄┘
                                                            │
                         executor: dry-run, conditional write, journal ──► verify original checks
```

Three Deployments run with separate ServiceAccounts:

| Component | Can | Cannot |
| --- | --- | --- |
| investigator | read evidence, call the model, create plans and Pending approvals (Approve only for Automatic tasks) | write workloads, approve human tasks |
| executor | execute the approved plan's typed actions | call the model, change task intent |
| admission | validate operator records and every executor/investigator write | — |

### Modes

| Mode | Behaviour |
| --- | --- |
| `Observe` | Continuous health checks. Each new failure gets one read-only model diagnosis, recorded on the incident and in `.status.report`; model-suggested actions are shown but never executed. Healthy periods and already-diagnosed failures cost no model calls. |
| `Propose` | Investigate and write an `ActionPlan`; never execute. |
| `HumanApproved` | Continuous checks; each repair waits for a person to set the generated `ActionApproval` to `Approve` or `Reject`. |
| `Automatic` | Continuous checks; the operator approves its own plans, which still pass the same authorization, freshness, dry-run and admission checks. |

### What is detected

A task targets one resource (`targetRef`) or a scope (`scope.namespaces` plus optional kind/name/label filters). In a scope, discovery checks every listable namespaced kind:

- **Pods**: every declared container running and ready, images matching, init containers completed.
- **Deployments, StatefulSets, DaemonSets, ReplicaSets**: ready/updated replicas at the current generation; failures in managed Pods are attributed to the owning workload.
- **Services**: a selector that matches no Pod and no workload template (typo in selector or labels). Intentionally scaled-down backends stay healthy.
- **Ingresses**: a backend Service that does not exist (with the nearest Service name), a port the Service does not expose, or a backend that selects nothing.
- **CronJobs**: the most recent Job failed with the current job template; failed Jobs and their Pods are attributed to the CronJob. After a template repair the CronJob is healthy until its next run proves otherwise.
- **PodDisruptionBudgets and NetworkPolicies**: a selector, or a same-namespace NetworkPolicy peer, that matches no Pod or workload template. A PDB allowing zero disruptions is not flagged: it is often an intentional availability policy.
- **ConfigMaps**: an optional key reference that is missing while an existing key differs by at most two characters (the consumer starts silently without the value). Missing required keys fail the consuming Pod, which is investigated instead.
- **PersistentVolumeClaims**: `Lost`, or `Pending` after a consumer was scheduled.
- **Jobs**: `Failed`/`FailureTarget` (completed Jobs are ignored).
- **Custom resources and others** with `Ready`/`Available`/`Degraded`/`Failed`/`ReplicaFailure` conditions, and HPAs.

A resource becomes an incident only after it stays unhealthy for `monitoring.gracePeriodSeconds` (default 60; `0` disables), so rollouts, image pulls and starting Pods cost no model calls and never trigger repairs; resources inside the grace period are listed in `.status.suspects`. Workloads scaled to zero are healthy. The operator's own workloads carry `app.kubernetes.io/part-of: periscope`; discovery skips them and no plan may target them, so the agent can share a namespace with the application it watches.

Bookkeeping and credential kinds (Secrets, Endpoints, EndpointSlices, RBAC, Leases, Events, quotas, ...) are skipped. Kinds with unknown health semantics are listed in `.status.gaps` but do not make the task unhealthy; add explicit `checks` for them. Explicit checks also cover field equality, resource existence/absence, Pod-vantage DNS/TCP/HTTP probes and Prometheus equality queries. A scoped task with `checks` evaluates only those checks; to watch metrics as well as a whole namespace, run a second task that holds the checks ([example](../tests/e2e/suite/metrics-task.yaml)).

When no safe repair exists inside the task (a missing Secret, a bug in the application, a dependency outside the scope, storage that can only be fixed by recreating it), the doctor records the reason on the incident (`outcome: NoSafeAction`), reports it as needing owner action and writes nothing. A repair that failed for a reason a new investigation cannot address is held the same way (`outcome: RepairFailed`), so it never stalls the other incidents in scope. Held incidents are not investigated again until their failure changes; repairs rejected by the API or RBAC are fed back to the model as rejected actions on the next attempt.

A failure is identified by its kind (container waiting/termination reasons, conditions, generation), not by restart counters, so per-incident attempt limits hold for crash loops while a spec change or a different reason opens a new incident.

## Configuration

Installation is described in the [README](../README.md#quickstart). The release namespace holds the coordination Leases and must be listed in `policy.namespaces` together with the application namespaces; it can be the application namespace itself.

Optional repairs that handle credentials or storage are refused unless enabled under `policy.repairs`, and the RBAC preset grants only what is enabled:

| Setting | Allows |
| --- | --- |
| `secrets.create: generate` | create a missing Opaque Secret whose keys the executor fills with random values |
| `secrets.create: fromSource` + `secrets.sources` | create a missing Secret by copying keys from the named Secrets |
| `storage.replaceUnboundClaims` | delete and recreate a PersistentVolumeClaim that never bound (`Pending`, no `volumeName`), for example to fix its storage class; also lets the investigator list StorageClass names (the chart's only cluster-scoped grant) so a misspelled class is restored to the nearest existing one |
| `storage.expandClaims` | increase a claim's `spec.resources.requests.storage` |

Plans never contain Secret values: a created Secret names its keys in `secretSources`, the executor fills them at write time, and digests in plan status record key names only. With secret creation enabled, the executor and admission (never the investigator or the model) may `get` Secrets in enrolled namespaces to copy allowed sources and confirm their own writes; the investigator cannot read Secrets, so a create is bound without reading and the API rejects it if the Secret already exists. Existing Secrets are never changed; bound claims and PersistentVolumes are never deleted or replaced. Without `repairs.storage`, the preset grants no PersistentVolumeClaim writes.

`policy.experimental.applicationErrors` (off by default) also scans the recent logs (last three minutes, up to 20 workloads per pass) of workloads that are healthy by status. Three or more lines with a connection-refused, timeout, DNS, unreachable or TLS error open an incident; the model looks for a Kubernetes-side cause such as a NetworkPolicy blocking the client, and returns no action when the cause is in the application. Recovery is verified when the error stops appearing. Repairs follow the task mode.

Workload permissions come from Kubernetes RBAC. `workloadRBAC.preset` creates them in every enrolled namespace:

| Preset | Grants |
| --- | --- |
| `none` (default) | nothing; supply Roles yourself |
| `observe` | read access to common application resources and Pod logs, never Secrets |
| `repair` | `observe` plus executor patch/create/delete on Pods, Services, ConfigMaps, workloads, Jobs, Ingresses, NetworkPolicies, HPAs and PDBs; RBAC is never granted, and Secret or PVC writes only as enabled under `policy.repairs` |

`workloadRBAC.extraReadRules`/`extraRepairRules` add custom resources. Admission still restricts every executor write to the exact approved plan; for field- or value-level limits add your own admission policies.

Provider settings: `provider.name` (`openai` or `anthropic`), `provider.model` (default `gpt-6-luna` or `claude-opus-5-5`), `provider.baseURL` (default: the provider's public API), `provider.existingSecret`/`secretKey`. OpenAI `gpt-6-luna` uses the Responses API with medium reasoning by default (`provider.api`, `provider.reasoningEffort`, `provider.maxOutputTokens`). With Anthropic, `provider.reasoningEffort` (`low`/`medium`/`high`) sets the model's effort; Claude 5.5 models always think, their thinking blocks are replayed unchanged within an investigation, and `maxOutputTokens` (default 16000) includes thinking. Requests mark the system prompt and the latest turn for prompt caching, and on the public API opt into server-side refusal fallbacks, so a safety-classifier false positive on security-adjacent evidence is retried on Anthropic's recommended model instead of failing the investigation. Rate limits and 5xx responses are retried a bounded number of times; other provider errors (invalid key, exhausted credit, unknown model) appear verbatim in `.status.report`. `controller.workers` (default 4) sets how many tasks reconcile in parallel; `controller.investigatorTimeout` bounds one investigation.

Prometheus (`observations.prometheus`) answers arbitrary model-written PromQL, so its endpoint must itself enforce the namespace boundary: `scopeBoundary` is only the owner's declaration. With a cluster-wide Prometheus, put [prom-label-proxy](https://github.com/prometheus-community/prom-label-proxy) in front of it with `--label=namespace --label-value=<namespace>` ([example](../tests/e2e/suite/prom-proxy.yaml), [values](../tests/e2e/suite/values-prometheus.yaml)). The source's `namespaces` must equal the task scope exactly, and tasks whose scope filters resources cannot query metrics.

## Operating tasks

[examples/repair-test.yaml](../examples/repair-test.yaml) creates a namespace with broken workloads to try the operator on.

```sh
kubectl apply -f examples/repair-test.yaml
kubectl get agenttasks -n agent-operator-test -o wide
kubectl get agenttask NAME -n agent-operator-test -o jsonpath='{.status.report}'
```

Review and approve a repair in `HumanApproved` mode:

```sh
kubectl get agenttask NAME -n NS -o jsonpath='{.status.planRef.name}{"\n"}{.status.approvalRef.name}{"\n"}'
kubectl describe actionplan PLAN -n NS
kubectl patch actionapproval APPROVAL -n NS --type=merge -p '{"spec":{"decision":"Approve"}}'
```

Each approval binds one immutable plan, task generation and monitoring cycle, and expires after 30 minutes (expired requests are replaced). Suspend a task with `spec.suspend: true`; this stops further work but cannot undo a write the API already accepted. GitOps controllers may revert repairs; persist desired changes through your usual review.

Useful status fields: `.status.phase`, `.status.healthy`, `.status.report`, `.status.incident` (with `diagnosis` in Observe), `.status.suspects`, `.status.pendingIncidents`, `.status.incidentHistory`, `.status.gaps`, `.status.budget`, and plan `.status.checkResults`.

### Evidence

Each incident starts from the failing results of its health checks (for example, the Service selector that matches nothing) and a compact bundle: the resource and its owners, API schema, its Events, Warning Events of its Pods and ReplicaSets, other Warning Events in the namespace, and the tail of current and previous logs of up to three failing Pods. Events are newest first. The model then reads more with tools: `get_resource`, `list_resources`, `get_owner`, `describe_api`, `get_events`, `list_events` (namespace-wide, filtered by type, reason or involved object), `get_pod_logs`, and optionally `query_prometheus`, network probes and reviewed runbooks.

### Limits

`healingLimits` (defaults: 3 attempts per incident, 30 s retry cooldown, a one-hour window with 20 model calls and 100 tool calls) bound continuous tasks, including every Observe task. `limits` bound each investigation. Health checks continue while budgets are exhausted.

Supported actions are bounded JSON patches, workload restarts, exact-object creates and UID-bound deletes of namespaced resources. Bound PersistentVolumeClaims and PersistentVolumes are never deleted, and existing Secrets are never changed, whatever RBAC grants; the opt-ins under `policy.repairs` are the only exceptions for unbound claims and missing Secrets.

## Security

Evidence is redacted before every model call: Secret payloads, literal values of credential-like environment variables and headers, credential URLs, bearer tokens and API keys. Names of referenced Secrets and ConfigMaps (`secretName`, `secretKeyRef`, `envFrom`, `imagePullSecrets`) are kept, so broken references can be diagnosed and repaired. Annotations are excluded. Resource text, logs and documents are untrusted evidence, never instructions. The provider key is mounted only in the investigator. See [security](security.md).

## Testing

Requires Go 1.25 and Helm. `make test` runs the race suite and `go vet` with module mode forced on. `go test -tags live ./tests/live` runs the real investigator, executor and model provider against a simulated namespace with three faults (set `DOCTOR_PROVIDER` and `DOCTOR_API_KEY_FILE`; it makes billed model calls). `tests/e2e/suite/run.sh` runs 19 production-like faults plus a protected and a control workload against a real release in `agent-operator-test` and checks that every repair restores the intended value ([results](validation.md#cluster-suite)). See [validation](validation.md) for results and what is not verified.
