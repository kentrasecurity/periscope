<h1 align="center">Periscope</h1>

<p align="center">
  An AI doctor for Kubernetes namespaces: it watches your workloads, finds the root cause when something breaks, and fixes it with a small, verified, approved change.
</p>

<div align="center">
  <a href="https://github.com/kentrasecurity/periscope/pkgs/container/docker%2Fperiscope">
    <img src="https://img.shields.io/badge/ghcr.io-periscope-blue" alt="GitHub Container Registry">
  </a>
  <a href="https://kubernetes.io/">
    <img src="https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes">
  </a>
  <a href="https://github.com/kentrasecurity/periscope/pkgs/container/helm%2Fperiscope">
    <img src="https://img.shields.io/badge/helm-chart-0F1689?logo=helm&logoColor=white" alt="Helm Chart">
  </a>
</div>

## Table of Contents
- [What is Periscope?](#what-is-periscope)
- [How it works](#how-it-works)
- [What it can fix](#what-it-can-fix)
- [Quickstart](#quickstart)
- [Your first task](#your-first-task)
- [Approving repairs](#approving-repairs)
- [Configuration](#configuration)
- [Safety](#safety)
- [Additional Documentation](#additional-documentation)
- [Development](#development)
- [Contributing](#contributing)

## What is Periscope?

**Periscope** is a Kubernetes operator that keeps watch over application namespaces. You describe what "healthy" means in plain language, and Periscope:

- **Monitors** every resource in scope with cheap health checks, without calling a model while things are healthy
- **Investigates** failures from status, Events, current and previous logs, API schemas and optional Prometheus metrics
- **Diagnoses** the root cause with a model (OpenAI or Anthropic)
- **Repairs** it with the smallest typed change, when you allow it
- **Verifies** that the original failure is gone

The model proposes repairs but never executes them. A separate executor makes the write, and an admission webhook rejects anything that does not exactly match the approved plan.

## How it works

```
AgentTask (objective, scope, mode)
   │  health checks every interval, no model calls while healthy
   ▼
incident ──► investigator: evidence + model ──► ActionPlan
                                                   │
                ActionApproval (you, or automatic) ◄┘
                                                   │
                executor: dry-run, write, verify ◄─┘
```

Each `AgentTask` runs in one of four modes:

| Mode | What happens |
| --- | --- |
| `Observe` | Diagnoses each failure once and writes the root cause to `.status.report`. Never changes anything. |
| `Propose` | Writes an `ActionPlan` for each failure. Never executes it. |
| `HumanApproved` | Each repair waits for a person to approve it. |
| `Automatic` | Repairs are approved by the operator and still pass every safety check. |

## What it can fix

| Problem | Example repair |
| --- | --- |
| Image tag does not exist | restore a valid tag |
| ConfigMap key typo, crash from a wrong mount path | fix the reference in the workload template |
| Service, Ingress, PDB or NetworkPolicy selecting nothing | restore the intended selector or backend |
| OOMKilled, unschedulable requests, wrong probe port | adjust limits, requests or the probe |
| Failing CronJob | fix the job template |
| Metric-only problems (e.g. CPU throttling, via Prometheus) | adjust the limit |
| Missing Secret, never-bound PVC *(opt-in)* | create the Secret with generated values, recreate the claim |
| Ready app logging "connection refused" *(experimental)* | allow the client in the blocking NetworkPolicy |

When no safe repair exists (a bug in the application, a dependency outside the scope), Periscope writes nothing and reports why. See [validation](docs/validation.md) for live results.

## Quickstart

Create a namespace and the provider API key Secret:

```bash
kubectl create namespace periscope-system
kubectl create secret generic agent-llm -n periscope-system --from-file=api-key=./key
```

Write a `values.yaml` listing the namespaces Periscope may look at (the release namespace must be included):

```yaml
policy:
  authorization: RBAC
  namespaces: [periscope-system, shop]
workloadRBAC:
  preset: repair        # or observe, for diagnosis only
provider:
  name: openai          # or anthropic
  existingSecret: agent-llm
  secretKey: api-key
```

Install the Helm chart (the CRDs are included):

```bash
helm install periscope oci://ghcr.io/kentrasecurity/helm/periscope \
  --version 0.1.0 -n periscope-system -f values.yaml
```

## Your first task

Ask Periscope to look after a namespace:

```yaml
apiVersion: periscope.kentrasecurity.io/v1alpha1
kind: AgentTask
metadata:
  name: shop-doctor
  namespace: shop
spec:
  mode: Observe           # switch to HumanApproved or Automatic to allow repairs
  scope:
    namespaces: [shop]
  objective: >-
    Keep the application workloads in this namespace healthy. Find the root
    cause of each failure and repair it with the smallest change that restores
    the intended behaviour. Never delete data or remove probes to pass checks.
  limits:
    deadlineSeconds: 600
    maxModelCalls: 12
    maxToolCalls: 60
```

```bash
kubectl apply -f shop-doctor.yaml
kubectl get agenttasks -n shop
kubectl get agenttask shop-doctor -n shop -o jsonpath='{.status.report}'
```

Want something broken to try it on? [`examples/repair-test.yaml`](examples/repair-test.yaml) creates a namespace full of faulty workloads.

## Approving repairs

In `HumanApproved` mode, each repair waits for you:

```bash
kubectl get actionplans,actionapprovals -n shop
kubectl describe actionplan PLAN -n shop
kubectl patch actionapproval APPROVAL -n shop --type=merge -p '{"spec":{"decision":"Approve"}}'
```

Approvals expire after 30 minutes. Pause a task at any time with `spec.suspend: true`.

## Configuration

The most used Helm values:

| Value | Description |
| --- | --- |
| `policy.namespaces` | Namespaces Periscope may read and repair |
| `workloadRBAC.preset` | `observe` (read only), `repair`, or `none` (bring your own Roles) |
| `provider.name` / `provider.model` | `openai` (`gpt-6-luna`) or `anthropic` (`claude-opus-5-5`) |
| `provider.existingSecret` / `secretKey` | Secret holding the API key |
| `policy.repairs.secrets.create` | Allow creating missing Secrets (`generate`, `fromSource`) |
| `policy.repairs.storage.*` | Allow replacing never-bound PVCs and growing PVC requests |
| `policy.experimental.applicationErrors` | Investigate healthy workloads whose logs repeat network errors |
| `observations.prometheus` | Prometheus endpoint for metric evidence and checks |

All options are in [`values.yaml`](charts/periscope/values.yaml). Behaviour, limits and checks are described in the [reference](docs/reference.md).

## Safety

- The model never writes to the cluster. It only proposes typed plans.
- Every write is dry-run first, bound to the exact approved plan, and checked by an admission webhook.
- Secret values are never sent to the model or written into plans.
- RBAC is never granted, Secrets are never changed, bound volumes are never deleted.
- Workloads labelled `periscope.kentrasecurity.io/healing-protected=true` are never touched.
- Budgets cap model and tool calls per task and per hour.

See [security](docs/security.md) for the full model.

## Additional Documentation

| Topic | Description |
| --- | --- |
| [Reference](docs/reference.md) | Modes, detection, evidence, limits and all configuration |
| [Security](docs/security.md) | Permissions, admission and redaction |
| [Validation](docs/validation.md) | Live test results and what is not verified yet |

## Development

Requires Go 1.25, Helm and Docker.

```bash
make test       # unit tests with the race detector, go vet
make image      # build dist/periscope-images.tar
make package    # build the Helm chart
```

`tests/e2e/suite/run.sh` runs a full fault suite against a real cluster (billed model calls).

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request (explain the changes!)

## Disclaimer
> [!CAUTION]
> Periscope changes resources in your cluster when a task runs in `HumanApproved` or `Automatic` mode. Start with `Observe`, review its diagnoses, and keep GitOps or backups in place for anything critical.
