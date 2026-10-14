# Validation

What was tested, against which model, and what is not verified. Results are from `gpt-6-luna` (OpenAI); the Anthropic path is covered by unit tests only.

## Unit and simulated-cluster tests

- `make test`: `go test -race ./...` and `go vet ./...`.
- `go test -tags live ./tests/live` runs the real investigator, executor and provider client against an in-memory namespace with three faults (missing image tag, misspelled ConfigMap key, Service selector typo). A small simulated kubelet derives ReplicaSets, Pods, Events and workload status from the Deployment templates. It makes billed model calls:

```sh
DOCTOR_PROVIDER=openai DOCTOR_API_KEY_FILE=./key go test -tags live -v -timeout 30m ./tests/live
```

Observe diagnosed all three without writing anything; Automatic repaired all three with one single-field plan each, in about 4 minutes.

## Cluster suite

`tests/e2e/suite/run.sh` runs against a real release in one namespace: it installs the faults below, a workload labelled `periscope.kentrasecurity.io/healing-protected=true` and a healthy control, runs the doctor in Observe until every fault is diagnosed, then switches to Automatic. `check.py` fails the run if Observe writes anything, if the protected or control workloads change, if a held fault is written, or if a repair is healthy but not what the broken value was meant to be (for example a Service pointed at another application).

| Fault | Outcome |
| --- | --- |
| Image tag does not exist | repaired: valid tag |
| ConfigMap key typo in a Deployment | repaired: key restored |
| Service selector typo | repaired: selector restored, not repointed at another workload |
| Crash from a mountPath typo, visible only in logs | repaired |
| OOMKilled under a too-low memory limit | repaired: limit raised, command unchanged |
| Readiness probe on the wrong port | repaired |
| CPU request larger than any node | repaired: schedulable value |
| PVC claimName typo | repaired |
| CPU-throttled worker visible only in Prometheus | repaired |
| Ingress backend Service typo | repaired |
| CronJob command typo | repaired |
| PodDisruptionBudget and NetworkPolicy selector typos | repaired |
| Optional ConfigMap key typo (silently ignored) | repaired in the consuming Deployment |
| PVC with a misspelled storage class (`policy.repairs.storage`) | replaced; Bound |
| Missing Secret (`policy.repairs.secrets`) | created with a generated value that appears in no plan, task, approval, Event or log |
| Ready client logging `Connection refused` (`policy.experimental`) | NetworkPolicy extended to allow the client |
| Protected workload | untouched, never an incident |
| Crash inside the application | held with a reason (`NoSafeAction`) |
| Dependency in a namespace outside the scope | held with a reason |

Latest combined run (all opt-ins enabled): 19 of 19 faults diagnosed, 17 repaired, 2 held, protected and control workloads untouched. Without the opt-ins, Secret and PVC faults are held.

## Not verified

- The Anthropic provider has not been run end to end.
- The `HumanApproved` flow is covered by unit tests, not by the live suite.
- Upgrading a release in place from an earlier version.
- Rancher, Argo CD and cert-manager style annotations were exercised (Rancher); other controllers that mutate objects after a repair were not.

## Known limits

- Event filtering for `list_events` and namespace Warnings uses the scope's kind/name selectors, not its label selectors, so Event text about resources excluded only by label can reach the model. Resource bodies cannot, and nothing can be written to them.
- Firing Prometheus alerts are not an incident source; Prometheus is a read tool and an explicit check type. A scoped task with `checks` skips discovery, so metric checks need their own task.
- The API group `periscope.kentrasecurity.io` and the Go module path are placeholders.
