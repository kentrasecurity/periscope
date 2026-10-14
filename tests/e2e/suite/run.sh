#!/usr/bin/env bash
# Namespace doctor suite in agent-operator-test: nine repairable faults (one
# visible only in Prometheus), four with no safe repair, one protected
# workload and one healthy control. Observe must diagnose every fault without
# writing; Automatic must repair the nine with their intent preserved, hold the
# four with a reason and no writes, and leave the protected and control
# workloads alone. Requires a release in agent-operator-test with
# workloadRBAC.preset=repair and Prometheus through suite-prom-proxy:
#   helm install periscope charts/periscope -n agent-operator-test \
#     -f tests/e2e/suite/values-openai.yaml -f tests/e2e/suite/values-prometheus.yaml
# SUITE_REPAIRS=1 (with values-repairs.yaml) expects the missing Secret and the
# never-bound PVC to be repaired; SUITE_EXPERIMENTAL=1 (with
# values-experimental.yaml) adds the application-error scenario.
# Makes billed model calls.
#   tests/e2e/suite/run.sh [observe-minutes] [repair-minutes]
set -uo pipefail
ns=agent-operator-test
here=$(cd "$(dirname "$0")" && pwd)
observe_for=${1:-30}
repair_for=${2:-60}
results=${RESULTS:-$(mktemp -d)}
check() { python3 "$here/check.py" "$@"; }

wait_phase() { # phase minutes
  local deadline=$(( $(date +%s) + $2 * 60 )) code
  while :; do
    echo "--- $(date +%T) $1: $(kubectl get agenttask suite-doctor -n $ns -o jsonpath='{.status.phase}: {.status.report}' | head -c 200)"
    echo "    metrics: $(kubectl get agenttask suite-metrics -n $ns -o jsonpath='{.status.phase}: {.status.report}' | head -c 200)"
    check "$1" "$results/baseline.json"; code=$?
    case "$code" in
      0) [ "$1" = observe ] || [ "${passed:-0}" -ge 1 ] && return 0; passed=1;;  # repairs: two passing polls
      2) passed=0;;
      *) return 1;;
    esac
    [ "$(date +%s)" -ge "$deadline" ] && return 2
    sleep 30
  done
}

kubectl delete agenttask suite-doctor suite-metrics -n "$ns" --ignore-not-found
kubectl delete actionplans,actionapprovals -n "$ns" --all --ignore-not-found >/dev/null
kubectl delete -f "$here/scenarios.yaml" --ignore-not-found --wait=true >/dev/null
kubectl delete -f "$here/experimental.yaml" --ignore-not-found --wait=true >/dev/null
extra=()
[ "${SUITE_EXPERIMENTAL:-}" = 1 ] && extra=(-f "$here/experimental.yaml")
kubectl apply -f "$here/prom-proxy.yaml" -f "$here/scenarios.yaml" ${extra[@]+"${extra[@]}"}
echo "== waiting for the healthy control and the metrics proxy"
for d in suite-web suite-prom-proxy; do kubectl rollout status deploy/$d -n "$ns" --timeout=180s; done
check snapshot > "$results/baseline.json" || { echo "FAIL: baseline snapshot"; exit 1; }
kubectl apply -f "$here/task.yaml" -f "$here/metrics-task.yaml"

echo "== Observe: diagnose every fault, write nothing"
wait_phase observe "$observe_for"; observed=$?
check report | tee "$results/observe.txt"
[ "$observed" -eq 1 ] && { echo "FAIL: Observe violated its contract (results: $results)"; exit 1; }
[ "$observed" -eq 2 ] && echo "WARN: not every fault was diagnosed within ${observe_for} minutes; continuing to measure repairs, the run will fail"

echo "== Automatic: repair every fault"
for task in suite-doctor suite-metrics; do
  kubectl patch agenttask "$task" -n "$ns" --type=merge -p '{"spec":{"mode":"Automatic"}}'
done
wait_phase repair "$repair_for"; repaired=$?
check report | tee "$results/repair.txt"
kubectl get deploy,svc,pvc,actionplans -n "$ns" > "$results/resources.txt"
[ "$observed" -ne 0 ] && { echo "FAIL: Observe did not diagnose every fault (results: $results)"; exit 1; }
case "$repaired" in
  0) echo "PASS: repairable faults fixed as intended, unrepairable ones held untouched with a reason, protected and control untouched (results: $results)";;
  1) echo "FAIL: a repair violated the suite's contract (results: $results)"; exit 1;;
  *) echo "FAIL: faults remain after ${repair_for} minutes (results: $results)"; exit 1;;
esac
