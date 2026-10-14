#!/usr/bin/env bash
# Explicitly authorized development helper. The temporary root Pods have
# node-runtime authority through a socket; never grant this to the operator.
set -euo pipefail
archive=${1:?usage: import-local-images.sh archive.tar}
namespace=agent-operator-test
utility='docker.io/rancher/shell@sha256:76f84dda75007bb9f93c64ac4dcdc592aa35443744585da68f0e7d36162b5e05'
for node in k3s-master-1 k3s-master-2 k3s-master-3; do
  pod="periscope-image-import-${node}"
  manifest=$(mktemp)
  python3 - "$namespace" "$node" "$pod" "$utility" > "$manifest" <<'PY'
import json,sys
ns,node,name,image=sys.argv[1:]
print(json.dumps({'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':ns},'spec':{
 'nodeName':node,'automountServiceAccountToken':False,'restartPolicy':'Never','activeDeadlineSeconds':600,'terminationGracePeriodSeconds':1,
 'containers':[{'name':'import','image':image,'imagePullPolicy':'Never','command':['/bin/sh','-c','sleep 600'],
  'securityContext':{'runAsUser':0,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
  'resources':{'requests':{'cpu':'10m','memory':'32Mi'},'limits':{'cpu':'500m','memory':'256Mi'}},
  'volumeMounts':[{'name':'runtime','mountPath':'/runtime'},{'name':'tools','mountPath':'/host-bin','readOnly':True}]}],
 'volumes':[{'name':'runtime','hostPath':{'path':'/run/k3s/containerd','type':'Directory'}},
 {'name':'tools','hostPath':{'path':'/var/lib/rancher/k3s/data/current/bin','type':'Directory'}}]}}))
PY
  trap 'kubectl delete pod "$pod" -n "$namespace" --ignore-not-found --wait=false; rm -f "$manifest"' EXIT
  kubectl create -f "$manifest"
  kubectl wait pod/"$pod" -n "$namespace" --for=condition=Ready --timeout=90s
  kubectl exec -i -n "$namespace" "$pod" -- /host-bin/ctr --address /runtime/containerd.sock --namespace k8s.io images import - < "$archive"
  kubectl delete pod "$pod" -n "$namespace" --wait=true --timeout=45s
  rm -f "$manifest"
  trap - EXIT
done
