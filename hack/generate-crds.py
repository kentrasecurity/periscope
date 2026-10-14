#!/usr/bin/env python3
"""Generate structural CRDs as JSON (also valid YAML); no third-party Python dependency."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "charts/periscope/crds"
ROOT.mkdir(parents=True, exist_ok=True)

def string(maximum=1024, **extra):
    return dict(type="string", maxLength=maximum, **extra)

def obj(properties, required=(), **extra):
    return dict(type="object", properties=properties, required=list(required), **extra)

def array(items, maximum=32):
    return dict(type="array", items=items, maxItems=maximum)

def integer(minimum, maximum, **extra):
    return dict(type="integer", minimum=minimum, maximum=maximum, **extra)

arbitrary = {"x-kubernetes-preserve-unknown-fields": True}
ref = obj({"name": string(253), "uid": string(128)}, ("name", "uid"))
target = obj({"apiVersion": string(128), "kind": string(128), "name": string(253),
              "namespace": string(63), "uid": string(128)}, ("apiVersion", "kind", "name"))
timestamp = string(64, format="date-time")
condition = obj({"type": string(128), "status": string(8, enum=["True", "False", "Unknown"]),
                 "reason": string(128), "message": string(4096), "observedGeneration": integer(0, 2**53),
                 "lastTransitionTime": timestamp}, ("type", "status", "reason", "message", "lastTransitionTime"))
evidence = obj({"id": string(128), "source": string(1024), "collectedAt": timestamp,
                "hash": string(128), "content": string(8192)}, ("id", "source", "collectedAt", "hash", "content"))
limits = obj({"deadlineSeconds": integer(1, 3600, default=600),
              "maxModelCalls": integer(1, 20, default=5), "maxToolCalls": integer(1, 100, default=30)},
             default={"deadlineSeconds": 600, "maxModelCalls": 5, "maxToolCalls": 30})
verification = obj({"type": string(64), "timeoutSeconds": integer(1, 1800), "stableWindowSeconds": integer(1, 600),
                    "path": string(1024), "expected": arbitrary, "healthURL": string(2048)},
                   ("type", "timeoutSeconds", "stableWindowSeconds"))

check = obj({"id":string(128),"type":string(64),"target":target,"path":string(1024),"expected":arbitrary,"source":string(128),"query":string(8192),"endpoint":string(2048),"vantage":string(128),"timeoutSeconds":integer(1,1800),"stableWindowSeconds":integer(1,600)},("id","type","target"))
check_result = obj({"checkID":string(128),"healthy":{"type":"boolean"},"fingerprint":string(128),"observation":string(4096),"observedAt":timestamp,"source":string(1024)},("checkID","healthy","observation","observedAt","source"))
incident = obj({"id":string(128),"target":target,"attempt":integer(1,1000),"originalChecks":array(check),"originalChecksDigest":string(128),"failureFingerprint":string(128),"nextAttemptAt":timestamp,"priorPlanRefs":array(ref),"diagnosis":string(2048),"outcome":string(32)},("id","target","attempt","originalChecks","originalChecksDigest"))
scope = obj({"namespaces":array(string(63,minLength=1),16),"resources":array(obj({"apiVersion":string(128),"kind":string(128),"name":string(253),"labelSelector":string(1024)}),32)},("namespaces",))
healing_limits=obj({"maxAttemptsPerIncident":integer(1,10),"retryCooldownSeconds":integer(5,3600),"windowSeconds":integer(60,86400),"maxModelCallsPerWindow":integer(1,1000),"maxToolCallsPerWindow":integer(1,10000)},("maxAttemptsPerIncident","retryCooldownSeconds","windowSeconds","maxModelCallsPerWindow","maxToolCallsPerWindow"))
budget=obj({"windowStartedAt":timestamp,"modelCalls":integer(0,100),"toolCalls":integer(0,1000)},("windowStartedAt","modelCalls","toolCalls"))
task_spec = obj({"healingLimits":healing_limits,"scope":scope,"checks":array(check),"monitoring":obj({"intervalSeconds":integer(5,3600),"gracePeriodSeconds":integer(0,3600)},("intervalSeconds",)),"targetRef": target, "mode": string(32, enum=["Observe", "Propose", "HumanApproved", "Automatic"]),
                 "suspend": {"type":"boolean", "default":False}, "verification": verification,
                 "objective": string(8192, minLength=1), "policyRef": string(253), "limits": limits},
                ("mode", "objective"), **{"x-kubernetes-validations":[{"rule":"has(self.targetRef) != has(self.scope)","message":"choose targetRef or scope"}]})
task_status = obj({"scopeScanCursor":integer(0,65536),"lastScopeScanAt":timestamp,"budget":budget,"suspects":array(obj({"target":target,"since":timestamp},("target","since")),100),"incident":incident,"pendingIncidents":array(incident,100),"incidentHistory":array(incident,64),"observedGeneration": integer(0, 2**53), "phase": string(32), "targetUID": string(128),
                   "approvalRef":ref, "cycle": integer(0,2**53), "lastCheckedAt":timestamp, "healthy":{"type":"boolean"}, "monitorDigest":string(128), "monitorUID":string(128), "monitorStableSince":timestamp, "monitorFingerprint":string(128), "monitorVerification":verification,
                   "attempt": integer(0, 1000), "modelCalls": integer(0, 1000), "toolCalls": integer(0, 1000),
                   "planRef": ref, "report": string(16384), "evidence": array(evidence), "gaps": array(string(1024)),
                   "conditions": array(condition), "startedAt": timestamp, "completedAt": timestamp})
patch = obj({"op": string(16, enum=["add", "replace", "remove", "test"]), "path": string(1024), "value": arbitrary}, ("op", "path"))
action = obj({"bindingID":string(128),"id": string(128), "type": string(32, enum=["RestartWorkload", "PatchResource", "CreateResource", "DeleteResource"]),
              "target": target, "patch": array(patch, 32), "object": dict(type="object", **{"x-kubernetes-preserve-unknown-fields": True}),
              "secretSources": dict(type="object", maxProperties=32, additionalProperties=obj({"generate": integer(16, 64), "fromSecret": string(253), "fromKey": string(253)}, ()))},
             ("id", "type"))
verification = obj({"type": string(64), "timeoutSeconds": integer(1, 1800), "stableWindowSeconds": integer(1, 600),
                    "path": string(1024), "expected": arbitrary, "healthURL": string(2048)},
                   ("type", "timeoutSeconds", "stableWindowSeconds"))
binding = obj({"id":string(128),"target":target,"preconditions":obj({"specDigest":string(128)},("specDigest",)),"afterActionID":string(128)},("id","target","preconditions"))
plan_spec = obj({"checks":array(check,32),"targets":array(binding,20),"incidentID":string(128),"originalChecksDigest":string(128),"taskCycle":integer(0,2**53),"taskRef": ref, "taskGeneration": integer(1, 2**53), "targetRef": target,
                 "preconditions": obj({"specDigest": string(128)}, ("specDigest",)), "policyDigest": string(128),
                 "diagnosis": string(16384), "risk": string(32), "actions": array(action, 10), "verification": verification,
                 "evidence": array(evidence), "digest": string(128, pattern="^sha256:[a-f0-9]{64}$")},
                ("taskRef", "taskGeneration", "targetRef", "preconditions", "policyDigest", "diagnosis", "risk", "actions", "verification", "digest"))
# Admission independently enforces full plan immutability, including arbitrary JSON values.
plan_spec["x-kubernetes-validations"] = [{"rule": "self.digest == oldSelf.digest", "message": "plan digest is immutable"}]
entry = obj({"id": string(128), "state": string(32), "operation": string(128), "beforeDigest": string(128),
             "afterDigest": string(128), "resultUID": string(128), "serverResultDigest": string(128), "updatedAt": timestamp, "error": string(4096)},
            ("id", "state", "operation", "beforeDigest", "updatedAt"))
plan_status = obj({"checkResults":array(check_result),"phase": string(32), "approvalUID": string(128), "entries": array(entry, 10), "conditions": array(condition),
                   "stableSince": timestamp, "verificationFingerprint": string(128), "executionStartedAt": timestamp})
approval_spec = obj({"planName":string(253),"decision":string(16,enum=["Pending","Approve","Reject"]),"taskUID": string(128), "planUID": string(128), "planDigest": string(128, pattern="^sha256:[a-f0-9]{64}$"),
                     "expiresAt": timestamp}, ("taskUID", "planUID", "planDigest", "expiresAt"))
approval_spec["x-kubernetes-validations"] = [
 {"rule":"self.taskUID == oldSelf.taskUID && self.planUID == oldSelf.planUID && self.planDigest == oldSelf.planDigest && self.expiresAt == oldSelf.expiresAt","message":"approval bindings and expiry are immutable"},
 {"rule":"(!has(oldSelf.decision) && !has(self.decision)) || (has(oldSelf.decision) && has(self.decision) && (self.decision == oldSelf.decision || (oldSelf.decision == 'Pending' && self.decision in ['Approve','Reject'])))","message":"decision allows only Pending to Approve or Reject"}]


def columns(kind):
    age = {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"}
    if kind == "AgentTask":
        return [{"name": "Mode", "type": "string", "jsonPath": ".spec.mode"},
                {"name": "Phase", "type": "string", "jsonPath": ".status.phase"},
                {"name": "Healthy", "type": "boolean", "jsonPath": ".status.healthy"},
                {"name": "Last-Check", "type": "date", "jsonPath": ".status.lastCheckedAt"},
                {"name": "Report", "type": "string", "jsonPath": ".status.report", "priority": 1}, age]
    if kind == "ActionApproval":
        return [{"name": "Decision", "type": "string", "jsonPath": ".spec.decision"},
                {"name": "Plan", "type": "string", "jsonPath": ".spec.planName"}, age]
    return [{"name": "Phase", "type": "string", "jsonPath": ".status.phase"},
            {"name": "Task", "type": "string", "jsonPath": ".spec.taskRef.name"}, age]

for kind, plural, spec, status in [
    ("AgentTask", "agenttasks", task_spec, task_status),
    ("ActionPlan", "actionplans", plan_spec, plan_status),
    ("ActionApproval", "actionapprovals", approval_spec, obj({"conditions": array(condition)})),
]:
    resource = {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": plural + ".periscope.kentrasecurity.io"}, "spec": {
                    "group": "periscope.kentrasecurity.io", "scope": "Namespaced",
                    "names": {"kind": kind, "plural": plural, "singular": plural[:-1]},
                    "versions": [{"name": "v1alpha1", "served": True, "storage": True,
                                  "subresources": {"status": {}}, "additionalPrinterColumns": columns(kind),
                                  "schema": {"openAPIV3Schema": obj({"apiVersion": string(), "kind": string(),
                                                                     "metadata": {"type": "object"}, "spec": spec, "status": status}, ("spec",))}}]}}
    (ROOT / (plural + ".yaml")).write_text(json.dumps(resource, indent=2) + "\n")
