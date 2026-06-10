import Hegemon.Release.DependencyAuditPolicy

open Hegemon.Release.DependencyAuditPolicy

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option DependencyAuditReject -> String
  | none => "null"
  | some DependencyAuditReject.malformedWaiver => "\"malformed_waiver\""
  | some DependencyAuditReject.unwaivedFinding => "\"unwaived_finding\""

def findingJson (finding : DependencyFinding) : String :=
  "        {\n"
    ++ "          \"id\": \"" ++ finding.id ++ "\",\n"
    ++ "          \"package\": \"" ++ finding.package ++ "\",\n"
    ++ "          \"version\": \"" ++ finding.version ++ "\",\n"
    ++ "          \"kind\": \"" ++ finding.kind ++ "\"\n"
    ++ "        }"

def waiverJson (waiver : DependencyWaiver) : String :=
  "        {\n"
    ++ "          \"id\": \"" ++ waiver.id ++ "\",\n"
    ++ "          \"package\": \"" ++ waiver.package ++ "\",\n"
    ++ "          \"version\": \"" ++ waiver.version ++ "\",\n"
    ++ "          \"kind\": \"" ++ waiver.kind ++ "\",\n"
    ++ "          \"not_expired\": " ++ boolJson waiver.notExpired ++ ",\n"
    ++ "          \"has_tracking\": " ++ boolJson waiver.hasTracking ++ ",\n"
    ++ "          \"has_reason\": " ++ boolJson waiver.hasReason ++ "\n"
    ++ "        }"

def joinJsonItems : List String -> String
  | [] => ""
  | [item] => item
  | item :: rest => item ++ ",\n" ++ joinJsonItems rest

def findingsJson (findings : List DependencyFinding) : String :=
  joinJsonItems (findings.map findingJson)

def waiversJson (waivers : List DependencyWaiver) : String :=
  joinJsonItems (waivers.map waiverJson)

def dependencyAuditPolicyCaseJson
    (name : String)
    (input : DependencyAuditInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"findings\": [\n"
    ++ findingsJson input.findings ++ "\n"
    ++ "      ],\n"
    ++ "      \"waivers\": [\n"
    ++ waiversJson input.waivers ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (dependencyAuditAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (dependencyAuditRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"dependency_audit_policy_cases\": [\n"
    ++ dependencyAuditPolicyCaseJson "no-findings-no-waivers-accepts"
      noFindingsNoWaivers ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "exact-waiver-accepts"
      exactWaiverInput ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "unwaived-finding-rejects"
      unwaivedFindingInput ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "expired-waiver-rejects"
      expiredWaiverInput ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "kind-mismatch-rejects"
      kindMismatchInput ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "missing-reason-rejects"
      missingReasonInput ++ ",\n"
    ++ dependencyAuditPolicyCaseJson "invalid-waiver-precedes-unwaived-finding"
      invalidWaiverPrecedenceInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
