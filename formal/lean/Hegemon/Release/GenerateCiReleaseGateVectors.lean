import Hegemon.Release.CiReleaseGate

open Hegemon.Release.CiReleaseGate

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CiReleaseGateReject -> String
  | none => "null"
  | some CiReleaseGateReject.dependencyAuditMissing =>
      "\"dependency_audit_missing\""
  | some CiReleaseGateReject.formalCoreMissing =>
      "\"formal_core_missing\""
  | some CiReleaseGateReject.releaseBuildMissing =>
      "\"release_build_missing\""
  | some CiReleaseGateReject.releaseBuildDependencyMissing =>
      "\"release_build_dependency_missing\""
  | some CiReleaseGateReject.releaseBinaryAuditMissing =>
      "\"release_binary_audit_missing\""

def ciReleaseGateCaseJson
    (name : String)
    (input : CiReleaseGateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"dependency_audit_job\": "
    ++ boolJson input.dependencyAuditJob ++ ",\n"
    ++ "      \"formal_core_job\": "
    ++ boolJson input.formalCoreJob ++ ",\n"
    ++ "      \"release_build_job\": "
    ++ boolJson input.releaseBuildJob ++ ",\n"
    ++ "      \"release_build_needs_security_gates\": "
    ++ boolJson input.releaseBuildNeedsSecurityGates ++ ",\n"
    ++ "      \"release_binary_audit_step\": "
    ++ boolJson input.releaseBinaryAuditStep ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (ciReleaseGateAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
    ++ rejectionJson (ciReleaseGateRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"ci_release_gate_cases\": [\n"
    ++ ciReleaseGateCaseJson "complete-ci-release-gate-accepts"
      completeCiReleaseGate ++ ",\n"
    ++ ciReleaseGateCaseJson "dependency-audit-missing-rejects"
      missingDependencyAuditJob ++ ",\n"
    ++ ciReleaseGateCaseJson "formal-core-missing-rejects"
      missingFormalCoreJob ++ ",\n"
    ++ ciReleaseGateCaseJson "release-build-missing-rejects"
      missingReleaseBuildJob ++ ",\n"
    ++ ciReleaseGateCaseJson "release-build-dependency-missing-rejects"
      missingReleaseBuildDependency ++ ",\n"
    ++ ciReleaseGateCaseJson "release-binary-audit-missing-rejects"
      missingReleaseBinaryAuditStep ++ ",\n"
    ++ ciReleaseGateCaseJson "dependency-audit-precedes-all-missing"
      {
        dependencyAuditJob := false,
        formalCoreJob := false,
        releaseBuildJob := false,
        releaseBuildNeedsSecurityGates := false,
        releaseBinaryAuditStep := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
