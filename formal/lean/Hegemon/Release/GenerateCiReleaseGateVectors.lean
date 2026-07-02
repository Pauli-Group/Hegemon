import Hegemon.Release.CiReleaseGate

open Hegemon.Release.CiReleaseGate

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CiReleaseGateReject -> String
  | none => "null"
  | some CiReleaseGateReject.dependencyAuditMissing =>
      "\"dependency_audit_missing\""
  | some CiReleaseGateReject.dependencyAuditWaiverGateMissing =>
      "\"dependency_audit_waiver_gate_missing\""
  | some CiReleaseGateReject.formalCoreMissing =>
      "\"formal_core_missing\""
  | some CiReleaseGateReject.securityAdversarialMissing =>
      "\"security_adversarial_missing\""
  | some CiReleaseGateReject.nativeBackendSecurityMissing =>
      "\"native_backend_security_missing\""
  | some CiReleaseGateReject.appNoSshE2eMissing =>
      "\"app_no_ssh_e2e_missing\""
  | some CiReleaseGateReject.releaseBuildMissing =>
      "\"release_build_missing\""
  | some CiReleaseGateReject.releaseBuildDependencyMissing =>
      "\"release_build_dependency_missing\""
  | some
      CiReleaseGateReject.releaseBuildSecurityAdversarialDependencyMissing =>
      "\"release_build_security_adversarial_dependency_missing\""
  | some
      CiReleaseGateReject.releaseBuildNativeBackendSecurityDependencyMissing =>
      "\"release_build_native_backend_security_dependency_missing\""
  | some
      CiReleaseGateReject.releaseBuildAppNoSshE2eDependencyMissing =>
      "\"release_build_app_no_ssh_e2e_dependency_missing\""
  | some CiReleaseGateReject.nonReleaseJobContentsWrite =>
      "\"non_release_job_contents_write\""
  | some CiReleaseGateReject.releaseBinaryAuditMissing =>
      "\"release_binary_audit_missing\""
  | some CiReleaseGateReject.tagReleaseNativeBackendReviewMissing =>
      "\"tag_release_native_backend_review_missing\""
  | some CiReleaseGateReject.tagReleaseNativeBackendPostureMissing =>
      "\"tag_release_native_backend_posture_missing\""
  | some CiReleaseGateReject.appUiGuardMissing =>
      "\"app_ui_guard_missing\""
  | some CiReleaseGateReject.branchProtectionRulesetMissing =>
      "\"branch_protection_ruleset_missing\""

def ciReleaseGateCaseJson
    (name : String)
    (input : CiReleaseGateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"dependency_audit_job\": "
    ++ boolJson input.dependencyAuditJob ++ ",\n"
    ++ "      \"dependency_audit_waiver_gate_step\": "
    ++ boolJson input.dependencyAuditWaiverGateStep ++ ",\n"
    ++ "      \"formal_core_job\": "
    ++ boolJson input.formalCoreJob ++ ",\n"
    ++ "      \"security_adversarial_job\": "
    ++ boolJson input.securityAdversarialJob ++ ",\n"
    ++ "      \"native_backend_security_job\": "
    ++ boolJson input.nativeBackendSecurityJob ++ ",\n"
    ++ "      \"app_no_ssh_e2e_job\": "
    ++ boolJson input.appNoSshE2eJob ++ ",\n"
    ++ "      \"release_build_job\": "
    ++ boolJson input.releaseBuildJob ++ ",\n"
    ++ "      \"release_build_needs_security_gates\": "
    ++ boolJson input.releaseBuildNeedsSecurityGates ++ ",\n"
    ++ "      \"release_build_needs_security_adversarial\": "
    ++ boolJson input.releaseBuildNeedsSecurityAdversarial ++ ",\n"
    ++ "      \"release_build_needs_native_backend_security\": "
    ++ boolJson input.releaseBuildNeedsNativeBackendSecurity ++ ",\n"
    ++ "      \"release_build_needs_app_no_ssh_e2e\": "
    ++ boolJson input.releaseBuildNeedsAppNoSshE2e ++ ",\n"
    ++ "      \"non_release_jobs_no_contents_write\": "
    ++ boolJson input.nonReleaseJobsNoContentsWrite ++ ",\n"
    ++ "      \"release_binary_audit_step\": "
    ++ boolJson input.releaseBinaryAuditStep ++ ",\n"
    ++ "      \"tag_release_native_backend_review_step\": "
    ++ boolJson input.tagReleaseNativeBackendReviewStep ++ ",\n"
    ++ "      \"tag_release_native_backend_posture_step\": "
    ++ boolJson input.tagReleaseNativeBackendPostureStep ++ ",\n"
    ++ "      \"app_ui_guard_step\": "
    ++ boolJson input.appUiGuardStep ++ ",\n"
    ++ "      \"branch_protection_ruleset_evidence\": "
    ++ boolJson input.branchProtectionRulesetEvidence ++ ",\n"
    ++ "      \"expected_valid\": "
    ++ boolJson (ciReleaseGateAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
    ++ rejectionJson (ciReleaseGateRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"ci_release_gate_cases\": [\n"
    ++ ciReleaseGateCaseJson "complete-ci-release-gate-accepts"
      completeCiReleaseGate ++ ",\n"
    ++ ciReleaseGateCaseJson "dependency-audit-missing-rejects"
      missingDependencyAuditJob ++ ",\n"
    ++ ciReleaseGateCaseJson
      "dependency-audit-waiver-gate-missing-rejects"
      missingDependencyAuditWaiverGateStep ++ ",\n"
    ++ ciReleaseGateCaseJson "formal-core-missing-rejects"
      missingFormalCoreJob ++ ",\n"
    ++ ciReleaseGateCaseJson "security-adversarial-missing-rejects"
      missingSecurityAdversarialJob ++ ",\n"
    ++ ciReleaseGateCaseJson "native-backend-security-missing-rejects"
      missingNativeBackendSecurityJob ++ ",\n"
    ++ ciReleaseGateCaseJson "app-no-ssh-e2e-missing-rejects"
      missingAppNoSshE2eJob ++ ",\n"
    ++ ciReleaseGateCaseJson "release-build-missing-rejects"
      missingReleaseBuildJob ++ ",\n"
    ++ ciReleaseGateCaseJson "release-build-dependency-missing-rejects"
      missingReleaseBuildDependency ++ ",\n"
    ++ ciReleaseGateCaseJson
      "release-build-security-adversarial-dependency-missing-rejects"
      missingReleaseBuildSecurityAdversarialDependency ++ ",\n"
    ++ ciReleaseGateCaseJson
      "release-build-native-backend-security-dependency-missing-rejects"
      missingReleaseBuildNativeBackendSecurityDependency ++ ",\n"
    ++ ciReleaseGateCaseJson
      "release-build-app-no-ssh-e2e-dependency-missing-rejects"
      missingReleaseBuildAppNoSshE2eDependency ++ ",\n"
    ++ ciReleaseGateCaseJson
      "non-release-job-contents-write-rejects"
      nonReleaseJobContentsWrite ++ ",\n"
    ++ ciReleaseGateCaseJson "release-binary-audit-missing-rejects"
      missingReleaseBinaryAuditStep ++ ",\n"
    ++ ciReleaseGateCaseJson
      "tag-release-native-backend-review-missing-rejects"
      missingTagReleaseNativeBackendReviewStep ++ ",\n"
    ++ ciReleaseGateCaseJson
      "tag-release-native-backend-posture-missing-rejects"
      missingTagReleaseNativeBackendPostureStep ++ ",\n"
    ++ ciReleaseGateCaseJson
      "app-ui-guard-missing-rejects"
      missingAppUiGuardStep ++ ",\n"
    ++ ciReleaseGateCaseJson
      "branch-protection-ruleset-missing-rejects"
      missingBranchProtectionRulesetEvidence ++ ",\n"
    ++ ciReleaseGateCaseJson "dependency-audit-precedes-all-missing"
      {
        dependencyAuditJob := false,
        dependencyAuditWaiverGateStep := false,
        formalCoreJob := false,
        securityAdversarialJob := false,
        nativeBackendSecurityJob := false,
        appNoSshE2eJob := false,
        releaseBuildJob := false,
        releaseBuildNeedsSecurityGates := false,
        releaseBuildNeedsSecurityAdversarial := false,
        releaseBuildNeedsNativeBackendSecurity := false,
        releaseBuildNeedsAppNoSshE2e := false,
        nonReleaseJobsNoContentsWrite := false,
        releaseBinaryAuditStep := false,
        tagReleaseNativeBackendReviewStep := false,
        tagReleaseNativeBackendPostureStep := false,
        appUiGuardStep := false,
        branchProtectionRulesetEvidence := false
      } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
