namespace Hegemon
namespace Release
namespace CiReleaseGate

inductive CiReleaseGateReject where
  | dependencyAuditMissing
  | formalCoreMissing
  | securityAdversarialMissing
  | nativeBackendSecurityMissing
  | releaseBuildMissing
  | releaseBuildDependencyMissing
  | releaseBuildSecurityAdversarialDependencyMissing
  | releaseBuildNativeBackendSecurityDependencyMissing
  | releaseBinaryAuditMissing
  | tagReleaseNativeBackendReviewMissing
  | tagReleaseNativeBackendPostureMissing
deriving DecidableEq, Repr

structure CiReleaseGateInput where
  dependencyAuditJob : Bool
  formalCoreJob : Bool
  securityAdversarialJob : Bool
  nativeBackendSecurityJob : Bool
  releaseBuildJob : Bool
  releaseBuildNeedsSecurityGates : Bool
  releaseBuildNeedsSecurityAdversarial : Bool
  releaseBuildNeedsNativeBackendSecurity : Bool
  releaseBinaryAuditStep : Bool
  tagReleaseNativeBackendReviewStep : Bool
  tagReleaseNativeBackendPostureStep : Bool
deriving DecidableEq, Repr

def evaluateCiReleaseGate
    (input : CiReleaseGateInput) : Except CiReleaseGateReject Unit :=
  if input.dependencyAuditJob = false then
    Except.error CiReleaseGateReject.dependencyAuditMissing
  else if input.formalCoreJob = false then
    Except.error CiReleaseGateReject.formalCoreMissing
  else if input.securityAdversarialJob = false then
    Except.error CiReleaseGateReject.securityAdversarialMissing
  else if input.nativeBackendSecurityJob = false then
    Except.error CiReleaseGateReject.nativeBackendSecurityMissing
  else if input.releaseBuildJob = false then
    Except.error CiReleaseGateReject.releaseBuildMissing
  else if input.releaseBuildNeedsSecurityGates = false then
    Except.error CiReleaseGateReject.releaseBuildDependencyMissing
  else if input.releaseBuildNeedsSecurityAdversarial = false then
    Except.error
      CiReleaseGateReject.releaseBuildSecurityAdversarialDependencyMissing
  else if input.releaseBuildNeedsNativeBackendSecurity = false then
    Except.error
      CiReleaseGateReject.releaseBuildNativeBackendSecurityDependencyMissing
  else if input.releaseBinaryAuditStep = false then
    Except.error CiReleaseGateReject.releaseBinaryAuditMissing
  else if input.tagReleaseNativeBackendReviewStep = false then
    Except.error CiReleaseGateReject.tagReleaseNativeBackendReviewMissing
  else if input.tagReleaseNativeBackendPostureStep = false then
    Except.error CiReleaseGateReject.tagReleaseNativeBackendPostureMissing
  else
    Except.ok ()

def ciReleaseGateAccepts (input : CiReleaseGateInput) : Bool :=
  match evaluateCiReleaseGate input with
  | Except.ok _ => true
  | Except.error _ => false

def ciReleaseGateRejection
    (input : CiReleaseGateInput) : Option CiReleaseGateReject :=
  match evaluateCiReleaseGate input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def ciReleaseGatePreconditions (input : CiReleaseGateInput) : Bool :=
  input.dependencyAuditJob &&
    input.formalCoreJob &&
    input.securityAdversarialJob &&
    input.nativeBackendSecurityJob &&
    input.releaseBuildJob &&
    input.releaseBuildNeedsSecurityGates &&
    input.releaseBuildNeedsSecurityAdversarial &&
    input.releaseBuildNeedsNativeBackendSecurity &&
    input.releaseBinaryAuditStep &&
    input.tagReleaseNativeBackendReviewStep &&
    input.tagReleaseNativeBackendPostureStep

theorem accepts_iff_ci_release_gate_preconditions
    (input : CiReleaseGateInput) :
    ciReleaseGateAccepts input = ciReleaseGatePreconditions input := by
  cases input with
  | mk dependencyAuditJob formalCoreJob securityAdversarialJob
      nativeBackendSecurityJob releaseBuildJob releaseBuildNeedsSecurityGates
      releaseBuildNeedsSecurityAdversarial
      releaseBuildNeedsNativeBackendSecurity releaseBinaryAuditStep
      tagReleaseNativeBackendReviewStep tagReleaseNativeBackendPostureStep =>
      unfold ciReleaseGateAccepts ciReleaseGatePreconditions
        evaluateCiReleaseGate
      cases dependencyAuditJob <;>
        cases formalCoreJob <;>
        cases securityAdversarialJob <;>
        cases nativeBackendSecurityJob <;>
        cases releaseBuildJob <;>
        cases releaseBuildNeedsSecurityGates <;>
        cases releaseBuildNeedsSecurityAdversarial <;>
        cases releaseBuildNeedsNativeBackendSecurity <;>
        cases releaseBinaryAuditStep <;>
        cases tagReleaseNativeBackendReviewStep <;>
        cases tagReleaseNativeBackendPostureStep <;>
        rfl

def completeCiReleaseGate : CiReleaseGateInput :=
  {
    dependencyAuditJob := true,
    formalCoreJob := true,
    securityAdversarialJob := true,
    nativeBackendSecurityJob := true,
    releaseBuildJob := true,
    releaseBuildNeedsSecurityGates := true,
    releaseBuildNeedsSecurityAdversarial := true,
    releaseBuildNeedsNativeBackendSecurity := true,
    releaseBinaryAuditStep := true,
    tagReleaseNativeBackendReviewStep := true,
    tagReleaseNativeBackendPostureStep := true
  }

def missingDependencyAuditJob : CiReleaseGateInput :=
  { completeCiReleaseGate with dependencyAuditJob := false }

def missingFormalCoreJob : CiReleaseGateInput :=
  { completeCiReleaseGate with formalCoreJob := false }

def missingSecurityAdversarialJob : CiReleaseGateInput :=
  { completeCiReleaseGate with securityAdversarialJob := false }

def missingNativeBackendSecurityJob : CiReleaseGateInput :=
  { completeCiReleaseGate with nativeBackendSecurityJob := false }

def missingReleaseBuildJob : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildJob := false }

def missingReleaseBuildDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsSecurityGates := false }

def missingReleaseBuildSecurityAdversarialDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsSecurityAdversarial := false }

def missingReleaseBuildNativeBackendSecurityDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsNativeBackendSecurity := false }

def missingReleaseBinaryAuditStep : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBinaryAuditStep := false }

def missingTagReleaseNativeBackendReviewStep : CiReleaseGateInput :=
  { completeCiReleaseGate with tagReleaseNativeBackendReviewStep := false }

def missingTagReleaseNativeBackendPostureStep : CiReleaseGateInput :=
  { completeCiReleaseGate with tagReleaseNativeBackendPostureStep := false }

theorem complete_ci_release_gate_accepts :
    evaluateCiReleaseGate completeCiReleaseGate = Except.ok () := by
  rfl

theorem dependency_audit_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.dependencyAuditMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency]

theorem formal_core_missing_rejects_after_dependency_audit
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.formalCoreMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore]

theorem release_build_missing_rejects_after_security_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild
  ]

theorem release_build_dependency_missing_rejects_after_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildDependencyMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity
  ]

theorem release_binary_audit_missing_rejects_after_security_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (binaryAudit : input.releaseBinaryAuditStep = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBinaryAuditMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    binaryAudit
  ]

theorem security_adversarial_missing_rejects_after_formal_core
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.securityAdversarialMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore, securityAdversarial]

theorem native_backend_security_missing_rejects_after_adversarial
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.nativeBackendSecurityMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore, securityAdversarial, nativeBackendSecurity]

theorem release_build_security_adversarial_dependency_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.releaseBuildSecurityAdversarialDependencyMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity,
    needsAdversarial
  ]

theorem release_build_native_backend_security_dependency_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.releaseBuildNativeBackendSecurityDependencyMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend
  ]

theorem tag_release_native_backend_review_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.tagReleaseNativeBackendReviewMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    binaryAudit,
    review
  ]

theorem tag_release_native_backend_posture_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = true)
    (posture : input.tagReleaseNativeBackendPostureStep = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.tagReleaseNativeBackendPostureMissing := by
  unfold evaluateCiReleaseGate
  simp [
    dependency,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    binaryAudit,
    review,
    posture
  ]

theorem dependency_audit_precedes_all_missing :
    evaluateCiReleaseGate {
      dependencyAuditJob := false,
      formalCoreJob := false,
      securityAdversarialJob := false,
      nativeBackendSecurityJob := false,
      releaseBuildJob := false,
      releaseBuildNeedsSecurityGates := false,
      releaseBuildNeedsSecurityAdversarial := false,
      releaseBuildNeedsNativeBackendSecurity := false,
      releaseBinaryAuditStep := false,
      tagReleaseNativeBackendReviewStep := false,
      tagReleaseNativeBackendPostureStep := false
    } = Except.error CiReleaseGateReject.dependencyAuditMissing := by
  rfl

end CiReleaseGate
end Release
end Hegemon
