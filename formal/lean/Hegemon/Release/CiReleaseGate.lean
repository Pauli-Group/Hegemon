set_option maxHeartbeats 2500000

namespace Hegemon
namespace Release
namespace CiReleaseGate

inductive CiReleaseGateReject where
  | dependencyAuditMissing
  | dependencyAuditWaiverGateMissing
  | formalCoreMissing
  | securityAdversarialMissing
  | nativeBackendSecurityMissing
  | appNoSshE2eMissing
  | releaseBuildMissing
  | releaseBuildDependencyMissing
  | releaseBuildSecurityAdversarialDependencyMissing
  | releaseBuildNativeBackendSecurityDependencyMissing
  | releaseBuildAppNoSshE2eDependencyMissing
  | nonReleaseJobContentsWrite
  | releaseBinaryAuditMissing
  | tagReleaseNativeBackendReviewMissing
  | tagReleaseNativeBackendPostureMissing
  | appUiGuardMissing
  | branchProtectionRulesetMissing
deriving DecidableEq, Repr

structure CiReleaseGateInput where
  dependencyAuditJob : Bool
  dependencyAuditWaiverGateStep : Bool
  formalCoreJob : Bool
  securityAdversarialJob : Bool
  nativeBackendSecurityJob : Bool
  appNoSshE2eJob : Bool
  releaseBuildJob : Bool
  releaseBuildNeedsSecurityGates : Bool
  releaseBuildNeedsSecurityAdversarial : Bool
  releaseBuildNeedsNativeBackendSecurity : Bool
  releaseBuildNeedsAppNoSshE2e : Bool
  nonReleaseJobsNoContentsWrite : Bool
  releaseBinaryAuditStep : Bool
  tagReleaseNativeBackendReviewStep : Bool
  tagReleaseNativeBackendPostureStep : Bool
  appUiGuardStep : Bool
  branchProtectionRulesetEvidence : Bool
deriving DecidableEq, Repr

def ciReleaseGatePreconditions (input : CiReleaseGateInput) : Bool :=
  input.dependencyAuditJob &&
    input.dependencyAuditWaiverGateStep &&
    input.formalCoreJob &&
    input.securityAdversarialJob &&
    input.nativeBackendSecurityJob &&
    input.appNoSshE2eJob &&
    input.releaseBuildJob &&
    input.releaseBuildNeedsSecurityGates &&
    input.releaseBuildNeedsSecurityAdversarial &&
    input.releaseBuildNeedsNativeBackendSecurity &&
    input.releaseBuildNeedsAppNoSshE2e &&
    input.nonReleaseJobsNoContentsWrite &&
    input.releaseBinaryAuditStep &&
    input.tagReleaseNativeBackendReviewStep &&
    input.tagReleaseNativeBackendPostureStep &&
    input.appUiGuardStep &&
    input.branchProtectionRulesetEvidence

def firstCiReleaseGateRejection
    (input : CiReleaseGateInput) : CiReleaseGateReject :=
  if input.dependencyAuditJob = false then
    CiReleaseGateReject.dependencyAuditMissing
  else if input.dependencyAuditWaiverGateStep = false then
    CiReleaseGateReject.dependencyAuditWaiverGateMissing
  else if input.formalCoreJob = false then
    CiReleaseGateReject.formalCoreMissing
  else if input.securityAdversarialJob = false then
    CiReleaseGateReject.securityAdversarialMissing
  else if input.nativeBackendSecurityJob = false then
    CiReleaseGateReject.nativeBackendSecurityMissing
  else if input.appNoSshE2eJob = false then
    CiReleaseGateReject.appNoSshE2eMissing
  else if input.releaseBuildJob = false then
    CiReleaseGateReject.releaseBuildMissing
  else if input.releaseBuildNeedsSecurityGates = false then
    CiReleaseGateReject.releaseBuildDependencyMissing
  else if input.releaseBuildNeedsSecurityAdversarial = false then
    CiReleaseGateReject.releaseBuildSecurityAdversarialDependencyMissing
  else if input.releaseBuildNeedsNativeBackendSecurity = false then
    CiReleaseGateReject.releaseBuildNativeBackendSecurityDependencyMissing
  else if input.releaseBuildNeedsAppNoSshE2e = false then
    CiReleaseGateReject.releaseBuildAppNoSshE2eDependencyMissing
  else if input.nonReleaseJobsNoContentsWrite = false then
    CiReleaseGateReject.nonReleaseJobContentsWrite
  else if input.releaseBinaryAuditStep = false then
    CiReleaseGateReject.releaseBinaryAuditMissing
  else if input.tagReleaseNativeBackendReviewStep = false then
    CiReleaseGateReject.tagReleaseNativeBackendReviewMissing
  else if input.tagReleaseNativeBackendPostureStep = false then
    CiReleaseGateReject.tagReleaseNativeBackendPostureMissing
  else if input.appUiGuardStep = false then
    CiReleaseGateReject.appUiGuardMissing
  else
    CiReleaseGateReject.branchProtectionRulesetMissing

def evaluateCiReleaseGate
    (input : CiReleaseGateInput) : Except CiReleaseGateReject Unit :=
  if ciReleaseGatePreconditions input then
    Except.ok ()
  else
    Except.error (firstCiReleaseGateRejection input)

def ciReleaseGateAccepts (input : CiReleaseGateInput) : Bool :=
  ciReleaseGatePreconditions input

def ciReleaseGateRejection
    (input : CiReleaseGateInput) : Option CiReleaseGateReject :=
  match evaluateCiReleaseGate input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

theorem accepts_iff_ci_release_gate_preconditions
    (input : CiReleaseGateInput) :
    ciReleaseGateAccepts input = ciReleaseGatePreconditions input := by
  rfl

theorem accepted_ci_release_gate_exposes_required_policy_facts
    {input : CiReleaseGateInput}
    (accepted : evaluateCiReleaseGate input = Except.ok ()) :
    input.dependencyAuditJob = true
      ∧ input.dependencyAuditWaiverGateStep = true
      ∧ input.formalCoreJob = true
      ∧ input.securityAdversarialJob = true
      ∧ input.nativeBackendSecurityJob = true
      ∧ input.appNoSshE2eJob = true
      ∧ input.releaseBuildJob = true
      ∧ input.releaseBuildNeedsSecurityGates = true
      ∧ input.releaseBuildNeedsSecurityAdversarial = true
      ∧ input.releaseBuildNeedsNativeBackendSecurity = true
      ∧ input.releaseBuildNeedsAppNoSshE2e = true
      ∧ input.nonReleaseJobsNoContentsWrite = true
      ∧ input.releaseBinaryAuditStep = true
      ∧ input.tagReleaseNativeBackendReviewStep = true
      ∧ input.tagReleaseNativeBackendPostureStep = true
      ∧ input.appUiGuardStep = true
      ∧ input.branchProtectionRulesetEvidence = true := by
  unfold evaluateCiReleaseGate at accepted
  by_cases preconditions : ciReleaseGatePreconditions input = true
  · simpa [ciReleaseGatePreconditions, and_assoc] using preconditions
  · simp [preconditions] at accepted

theorem accepted_ci_release_gate_depends_on_dependency_audit_policy
    {input : CiReleaseGateInput}
    (accepted : evaluateCiReleaseGate input = Except.ok ()) :
    input.dependencyAuditJob = true
      ∧ input.dependencyAuditWaiverGateStep = true
      ∧ input.releaseBuildJob = true
      ∧ input.releaseBuildNeedsSecurityGates = true := by
  have facts :=
    accepted_ci_release_gate_exposes_required_policy_facts accepted
  rcases facts with
    ⟨dependency, dependencyWaiverGate, _formalCore, _securityAdversarial,
      _nativeBackendSecurity, _appNoSshE2e, releaseBuild, needsSecurity,
      _needsAdversarial, _needsNativeBackend, _needsAppNoSshE2e,
      _nonReleaseWrite, _binaryAudit, _review, _posture, _appUiGuard,
      _ruleset⟩
  exact ⟨dependency, dependencyWaiverGate, releaseBuild, needsSecurity⟩

theorem accepted_ci_release_gate_binds_dependency_audit_to_release_build
    {input : CiReleaseGateInput}
    (accepted : evaluateCiReleaseGate input = Except.ok ()) :
    input.dependencyAuditJob
      && input.dependencyAuditWaiverGateStep
      && input.releaseBuildJob
      && input.releaseBuildNeedsSecurityGates = true := by
  have facts :=
    accepted_ci_release_gate_depends_on_dependency_audit_policy accepted
  simp [
    facts.left,
    facts.right.left,
    facts.right.right.left,
    facts.right.right.right
  ]

def completeCiReleaseGate : CiReleaseGateInput :=
  {
    dependencyAuditJob := true,
    dependencyAuditWaiverGateStep := true,
    formalCoreJob := true,
    securityAdversarialJob := true,
    nativeBackendSecurityJob := true,
    appNoSshE2eJob := true,
    releaseBuildJob := true,
    releaseBuildNeedsSecurityGates := true,
    releaseBuildNeedsSecurityAdversarial := true,
    releaseBuildNeedsNativeBackendSecurity := true,
    releaseBuildNeedsAppNoSshE2e := true,
    nonReleaseJobsNoContentsWrite := true,
    releaseBinaryAuditStep := true,
    tagReleaseNativeBackendReviewStep := true,
    tagReleaseNativeBackendPostureStep := true,
    appUiGuardStep := true,
    branchProtectionRulesetEvidence := true
  }

def missingDependencyAuditJob : CiReleaseGateInput :=
  { completeCiReleaseGate with dependencyAuditJob := false }

def missingDependencyAuditWaiverGateStep : CiReleaseGateInput :=
  { completeCiReleaseGate with dependencyAuditWaiverGateStep := false }

def missingFormalCoreJob : CiReleaseGateInput :=
  { completeCiReleaseGate with formalCoreJob := false }

def missingSecurityAdversarialJob : CiReleaseGateInput :=
  { completeCiReleaseGate with securityAdversarialJob := false }

def missingNativeBackendSecurityJob : CiReleaseGateInput :=
  { completeCiReleaseGate with nativeBackendSecurityJob := false }

def missingAppNoSshE2eJob : CiReleaseGateInput :=
  { completeCiReleaseGate with appNoSshE2eJob := false }

def missingReleaseBuildJob : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildJob := false }

def missingReleaseBuildDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsSecurityGates := false }

def missingReleaseBuildSecurityAdversarialDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsSecurityAdversarial := false }

def missingReleaseBuildNativeBackendSecurityDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsNativeBackendSecurity := false }

def missingReleaseBuildAppNoSshE2eDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsAppNoSshE2e := false }

def nonReleaseJobContentsWrite : CiReleaseGateInput :=
  { completeCiReleaseGate with nonReleaseJobsNoContentsWrite := false }

def missingReleaseBinaryAuditStep : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBinaryAuditStep := false }

def missingTagReleaseNativeBackendReviewStep : CiReleaseGateInput :=
  { completeCiReleaseGate with tagReleaseNativeBackendReviewStep := false }

def missingTagReleaseNativeBackendPostureStep : CiReleaseGateInput :=
  { completeCiReleaseGate with tagReleaseNativeBackendPostureStep := false }

def missingAppUiGuardStep : CiReleaseGateInput :=
  { completeCiReleaseGate with appUiGuardStep := false }

def missingBranchProtectionRulesetEvidence : CiReleaseGateInput :=
  { completeCiReleaseGate with branchProtectionRulesetEvidence := false }

theorem complete_ci_release_gate_accepts :
    evaluateCiReleaseGate completeCiReleaseGate = Except.ok () := by
  rfl

theorem dependency_audit_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.dependencyAuditMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions, dependency]

theorem formal_core_missing_rejects_after_dependency_audit
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.formalCoreMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions, dependency, dependencyWaiverGate, formalCore]

theorem dependency_audit_waiver_gate_missing_rejects_after_job
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.dependencyAuditWaiverGateMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions, dependency, dependencyWaiverGate]

theorem release_build_missing_rejects_after_security_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild
  ]

theorem release_build_dependency_missing_rejects_after_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildDependencyMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity
  ]

theorem release_binary_audit_missing_rejects_after_security_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = true)
    (binaryAudit : input.releaseBinaryAuditStep = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBinaryAuditMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite,
    binaryAudit
  ]

theorem security_adversarial_missing_rejects_after_formal_core
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.securityAdversarialMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions, dependency, dependencyWaiverGate, formalCore, securityAdversarial]

theorem native_backend_security_missing_rejects_after_adversarial
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.nativeBackendSecurityMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity
  ]

theorem app_no_ssh_e2e_missing_rejects_after_native_backend_security
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.appNoSshE2eMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e
  ]

theorem release_build_security_adversarial_dependency_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.releaseBuildSecurityAdversarialDependencyMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial
  ]

theorem release_build_native_backend_security_dependency_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.releaseBuildNativeBackendSecurityDependencyMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend
  ]

theorem release_build_app_no_ssh_e2e_dependency_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.releaseBuildAppNoSshE2eDependencyMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e
  ]

theorem non_release_job_contents_write_rejects_before_release_binary_audit
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.nonReleaseJobContentsWrite := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite
  ]

theorem tag_release_native_backend_review_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.tagReleaseNativeBackendReviewMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite,
    binaryAudit,
    review
  ]

theorem tag_release_native_backend_posture_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = true)
    (posture : input.tagReleaseNativeBackendPostureStep = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.tagReleaseNativeBackendPostureMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite,
    binaryAudit,
    review,
    posture
  ]

theorem branch_protection_ruleset_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = true)
    (posture : input.tagReleaseNativeBackendPostureStep = true)
    (appUiGuard : input.appUiGuardStep = true)
    (ruleset : input.branchProtectionRulesetEvidence = false) :
    evaluateCiReleaseGate input =
      Except.error
        CiReleaseGateReject.branchProtectionRulesetMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite,
    binaryAudit,
    review,
    posture,
    appUiGuard,
    ruleset
  ]

theorem app_ui_guard_missing_rejects
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (dependencyWaiverGate : input.dependencyAuditWaiverGateStep = true)
    (formalCore : input.formalCoreJob = true)
    (securityAdversarial : input.securityAdversarialJob = true)
    (nativeBackendSecurity : input.nativeBackendSecurityJob = true)
    (appNoSshE2e : input.appNoSshE2eJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (needsAdversarial :
      input.releaseBuildNeedsSecurityAdversarial = true)
    (needsNativeBackend :
      input.releaseBuildNeedsNativeBackendSecurity = true)
    (needsAppNoSshE2e :
      input.releaseBuildNeedsAppNoSshE2e = true)
    (nonReleaseNoWrite : input.nonReleaseJobsNoContentsWrite = true)
    (binaryAudit : input.releaseBinaryAuditStep = true)
    (review : input.tagReleaseNativeBackendReviewStep = true)
    (posture : input.tagReleaseNativeBackendPostureStep = true)
    (appUiGuard : input.appUiGuardStep = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.appUiGuardMissing := by
  unfold evaluateCiReleaseGate firstCiReleaseGateRejection
  simp [ciReleaseGatePreconditions,
    dependency,
    dependencyWaiverGate,
    formalCore,
    securityAdversarial,
    nativeBackendSecurity,
    appNoSshE2e,
    releaseBuild,
    needsSecurity,
    needsAdversarial,
    needsNativeBackend,
    needsAppNoSshE2e,
    nonReleaseNoWrite,
    binaryAudit,
    review,
    posture,
    appUiGuard
  ]

theorem dependency_audit_precedes_all_missing :
    evaluateCiReleaseGate {
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
    } = Except.error CiReleaseGateReject.dependencyAuditMissing := by
  rfl

end CiReleaseGate
end Release
end Hegemon
