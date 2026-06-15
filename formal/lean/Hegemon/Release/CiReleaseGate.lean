namespace Hegemon
namespace Release
namespace CiReleaseGate

inductive CiReleaseGateReject where
  | dependencyAuditMissing
  | formalCoreMissing
  | releaseBuildMissing
  | releaseBuildDependencyMissing
  | releaseBinaryAuditMissing
deriving DecidableEq, Repr

structure CiReleaseGateInput where
  dependencyAuditJob : Bool
  formalCoreJob : Bool
  releaseBuildJob : Bool
  releaseBuildNeedsSecurityGates : Bool
  releaseBinaryAuditStep : Bool
deriving DecidableEq, Repr

def evaluateCiReleaseGate
    (input : CiReleaseGateInput) : Except CiReleaseGateReject Unit :=
  if input.dependencyAuditJob = false then
    Except.error CiReleaseGateReject.dependencyAuditMissing
  else if input.formalCoreJob = false then
    Except.error CiReleaseGateReject.formalCoreMissing
  else if input.releaseBuildJob = false then
    Except.error CiReleaseGateReject.releaseBuildMissing
  else if input.releaseBuildNeedsSecurityGates = false then
    Except.error CiReleaseGateReject.releaseBuildDependencyMissing
  else if input.releaseBinaryAuditStep = false then
    Except.error CiReleaseGateReject.releaseBinaryAuditMissing
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
    input.releaseBuildJob &&
    input.releaseBuildNeedsSecurityGates &&
    input.releaseBinaryAuditStep

theorem accepts_iff_ci_release_gate_preconditions
    (input : CiReleaseGateInput) :
    ciReleaseGateAccepts input = ciReleaseGatePreconditions input := by
  cases input with
  | mk dependencyAuditJob formalCoreJob releaseBuildJob
      releaseBuildNeedsSecurityGates releaseBinaryAuditStep =>
      unfold ciReleaseGateAccepts ciReleaseGatePreconditions
        evaluateCiReleaseGate
      cases dependencyAuditJob <;>
        cases formalCoreJob <;>
        cases releaseBuildJob <;>
        cases releaseBuildNeedsSecurityGates <;>
        cases releaseBinaryAuditStep <;>
        rfl

def completeCiReleaseGate : CiReleaseGateInput :=
  {
    dependencyAuditJob := true,
    formalCoreJob := true,
    releaseBuildJob := true,
    releaseBuildNeedsSecurityGates := true,
    releaseBinaryAuditStep := true
  }

def missingDependencyAuditJob : CiReleaseGateInput :=
  { completeCiReleaseGate with dependencyAuditJob := false }

def missingFormalCoreJob : CiReleaseGateInput :=
  { completeCiReleaseGate with formalCoreJob := false }

def missingReleaseBuildJob : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildJob := false }

def missingReleaseBuildDependency : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBuildNeedsSecurityGates := false }

def missingReleaseBinaryAuditStep : CiReleaseGateInput :=
  { completeCiReleaseGate with releaseBinaryAuditStep := false }

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
    (releaseBuild : input.releaseBuildJob = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore, releaseBuild]

theorem release_build_dependency_missing_rejects_after_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBuildDependencyMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore, releaseBuild, needsSecurity]

theorem release_binary_audit_missing_rejects_after_security_jobs
    {input : CiReleaseGateInput}
    (dependency : input.dependencyAuditJob = true)
    (formalCore : input.formalCoreJob = true)
    (releaseBuild : input.releaseBuildJob = true)
    (needsSecurity : input.releaseBuildNeedsSecurityGates = true)
    (binaryAudit : input.releaseBinaryAuditStep = false) :
    evaluateCiReleaseGate input =
      Except.error CiReleaseGateReject.releaseBinaryAuditMissing := by
  unfold evaluateCiReleaseGate
  simp [dependency, formalCore, releaseBuild, needsSecurity, binaryAudit]

theorem dependency_audit_precedes_all_missing :
    evaluateCiReleaseGate {
      dependencyAuditJob := false,
      formalCoreJob := false,
      releaseBuildJob := false,
      releaseBuildNeedsSecurityGates := false,
      releaseBinaryAuditStep := false
    } = Except.error CiReleaseGateReject.dependencyAuditMissing := by
  rfl

end CiReleaseGate
end Release
end Hegemon
