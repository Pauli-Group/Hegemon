import Hegemon.Release.CiReleaseGate
import Hegemon.Release.DependencyAuditPolicy
import Hegemon.Release.PqBinaryPolicy

namespace Hegemon
namespace Release
namespace ReleasePostureCertificate

open Hegemon.Release.CiReleaseGate
open Hegemon.Release.DependencyAuditPolicy
open Hegemon.Release.PqBinaryPolicy

structure ReleasePostureSurface where
  dependencyAudit : DependencyAuditInput
  pqBinaryAudit : PqBinaryAuditInput
  ciReleaseGate : CiReleaseGateInput
deriving DecidableEq, Repr

structure AcceptedReleasePostureInputs
    (surface : ReleasePostureSurface) : Prop where
  dependencyAuditAccepted :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
  pqBinaryAuditAccepted :
    evaluatePqBinaryAudit surface.pqBinaryAudit = Except.ok ()
  ciReleaseGateAccepted :
    evaluateCiReleaseGate surface.ciReleaseGate = Except.ok ()

structure AcceptedReleasePostureFacts
    (surface : ReleasePostureSurface) : Prop where
  dependencyAuditAccepted :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
  dependencyWaiversValid :
    dependencyWaiversValid surface.dependencyAudit = true
  dependencyFindingsWaived :
    dependencyFindingsWaived surface.dependencyAudit = true
  dependencyWaiversUsed :
    dependencyWaiversUsed surface.dependencyAudit = true
  pqBinaryAuditAccepted :
    evaluatePqBinaryAudit surface.pqBinaryAudit = Except.ok ()
  sourceScanClean :
    surface.pqBinaryAudit.sourceScanClean = true
  dependencyScanClean :
    surface.pqBinaryAudit.dependencyScanClean = true
  binaryScanClean :
    surface.pqBinaryAudit.binaryScanClean = true
  ciReleaseGateAccepted :
    evaluateCiReleaseGate surface.ciReleaseGate = Except.ok ()
  dependencyAuditJob :
    surface.ciReleaseGate.dependencyAuditJob = true
  formalCoreJob :
    surface.ciReleaseGate.formalCoreJob = true
  securityAdversarialJob :
    surface.ciReleaseGate.securityAdversarialJob = true
  nativeBackendSecurityJob :
    surface.ciReleaseGate.nativeBackendSecurityJob = true
  releaseBuildJob :
    surface.ciReleaseGate.releaseBuildJob = true
  releaseBuildNeedsSecurityGates :
    surface.ciReleaseGate.releaseBuildNeedsSecurityGates = true
  releaseBuildNeedsSecurityAdversarial :
    surface.ciReleaseGate.releaseBuildNeedsSecurityAdversarial = true
  releaseBuildNeedsNativeBackendSecurity :
    surface.ciReleaseGate.releaseBuildNeedsNativeBackendSecurity = true
  releaseBinaryAuditStep :
    surface.ciReleaseGate.releaseBinaryAuditStep = true
  tagReleaseNativeBackendReviewStep :
    surface.ciReleaseGate.tagReleaseNativeBackendReviewStep = true
  tagReleaseNativeBackendPostureStep :
    surface.ciReleaseGate.tagReleaseNativeBackendPostureStep = true

theorem accepted_pq_binary_audit_exposes_clean_scans
    {input : PqBinaryAuditInput}
    (accepted : evaluatePqBinaryAudit input = Except.ok ()) :
    input.sourceScanClean = true
      ∧ input.dependencyScanClean = true
      ∧ input.binaryScanClean = true := by
  unfold evaluatePqBinaryAudit at accepted
  cases hSource : input.sourceScanClean <;>
    cases hDependency : input.dependencyScanClean <;>
    cases hBinary : input.binaryScanClean <;>
    simp [hSource, hDependency, hBinary] at accepted ⊢

theorem accepted_release_posture_exposes_all_release_gates
    {surface : ReleasePostureSurface}
    (accepted : AcceptedReleasePostureInputs surface) :
    AcceptedReleasePostureFacts surface := by
  have dependencyFacts :=
    accepted_dependency_audit_exposes_policy_facts
      accepted.dependencyAuditAccepted
  have pqFacts :=
    accepted_pq_binary_audit_exposes_clean_scans
      accepted.pqBinaryAuditAccepted
  have ciFacts :=
    accepted_ci_release_gate_exposes_required_policy_facts
      accepted.ciReleaseGateAccepted
  exact {
    dependencyAuditAccepted := accepted.dependencyAuditAccepted,
    dependencyWaiversValid := dependencyFacts.left,
    dependencyFindingsWaived := dependencyFacts.right.left,
    dependencyWaiversUsed := dependencyFacts.right.right,
    pqBinaryAuditAccepted := accepted.pqBinaryAuditAccepted,
    sourceScanClean := pqFacts.left,
    dependencyScanClean := pqFacts.right.left,
    binaryScanClean := pqFacts.right.right,
    ciReleaseGateAccepted := accepted.ciReleaseGateAccepted,
    dependencyAuditJob := ciFacts.left,
    formalCoreJob := ciFacts.right.left,
    securityAdversarialJob := ciFacts.right.right.left,
    nativeBackendSecurityJob := ciFacts.right.right.right.left,
    releaseBuildJob := ciFacts.right.right.right.right.left,
    releaseBuildNeedsSecurityGates :=
      ciFacts.right.right.right.right.right.left,
    releaseBuildNeedsSecurityAdversarial :=
      ciFacts.right.right.right.right.right.right.left,
    releaseBuildNeedsNativeBackendSecurity :=
      ciFacts.right.right.right.right.right.right.right.left,
    releaseBinaryAuditStep :=
      ciFacts.right.right.right.right.right.right.right.right.left,
    tagReleaseNativeBackendReviewStep :=
      ciFacts.right.right.right.right.right.right.right.right.right.left,
    tagReleaseNativeBackendPostureStep :=
      ciFacts.right.right.right.right.right.right.right.right.right.right
  }

end ReleasePostureCertificate
end Release
end Hegemon
