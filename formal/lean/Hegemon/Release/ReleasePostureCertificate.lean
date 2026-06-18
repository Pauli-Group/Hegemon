import Hegemon.Release.CiReleaseGate
import Hegemon.Release.DependencyAuditPolicy
import Hegemon.Release.PqBinaryPolicy
import Hegemon.Native.NativeBackendReleasePosture

namespace Hegemon
namespace Release
namespace ReleasePostureCertificate

open Hegemon.Release.CiReleaseGate
open Hegemon.Release.DependencyAuditPolicy
open Hegemon.Release.PqBinaryPolicy
open Hegemon.Native.NativeBackendReleasePosture

structure ReleasePostureSurface where
  dependencyAudit : DependencyAuditInput
  pqBinaryAudit : PqBinaryAuditInput
  ciReleaseGate : CiReleaseGateInput
  nativeBackendPosture : ReleasePostureInput
deriving DecidableEq, Repr

structure AcceptedReleasePostureInputs
    (surface : ReleasePostureSurface) : Prop where
  dependencyAuditAccepted :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
  pqBinaryAuditAccepted :
    evaluatePqBinaryAudit surface.pqBinaryAudit = Except.ok ()
  ciReleaseGateAccepted :
    evaluateCiReleaseGate surface.ciReleaseGate = Except.ok ()
  nativeBackendPostureAccepted :
    evaluateReleasePosture surface.nativeBackendPosture = Except.ok ()

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
  nativeBackendPostureAccepted :
    evaluateReleasePosture surface.nativeBackendPosture = Except.ok ()
  nativeBackendPosturePreconditions :
    releasePosturePreconditions surface.nativeBackendPosture = true

structure DependencyAuditExplicitWaiverCertificate
    (input : DependencyAuditInput) : Prop where
  auditAccepted :
    evaluateDependencyAudit input = Except.ok ()
  auditPreconditions :
    dependencyAuditPreconditions input = true
  everyFindingHasExplicitValidWaiver :
    ∀ finding, finding ∈ input.findings →
      findingHasValidWaiver input.waivers finding = true
  everyWaiverIsValid :
    ∀ waiver, waiver ∈ input.waivers →
      waiverIsValid waiver = true
  everyWaiverMatchesLiveFinding :
    ∀ waiver, waiver ∈ input.waivers →
      waiverMatchesAnyFinding input.findings waiver = true

structure PqReleaseResidualCertificate
    (input : PqBinaryAuditInput) : Prop where
  auditAccepted :
    evaluatePqBinaryAudit input = Except.ok ()
  allScansClean :
    pqBinaryAllScansClean input = true
  sourceScanClean :
    input.sourceScanClean = true
  dependencyScanClean :
    input.dependencyScanClean = true
  binaryScanClean :
    input.binaryScanClean = true

structure NativeBackendProductionAcceptedCertificate
    (input : ReleasePostureInput) : Prop where
  acceptedModeRequired :
    input.requireAccepted = true
  postureAccepted :
    evaluateReleasePosture input = Except.ok ()
  acceptedPreconditionsHold :
    acceptedPreconditions input = true
  posturePreconditionsHold :
    releasePosturePreconditions input = true

structure ProductionReleaseGateCertificate
    (surface : ReleasePostureSurface) : Prop where
  releaseFacts :
    AcceptedReleasePostureFacts surface
  dependencyWaiverGate :
    DependencyAuditExplicitWaiverCertificate surface.dependencyAudit
  pqResidualGate :
    PqReleaseResidualCertificate surface.pqBinaryAudit
  nativeBackendResidualGate :
    NativeBackendProductionAcceptedCertificate surface.nativeBackendPosture

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

theorem accepted_native_backend_release_posture_exposes_preconditions
    {input : ReleasePostureInput}
    (accepted : evaluateReleasePosture input = Except.ok ()) :
    releasePosturePreconditions input = true := by
  have accepts : releasePostureAccepts input = true := by
    unfold releasePostureAccepts
    simp [accepted]
  rw [accepts_iff_release_posture_preconditions] at accepts
  exact accepts

theorem accepted_native_backend_release_posture_in_accepted_mode_exposes_preconditions
    {input : ReleasePostureInput}
    (accepted : evaluateReleasePosture input = Except.ok ())
    (acceptedMode : input.requireAccepted = true) :
    acceptedPreconditions input = true := by
  have posturePreconditions :=
    accepted_native_backend_release_posture_exposes_preconditions accepted
  unfold releasePosturePreconditions at posturePreconditions
  simpa [acceptedMode] using posturePreconditions

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
  have nativeBackendPostureFacts :=
    accepted_native_backend_release_posture_exposes_preconditions
      accepted.nativeBackendPostureAccepted
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
      ciFacts.right.right.right.right.right.right.right.right.right.right,
    nativeBackendPostureAccepted :=
      accepted.nativeBackendPostureAccepted,
    nativeBackendPosturePreconditions :=
      nativeBackendPostureFacts
  }

theorem accepted_release_posture_with_native_accepted_mode_yields_production_gate_certificate
    {surface : ReleasePostureSurface}
    (accepted : AcceptedReleasePostureInputs surface)
    (nativeAcceptedMode :
      surface.nativeBackendPosture.requireAccepted = true) :
    ProductionReleaseGateCertificate surface := by
  have releaseFacts :=
    accepted_release_posture_exposes_all_release_gates accepted
  have nativeAcceptedPreconditions :=
    accepted_native_backend_release_posture_in_accepted_mode_exposes_preconditions
      accepted.nativeBackendPostureAccepted
      nativeAcceptedMode
  exact {
    releaseFacts := releaseFacts,
    dependencyWaiverGate := {
      auditAccepted := accepted.dependencyAuditAccepted,
      auditPreconditions := by
        simp [
          dependencyAuditPreconditions,
          releaseFacts.dependencyWaiversValid,
          releaseFacts.dependencyFindingsWaived,
          releaseFacts.dependencyWaiversUsed
        ],
      everyFindingHasExplicitValidWaiver := by
        intro finding present
        exact accepted_dependency_audit_finding_has_explicit_valid_waiver
          accepted.dependencyAuditAccepted
          present,
      everyWaiverIsValid := by
        intro waiver present
        exact accepted_dependency_audit_waiver_is_valid
          accepted.dependencyAuditAccepted
          present,
      everyWaiverMatchesLiveFinding := by
        intro waiver present
        exact accepted_dependency_audit_waiver_matches_live_finding
          accepted.dependencyAuditAccepted
          present
    },
    pqResidualGate := {
      auditAccepted := accepted.pqBinaryAuditAccepted,
      allScansClean := by
        simp [
          pqBinaryAllScansClean,
          releaseFacts.sourceScanClean,
          releaseFacts.dependencyScanClean,
          releaseFacts.binaryScanClean
        ],
      sourceScanClean := releaseFacts.sourceScanClean,
      dependencyScanClean := releaseFacts.dependencyScanClean,
      binaryScanClean := releaseFacts.binaryScanClean
    },
    nativeBackendResidualGate := {
      acceptedModeRequired := nativeAcceptedMode,
      postureAccepted := accepted.nativeBackendPostureAccepted,
      acceptedPreconditionsHold := nativeAcceptedPreconditions,
      posturePreconditionsHold :=
        releaseFacts.nativeBackendPosturePreconditions
    }
  }

end ReleasePostureCertificate
end Release
end Hegemon
