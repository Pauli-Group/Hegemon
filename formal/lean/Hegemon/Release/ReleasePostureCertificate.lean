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
  dependencyAuditWaiverGateStep :
    surface.ciReleaseGate.dependencyAuditWaiverGateStep = true
  formalCoreJob :
    surface.ciReleaseGate.formalCoreJob = true
  securityAdversarialJob :
    surface.ciReleaseGate.securityAdversarialJob = true
  nativeBackendSecurityJob :
    surface.ciReleaseGate.nativeBackendSecurityJob = true
  appNoSshE2eJob :
    surface.ciReleaseGate.appNoSshE2eJob = true
  releaseBuildJob :
    surface.ciReleaseGate.releaseBuildJob = true
  releaseBuildNeedsSecurityGates :
    surface.ciReleaseGate.releaseBuildNeedsSecurityGates = true
  releaseBuildNeedsSecurityAdversarial :
    surface.ciReleaseGate.releaseBuildNeedsSecurityAdversarial = true
  releaseBuildNeedsNativeBackendSecurity :
    surface.ciReleaseGate.releaseBuildNeedsNativeBackendSecurity = true
  releaseBuildNeedsAppNoSshE2e :
    surface.ciReleaseGate.releaseBuildNeedsAppNoSshE2e = true
  nonReleaseJobsNoContentsWrite :
    surface.ciReleaseGate.nonReleaseJobsNoContentsWrite = true
  releaseBinaryAuditStep :
    surface.ciReleaseGate.releaseBinaryAuditStep = true
  tagReleaseNativeBackendReviewStep :
    surface.ciReleaseGate.tagReleaseNativeBackendReviewStep = true
  tagReleaseNativeBackendPostureStep :
    surface.ciReleaseGate.tagReleaseNativeBackendPostureStep = true
  appUiGuardStep :
    surface.ciReleaseGate.appUiGuardStep = true
  branchProtectionRulesetEvidence :
    surface.ciReleaseGate.branchProtectionRulesetEvidence = true
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
  everyFindingHasExplicitCurrentReviewedWaiver :
    ∀ finding, finding ∈ input.findings →
      ∃ waiver, waiver ∈ input.waivers
        ∧ waiver.id = finding.id
        ∧ waiver.package = finding.package
        ∧ waiver.version = finding.version
        ∧ waiver.kind = finding.kind
        ∧ waiver.hasTracking = true
        ∧ waiver.hasReason = true
        ∧ waiver.hasOwner = true
        ∧ waiver.hasRemediation = true
        ∧ waiver.hasReviewDate = true
        ∧ waiver.notExpired = true
  everyWaiverIsValid :
    ∀ waiver, waiver ∈ input.waivers →
      waiverIsValid waiver = true
  everyWaiverHasCurrentReviewPolicy :
    ∀ waiver, waiver ∈ input.waivers →
      waiverHasIdentityFields waiver = true
        ∧ waiver.hasTracking = true
        ∧ waiver.hasReason = true
        ∧ waiver.hasOwner = true
        ∧ waiver.hasRemediation = true
        ∧ waiver.hasReviewDate = true
        ∧ waiver.notExpired = true
  everyWaiverHasReleaseMetadata :
    ∀ waiver, waiver ∈ input.waivers →
      waiverHasReleaseMetadata waiver = true
  everyWaiverHasReleaseMetadataFields :
    ∀ waiver, waiver ∈ input.waivers →
      waiver.hasTracking = true
        ∧ waiver.hasReason = true
        ∧ waiver.hasOwner = true
        ∧ waiver.hasRemediation = true
        ∧ waiver.hasReviewDate = true
  everyWaiverMatchesLiveFinding :
    ∀ waiver, waiver ∈ input.waivers →
      waiverMatchesAnyFinding input.findings waiver = true
  everyWaiverHasLiveExactFinding :
    ∀ waiver, waiver ∈ input.waivers →
      ∃ finding, finding ∈ input.findings
        ∧ waiver.id = finding.id
        ∧ waiver.package = finding.package
        ∧ waiver.version = finding.version
        ∧ waiver.kind = finding.kind

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
  rcases ciFacts with
    ⟨dependencyAuditJob, dependencyAuditWaiverGateStep, formalCoreJob,
      securityAdversarialJob, nativeBackendSecurityJob, appNoSshE2eJob,
      releaseBuildJob,
      releaseBuildNeedsSecurityGates, releaseBuildNeedsSecurityAdversarial,
      releaseBuildNeedsNativeBackendSecurity, releaseBuildNeedsAppNoSshE2e,
      nonReleaseJobsNoContentsWrite, releaseBinaryAuditStep,
      tagReleaseNativeBackendReviewStep, tagReleaseNativeBackendPostureStep,
      appUiGuardStep, branchProtectionRulesetEvidence⟩
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
    dependencyAuditJob := dependencyAuditJob,
    dependencyAuditWaiverGateStep := dependencyAuditWaiverGateStep,
    formalCoreJob := formalCoreJob,
    securityAdversarialJob := securityAdversarialJob,
    nativeBackendSecurityJob := nativeBackendSecurityJob,
    appNoSshE2eJob := appNoSshE2eJob,
    releaseBuildJob := releaseBuildJob,
    releaseBuildNeedsSecurityGates := releaseBuildNeedsSecurityGates,
    releaseBuildNeedsSecurityAdversarial := releaseBuildNeedsSecurityAdversarial,
    releaseBuildNeedsNativeBackendSecurity := releaseBuildNeedsNativeBackendSecurity,
    releaseBuildNeedsAppNoSshE2e := releaseBuildNeedsAppNoSshE2e,
    nonReleaseJobsNoContentsWrite := nonReleaseJobsNoContentsWrite,
    releaseBinaryAuditStep := releaseBinaryAuditStep,
    tagReleaseNativeBackendReviewStep := tagReleaseNativeBackendReviewStep,
    tagReleaseNativeBackendPostureStep := tagReleaseNativeBackendPostureStep,
    appUiGuardStep := appUiGuardStep,
    branchProtectionRulesetEvidence := branchProtectionRulesetEvidence,
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
      everyFindingHasExplicitCurrentReviewedWaiver := by
        intro finding present
        exact
          accepted_dependency_audit_finding_has_explicit_current_reviewed_waiver
            accepted.dependencyAuditAccepted
            present,
      everyWaiverIsValid := by
        intro waiver present
        exact accepted_dependency_audit_waiver_is_valid
          accepted.dependencyAuditAccepted
          present,
      everyWaiverHasCurrentReviewPolicy := by
        intro waiver present
        exact accepted_dependency_audit_waiver_has_current_review_policy
          accepted.dependencyAuditAccepted
          present,
      everyWaiverHasReleaseMetadata := by
        intro waiver present
        exact accepted_dependency_audit_waiver_has_release_metadata
          accepted.dependencyAuditAccepted
          present,
      everyWaiverHasReleaseMetadataFields := by
        intro waiver present
        exact accepted_dependency_audit_waiver_release_metadata_fields
          accepted.dependencyAuditAccepted
          present,
      everyWaiverMatchesLiveFinding := by
        intro waiver present
        exact accepted_dependency_audit_waiver_matches_live_finding
          accepted.dependencyAuditAccepted
          present,
      everyWaiverHasLiveExactFinding := by
        intro waiver present
        exact accepted_dependency_audit_waiver_has_live_exact_finding
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

theorem production_release_gate_certificate_exposes_dependency_waiver_accounting
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
      ∧ dependencyAuditPreconditions surface.dependencyAudit = true
      ∧ (∀ finding, finding ∈ surface.dependencyAudit.findings →
          findingHasValidWaiver surface.dependencyAudit.waivers finding = true)
      ∧ (∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
          waiverIsValid waiver = true)
      ∧ (∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
          waiverHasReleaseMetadata waiver = true)
      ∧ (∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
          waiverMatchesAnyFinding surface.dependencyAudit.findings waiver =
            true) := by
  exact
    ⟨certificate.dependencyWaiverGate.auditAccepted,
      certificate.dependencyWaiverGate.auditPreconditions,
      certificate.dependencyWaiverGate.everyFindingHasExplicitValidWaiver,
      certificate.dependencyWaiverGate.everyWaiverIsValid,
      certificate.dependencyWaiverGate.everyWaiverHasReleaseMetadata,
      certificate.dependencyWaiverGate.everyWaiverMatchesLiveFinding⟩

theorem production_release_gate_certificate_exposes_dependency_waiver_metadata_fields
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    ∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
      waiver.hasTracking = true
        ∧ waiver.hasReason = true
        ∧ waiver.hasOwner = true
        ∧ waiver.hasRemediation = true
        ∧ waiver.hasReviewDate = true := by
  exact
    certificate.dependencyWaiverGate.everyWaiverHasReleaseMetadataFields

theorem production_release_gate_certificate_exposes_current_review_policy
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    (∀ finding, finding ∈ surface.dependencyAudit.findings →
      ∃ waiver, waiver ∈ surface.dependencyAudit.waivers
        ∧ waiver.id = finding.id
        ∧ waiver.package = finding.package
        ∧ waiver.version = finding.version
        ∧ waiver.kind = finding.kind
        ∧ waiver.hasTracking = true
        ∧ waiver.hasReason = true
        ∧ waiver.hasOwner = true
        ∧ waiver.hasRemediation = true
        ∧ waiver.hasReviewDate = true
        ∧ waiver.notExpired = true)
      ∧ (∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
        waiverHasIdentityFields waiver = true
          ∧ waiver.hasTracking = true
          ∧ waiver.hasReason = true
          ∧ waiver.hasOwner = true
          ∧ waiver.hasRemediation = true
          ∧ waiver.hasReviewDate = true
          ∧ waiver.notExpired = true) := by
  exact
    ⟨certificate.dependencyWaiverGate.everyFindingHasExplicitCurrentReviewedWaiver,
      certificate.dependencyWaiverGate.everyWaiverHasCurrentReviewPolicy⟩

theorem production_release_gate_certificate_exposes_live_waiver_exactness
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    ∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
      ∃ finding, finding ∈ surface.dependencyAudit.findings
        ∧ waiver.id = finding.id
        ∧ waiver.package = finding.package
        ∧ waiver.version = finding.version
        ∧ waiver.kind = finding.kind := by
  exact certificate.dependencyWaiverGate.everyWaiverHasLiveExactFinding

theorem production_release_gate_certificate_exposes_dependency_audit_ci_binding
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
      ∧ dependencyAuditPreconditions surface.dependencyAudit = true
      ∧ evaluateCiReleaseGate surface.ciReleaseGate = Except.ok ()
      ∧ surface.ciReleaseGate.dependencyAuditJob = true
      ∧ surface.ciReleaseGate.dependencyAuditWaiverGateStep = true
      ∧ surface.ciReleaseGate.releaseBuildJob = true
      ∧ surface.ciReleaseGate.releaseBuildNeedsSecurityGates = true := by
  exact
    ⟨certificate.dependencyWaiverGate.auditAccepted,
      certificate.dependencyWaiverGate.auditPreconditions,
      certificate.releaseFacts.ciReleaseGateAccepted,
      certificate.releaseFacts.dependencyAuditJob,
      certificate.releaseFacts.dependencyAuditWaiverGateStep,
        certificate.releaseFacts.releaseBuildJob,
        certificate.releaseFacts.releaseBuildNeedsSecurityGates⟩

theorem production_release_gate_certificate_binds_dependency_audit_to_ci_release_gate
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    evaluateDependencyAudit surface.dependencyAudit = Except.ok ()
      ∧ dependencyAuditPreconditions surface.dependencyAudit = true
      ∧ (∀ finding, finding ∈ surface.dependencyAudit.findings →
        ∃ waiver, waiver ∈ surface.dependencyAudit.waivers
          ∧ waiver.id = finding.id
          ∧ waiver.package = finding.package
          ∧ waiver.version = finding.version
          ∧ waiver.kind = finding.kind
          ∧ waiver.hasTracking = true
          ∧ waiver.hasReason = true
          ∧ waiver.hasOwner = true
          ∧ waiver.hasRemediation = true
          ∧ waiver.hasReviewDate = true
          ∧ waiver.notExpired = true)
      ∧ (∀ waiver, waiver ∈ surface.dependencyAudit.waivers →
        ∃ finding, finding ∈ surface.dependencyAudit.findings
          ∧ waiver.id = finding.id
          ∧ waiver.package = finding.package
          ∧ waiver.version = finding.version
          ∧ waiver.kind = finding.kind)
      ∧ evaluateCiReleaseGate surface.ciReleaseGate = Except.ok ()
      ∧ surface.ciReleaseGate.dependencyAuditJob = true
      ∧ surface.ciReleaseGate.dependencyAuditWaiverGateStep = true
      ∧ surface.ciReleaseGate.releaseBuildJob = true
      ∧ surface.ciReleaseGate.releaseBuildNeedsSecurityGates = true := by
  exact
    ⟨certificate.dependencyWaiverGate.auditAccepted,
      certificate.dependencyWaiverGate.auditPreconditions,
      certificate.dependencyWaiverGate.everyFindingHasExplicitCurrentReviewedWaiver,
      certificate.dependencyWaiverGate.everyWaiverHasLiveExactFinding,
      certificate.releaseFacts.ciReleaseGateAccepted,
      certificate.releaseFacts.dependencyAuditJob,
      certificate.releaseFacts.dependencyAuditWaiverGateStep,
      certificate.releaseFacts.releaseBuildJob,
      certificate.releaseFacts.releaseBuildNeedsSecurityGates⟩

theorem production_release_gate_certificate_requires_native_backend_accepted_mode
    {surface : ReleasePostureSurface}
    (certificate : ProductionReleaseGateCertificate surface) :
    surface.nativeBackendPosture.requireAccepted = true
      ∧ acceptedPreconditions surface.nativeBackendPosture = true
      ∧ releasePosturePreconditions surface.nativeBackendPosture = true := by
  exact
    ⟨certificate.nativeBackendResidualGate.acceptedModeRequired,
      certificate.nativeBackendResidualGate.acceptedPreconditionsHold,
      certificate.nativeBackendResidualGate.posturePreconditionsHold⟩

end ReleasePostureCertificate
end Release
end Hegemon
