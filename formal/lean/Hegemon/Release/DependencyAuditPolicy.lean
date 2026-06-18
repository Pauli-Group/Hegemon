namespace Hegemon
namespace Release
namespace DependencyAuditPolicy

inductive DependencyAuditReject where
  | malformedWaiver
  | unwaivedFinding
  | unusedWaiver
deriving DecidableEq, Repr

structure DependencyFinding where
  id : String
  package : String
  version : String
  kind : String
deriving DecidableEq, Repr

structure DependencyWaiver where
  id : String
  package : String
  version : String
  kind : String
  notExpired : Bool
  hasTracking : Bool
  hasReason : Bool
  hasOwner : Bool
  hasRemediation : Bool
  hasReviewDate : Bool
deriving DecidableEq, Repr

structure DependencyAuditInput where
  findings : List DependencyFinding
  waivers : List DependencyWaiver
deriving DecidableEq, Repr

def stringNonEmpty (value : String) : Bool :=
  value != ""

def waiverHasIdentityFields (waiver : DependencyWaiver) : Bool :=
  stringNonEmpty waiver.id
    && stringNonEmpty waiver.package
    && stringNonEmpty waiver.version
    && stringNonEmpty waiver.kind

def waiverHasReleaseMetadata (waiver : DependencyWaiver) : Bool :=
  waiver.hasTracking
    && waiver.hasReason
    && waiver.hasOwner
    && waiver.hasRemediation
    && waiver.hasReviewDate

def waiverHasRequiredFields (waiver : DependencyWaiver) : Bool :=
  waiverHasIdentityFields waiver && waiverHasReleaseMetadata waiver

def waiverIsValid (waiver : DependencyWaiver) : Bool :=
  waiverHasRequiredFields waiver && waiver.notExpired

def waiverMatchesFinding
    (finding : DependencyFinding)
    (waiver : DependencyWaiver) : Bool :=
  waiver.id == finding.id
    && waiver.package == finding.package
    && waiver.version == finding.version
    && waiver.kind == finding.kind

def findingHasValidWaiver
    (waivers : List DependencyWaiver)
    (finding : DependencyFinding) : Bool :=
  waivers.any (fun waiver => waiverIsValid waiver && waiverMatchesFinding finding waiver)

def waiverMatchesAnyFinding
    (findings : List DependencyFinding)
    (waiver : DependencyWaiver) : Bool :=
  findings.any (fun finding => waiverMatchesFinding finding waiver)

def dependencyWaiversValid (input : DependencyAuditInput) : Bool :=
  input.waivers.all waiverIsValid

def dependencyFindingsWaived (input : DependencyAuditInput) : Bool :=
  input.findings.all (findingHasValidWaiver input.waivers)

def dependencyWaiversUsed (input : DependencyAuditInput) : Bool :=
  input.waivers.all (waiverMatchesAnyFinding input.findings)

def dependencyAuditPreconditions (input : DependencyAuditInput) : Bool :=
  dependencyWaiversValid input
    && dependencyFindingsWaived input
    && dependencyWaiversUsed input

def evaluateDependencyAudit
    (input : DependencyAuditInput) : Except DependencyAuditReject Unit :=
  if dependencyWaiversValid input = false then
    Except.error DependencyAuditReject.malformedWaiver
  else if dependencyFindingsWaived input = false then
    Except.error DependencyAuditReject.unwaivedFinding
  else if dependencyWaiversUsed input = false then
    Except.error DependencyAuditReject.unusedWaiver
  else
    Except.ok ()

def dependencyAuditAccepts (input : DependencyAuditInput) : Bool :=
  match evaluateDependencyAudit input with
  | Except.ok _ => true
  | Except.error _ => false

def dependencyAuditRejection
    (input : DependencyAuditInput) : Option DependencyAuditReject :=
  match evaluateDependencyAudit input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

theorem accepts_iff_dependency_audit_preconditions
    (input : DependencyAuditInput) :
    dependencyAuditAccepts input = dependencyAuditPreconditions input := by
  unfold dependencyAuditAccepts
    dependencyAuditPreconditions evaluateDependencyAudit
  cases hWaivers : dependencyWaiversValid input <;>
    cases hFindings : dependencyFindingsWaived input <;>
    cases hUsed : dependencyWaiversUsed input <;>
    simp

theorem accepted_dependency_audit_exposes_policy_facts
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ()) :
    dependencyWaiversValid input = true
      ∧ dependencyFindingsWaived input = true
      ∧ dependencyWaiversUsed input = true := by
  unfold evaluateDependencyAudit at accepted
  cases hWaivers : dependencyWaiversValid input <;>
    cases hFindings : dependencyFindingsWaived input <;>
    cases hUsed : dependencyWaiversUsed input <;>
    simp [hWaivers, hFindings, hUsed] at accepted ⊢

theorem accepted_dependency_audit_finding_has_explicit_valid_waiver
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {finding : DependencyFinding}
    (present : finding ∈ input.findings) :
    findingHasValidWaiver input.waivers finding = true := by
  have facts := accepted_dependency_audit_exposes_policy_facts accepted
  exact (List.all_eq_true.mp facts.2.1) finding present

theorem accepted_dependency_audit_waiver_is_valid
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    waiverIsValid waiver = true := by
  have facts := accepted_dependency_audit_exposes_policy_facts accepted
  exact (List.all_eq_true.mp facts.1) waiver present

theorem accepted_dependency_audit_waiver_has_release_metadata
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    waiverHasReleaseMetadata waiver = true := by
  have valid :=
    accepted_dependency_audit_waiver_is_valid accepted present
  unfold waiverIsValid at valid
  unfold waiverHasRequiredFields at valid
  cases hIdentity : waiverHasIdentityFields waiver <;>
    cases hMetadata : waiverHasReleaseMetadata waiver <;>
    cases hNotExpired : waiver.notExpired <;>
    simp [hIdentity, hMetadata] at valid ⊢

theorem waiver_release_metadata_true_exposes_fields
    {waiver : DependencyWaiver}
    (metadata : waiverHasReleaseMetadata waiver = true) :
    waiver.hasTracking = true
      ∧ waiver.hasReason = true
      ∧ waiver.hasOwner = true
      ∧ waiver.hasRemediation = true
      ∧ waiver.hasReviewDate = true := by
  unfold waiverHasReleaseMetadata at metadata
  simp at metadata
  rcases metadata with
    ⟨⟨⟨⟨tracking, reason⟩, owner⟩, remediation⟩, reviewDate⟩
  exact ⟨tracking, reason, owner, remediation, reviewDate⟩

theorem accepted_dependency_audit_waiver_release_metadata_fields
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    waiver.hasTracking = true
      ∧ waiver.hasReason = true
      ∧ waiver.hasOwner = true
      ∧ waiver.hasRemediation = true
      ∧ waiver.hasReviewDate = true := by
  exact waiver_release_metadata_true_exposes_fields
    (accepted_dependency_audit_waiver_has_release_metadata accepted present)

theorem waiver_valid_true_exposes_current_review_policy
    {waiver : DependencyWaiver}
    (valid : waiverIsValid waiver = true) :
    waiverHasIdentityFields waiver = true
      ∧ waiver.hasTracking = true
      ∧ waiver.hasReason = true
      ∧ waiver.hasOwner = true
      ∧ waiver.hasRemediation = true
      ∧ waiver.hasReviewDate = true
      ∧ waiver.notExpired = true := by
  unfold waiverIsValid waiverHasRequiredFields at valid
  simp at valid
  rcases valid with ⟨⟨identity, metadata⟩, notExpired⟩
  have metadataFields :=
    waiver_release_metadata_true_exposes_fields metadata
  exact
    ⟨identity,
      metadataFields.left,
      metadataFields.right.left,
      metadataFields.right.right.left,
      metadataFields.right.right.right.left,
      metadataFields.right.right.right.right,
      notExpired⟩

theorem accepted_dependency_audit_waiver_has_current_review_policy
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    waiverHasIdentityFields waiver = true
      ∧ waiver.hasTracking = true
      ∧ waiver.hasReason = true
      ∧ waiver.hasOwner = true
      ∧ waiver.hasRemediation = true
      ∧ waiver.hasReviewDate = true
      ∧ waiver.notExpired = true := by
  exact waiver_valid_true_exposes_current_review_policy
    (accepted_dependency_audit_waiver_is_valid accepted present)

theorem accepted_dependency_audit_waiver_matches_live_finding
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    waiverMatchesAnyFinding input.findings waiver = true := by
  have facts := accepted_dependency_audit_exposes_policy_facts accepted
  exact (List.all_eq_true.mp facts.2.2) waiver present

theorem waiver_match_true_exposes_exact_fields
    {finding : DependencyFinding}
    {waiver : DependencyWaiver}
    (matched : waiverMatchesFinding finding waiver = true) :
    waiver.id = finding.id
      ∧ waiver.package = finding.package
      ∧ waiver.version = finding.version
      ∧ waiver.kind = finding.kind := by
  unfold waiverMatchesFinding at matched
  simp at matched
  rcases matched with
    ⟨⟨⟨idExact, packageExact⟩, versionExact⟩, kindExact⟩
  exact ⟨idExact, packageExact, versionExact, kindExact⟩

theorem waiver_matches_any_finding_exposes_live_exact_match
    {findings : List DependencyFinding}
    {waiver : DependencyWaiver}
    (matched : waiverMatchesAnyFinding findings waiver = true) :
    ∃ finding, finding ∈ findings
      ∧ waiverMatchesFinding finding waiver = true := by
  unfold waiverMatchesAnyFinding at matched
  simpa using matched

theorem finding_has_valid_waiver_exposes_explicit_waiver
    {waivers : List DependencyWaiver}
    {finding : DependencyFinding}
    (hasWaiver : findingHasValidWaiver waivers finding = true) :
    ∃ waiver, waiver ∈ waivers
      ∧ waiverIsValid waiver = true
      ∧ waiverMatchesFinding finding waiver = true := by
  unfold findingHasValidWaiver at hasWaiver
  simpa using hasWaiver

theorem accepted_dependency_audit_finding_has_explicit_current_reviewed_waiver
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {finding : DependencyFinding}
    (present : finding ∈ input.findings) :
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
      ∧ waiver.notExpired = true := by
  have hasWaiver :=
    accepted_dependency_audit_finding_has_explicit_valid_waiver
      accepted
      present
  rcases finding_has_valid_waiver_exposes_explicit_waiver hasWaiver with
    ⟨waiver, waiverPresent, waiverValid, waiverMatched⟩
  have exactFields :=
    waiver_match_true_exposes_exact_fields
      (finding := finding)
      (waiver := waiver)
      waiverMatched
  have reviewPolicy :=
    waiver_valid_true_exposes_current_review_policy waiverValid
  exact
    ⟨waiver,
      waiverPresent,
      exactFields.left,
      exactFields.right.left,
      exactFields.right.right.left,
      exactFields.right.right.right,
      reviewPolicy.right.left,
      reviewPolicy.right.right.left,
      reviewPolicy.right.right.right.left,
      reviewPolicy.right.right.right.right.left,
      reviewPolicy.right.right.right.right.right.left,
      reviewPolicy.right.right.right.right.right.right⟩

theorem accepted_dependency_audit_waiver_has_live_exact_finding
    {input : DependencyAuditInput}
    (accepted : evaluateDependencyAudit input = Except.ok ())
    {waiver : DependencyWaiver}
    (present : waiver ∈ input.waivers) :
    ∃ finding, finding ∈ input.findings
      ∧ waiver.id = finding.id
      ∧ waiver.package = finding.package
      ∧ waiver.version = finding.version
      ∧ waiver.kind = finding.kind := by
  have matched :=
    accepted_dependency_audit_waiver_matches_live_finding
      accepted
      present
  rcases waiver_matches_any_finding_exposes_live_exact_match matched with
    ⟨finding, findingPresent, findingMatched⟩
  have exactFields :=
    waiver_match_true_exposes_exact_fields
      (finding := finding)
      (waiver := waiver)
      findingMatched
  exact
    ⟨finding,
      findingPresent,
      exactFields.left,
      exactFields.right.left,
      exactFields.right.right.left,
        exactFields.right.right.right⟩

theorem dependency_audit_rejects_malformed_waiver_fail_closed
    {input : DependencyAuditInput}
    (malformed : dependencyWaiversValid input = false) :
    evaluateDependencyAudit input =
      Except.error DependencyAuditReject.malformedWaiver := by
  unfold evaluateDependencyAudit
  simp [malformed]

theorem dependency_audit_rejects_unwaived_finding_fail_closed
    {input : DependencyAuditInput}
    (waiversValid : dependencyWaiversValid input = true)
    (findingsWaived : dependencyFindingsWaived input = false) :
    evaluateDependencyAudit input =
      Except.error DependencyAuditReject.unwaivedFinding := by
  unfold evaluateDependencyAudit
  simp [waiversValid, findingsWaived]

theorem dependency_audit_rejects_unused_waiver_fail_closed
    {input : DependencyAuditInput}
    (waiversValid : dependencyWaiversValid input = true)
    (findingsWaived : dependencyFindingsWaived input = true)
    (waiversUsed : dependencyWaiversUsed input = false) :
    evaluateDependencyAudit input =
      Except.error DependencyAuditReject.unusedWaiver := by
  unfold evaluateDependencyAudit
  simp [waiversValid, findingsWaived, waiversUsed]

def bincodeFinding : DependencyFinding :=
  {
    id := "RUSTSEC-2025-0141",
    package := "bincode",
    version := "1.3.3",
    kind := "unmaintained"
  }

def validBincodeWaiver : DependencyWaiver :=
  {
    id := "RUSTSEC-2025-0141",
    package := "bincode",
    version := "1.3.3",
    kind := "unmaintained",
    notExpired := true,
    hasTracking := true,
    hasReason := true,
    hasOwner := true,
    hasRemediation := true,
    hasReviewDate := true
    }

def pasteFinding : DependencyFinding :=
  {
    id := "RUSTSEC-2024-0436",
    package := "paste",
    version := "1.0.15",
    kind := "unmaintained"
  }

def validPasteWaiver : DependencyWaiver :=
  {
    id := "RUSTSEC-2024-0436",
    package := "paste",
    version := "1.0.15",
    kind := "unmaintained",
    notExpired := true,
    hasTracking := true,
    hasReason := true,
    hasOwner := true,
    hasRemediation := true,
    hasReviewDate := true
  }

def noFindingsNoWaivers : DependencyAuditInput :=
  {
    findings := [],
    waivers := []
  }

def exactWaiverInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [validBincodeWaiver]
  }

def unwaivedFindingInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := []
  }

def expiredWaiverInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with notExpired := false }]
  }

def kindMismatchInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with kind := "vulnerability" }]
  }

def missingReasonInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with hasReason := false }]
    }

def missingTrackingInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with hasTracking := false }]
  }

def missingOwnerInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with hasOwner := false }]
  }

def missingRemediationInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with hasRemediation := false }]
  }

def missingReviewDateInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with hasReviewDate := false }]
    }

def missingIdInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with id := "" }]
  }

def versionMismatchInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding],
    waivers := [{ validBincodeWaiver with version := "1.3.2" }]
  }

def multiFindingExactWaiversInput : DependencyAuditInput :=
  {
    findings := [bincodeFinding, pasteFinding],
    waivers := [validBincodeWaiver, validPasteWaiver]
  }

def invalidWaiverPrecedenceInput : DependencyAuditInput :=
  {
    findings := [
      {
        id := "RUSTSEC-2099-0001",
        package := "unknown",
        version := "0.0.0",
        kind := "vulnerability"
      }
    ],
    waivers := [{ validBincodeWaiver with hasTracking := false }]
  }

def unusedWaiverInput : DependencyAuditInput :=
  {
    findings := []
    waivers := [validBincodeWaiver]
  }

def unwaivedFindingPrecedesUnusedWaiverInput : DependencyAuditInput :=
  {
    findings := [
      {
        id := "RUSTSEC-2099-0001",
        package := "unknown",
        version := "0.0.0",
        kind := "vulnerability"
      }
    ],
    waivers := [validBincodeWaiver]
  }

theorem no_findings_no_waivers_accepts :
    evaluateDependencyAudit noFindingsNoWaivers = Except.ok () := by
  rfl

theorem exact_waiver_accepts :
    evaluateDependencyAudit exactWaiverInput = Except.ok () := by
  rfl

theorem unwaived_finding_rejects :
    evaluateDependencyAudit unwaivedFindingInput =
      Except.error DependencyAuditReject.unwaivedFinding := by
  rfl

theorem expired_waiver_rejects :
    evaluateDependencyAudit expiredWaiverInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem kind_mismatch_rejects :
    evaluateDependencyAudit kindMismatchInput =
      Except.error DependencyAuditReject.unwaivedFinding := by
  rfl

theorem missing_reason_rejects :
    evaluateDependencyAudit missingReasonInput =
      Except.error DependencyAuditReject.malformedWaiver := by
    rfl

theorem missing_tracking_rejects :
    evaluateDependencyAudit missingTrackingInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem missing_owner_rejects :
    evaluateDependencyAudit missingOwnerInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem missing_remediation_rejects :
    evaluateDependencyAudit missingRemediationInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem missing_review_date_rejects :
    evaluateDependencyAudit missingReviewDateInput =
      Except.error DependencyAuditReject.malformedWaiver := by
    rfl

theorem missing_id_rejects :
    evaluateDependencyAudit missingIdInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem version_mismatch_rejects :
    evaluateDependencyAudit versionMismatchInput =
      Except.error DependencyAuditReject.unwaivedFinding := by
  rfl

theorem multi_finding_exact_waivers_accepts :
    evaluateDependencyAudit multiFindingExactWaiversInput = Except.ok () := by
  rfl

theorem invalid_waiver_precedes_unwaived_finding :
    evaluateDependencyAudit invalidWaiverPrecedenceInput =
      Except.error DependencyAuditReject.malformedWaiver := by
  rfl

theorem unused_waiver_rejects :
    evaluateDependencyAudit unusedWaiverInput =
      Except.error DependencyAuditReject.unusedWaiver := by
  rfl

theorem unwaived_finding_precedes_unused_waiver :
    evaluateDependencyAudit unwaivedFindingPrecedesUnusedWaiverInput =
      Except.error DependencyAuditReject.unwaivedFinding := by
  rfl

end DependencyAuditPolicy
end Release
end Hegemon
