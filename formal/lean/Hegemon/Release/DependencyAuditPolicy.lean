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
deriving DecidableEq, Repr

structure DependencyAuditInput where
  findings : List DependencyFinding
  waivers : List DependencyWaiver
deriving DecidableEq, Repr

def stringNonEmpty (value : String) : Bool :=
  value != ""

def waiverHasRequiredFields (waiver : DependencyWaiver) : Bool :=
  stringNonEmpty waiver.id
    && stringNonEmpty waiver.package
    && stringNonEmpty waiver.version
    && stringNonEmpty waiver.kind
    && waiver.hasTracking
    && waiver.hasReason

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
    hasReason := true
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
