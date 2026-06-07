namespace Hegemon
namespace Native
namespace ActionHashAdmission

inductive AdmissionReject where
  | actionCountMismatch
  | actionHashMismatch
  | duplicateActionHash
deriving DecidableEq, Repr

structure AdmissionInput where
  actionCountMatches : Bool
  actionHashesMatch : Bool
  actionHashesUnique : Bool
deriving DecidableEq, Repr

def evaluateAdmissionRejection (input : AdmissionInput) : Option AdmissionReject :=
  if input.actionCountMatches = false then
    some AdmissionReject.actionCountMismatch
  else if input.actionHashesMatch = false then
    some AdmissionReject.actionHashMismatch
  else if input.actionHashesUnique = false then
    some AdmissionReject.duplicateActionHash
  else
    none

def admissionAccepts (input : AdmissionInput) : Bool :=
  evaluateAdmissionRejection input = none

def admissionPreconditions (input : AdmissionInput) : Bool :=
  input.actionCountMatches && input.actionHashesMatch && input.actionHashesUnique

theorem accepts_iff_admission_preconditions
    {input : AdmissionInput} :
    admissionAccepts input = true ↔ admissionPreconditions input = true := by
  cases input with
  | mk actionCountMatches actionHashesMatch actionHashesUnique =>
      cases actionCountMatches <;>
        cases actionHashesMatch <;>
        cases actionHashesUnique <;>
        simp [
          admissionAccepts,
          admissionPreconditions,
          evaluateAdmissionRejection
        ]

def valid : AdmissionInput :=
  {
    actionCountMatches := true,
    actionHashesMatch := true,
    actionHashesUnique := true
  }

theorem valid_accepts :
    evaluateAdmissionRejection valid = none := by
  rfl

theorem action_count_mismatch_rejects
    {input : AdmissionInput}
    (countMismatch : input.actionCountMatches = false) :
    evaluateAdmissionRejection input =
      some AdmissionReject.actionCountMismatch := by
  unfold evaluateAdmissionRejection
  simp [countMismatch]

theorem action_hash_mismatch_rejects
    {input : AdmissionInput}
    (countMatches : input.actionCountMatches = true)
    (hashMismatch : input.actionHashesMatch = false) :
    evaluateAdmissionRejection input =
      some AdmissionReject.actionHashMismatch := by
  unfold evaluateAdmissionRejection
  simp [countMatches, hashMismatch]

theorem duplicate_action_hash_rejects
    {input : AdmissionInput}
    (countMatches : input.actionCountMatches = true)
    (hashesMatch : input.actionHashesMatch = true)
    (notUnique : input.actionHashesUnique = false) :
    evaluateAdmissionRejection input =
      some AdmissionReject.duplicateActionHash := by
  unfold evaluateAdmissionRejection
  simp [countMatches, hashesMatch, notUnique]

theorem hash_mismatch_precedes_duplicate
    {input : AdmissionInput}
    (countMatches : input.actionCountMatches = true)
    (hashMismatch : input.actionHashesMatch = false) :
    evaluateAdmissionRejection input =
      some AdmissionReject.actionHashMismatch := by
  unfold evaluateAdmissionRejection
  simp [countMatches, hashMismatch]

end ActionHashAdmission
end Native
end Hegemon
