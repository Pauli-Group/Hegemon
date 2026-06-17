namespace Hegemon
namespace Transaction
namespace SmallWoodCandidateWrapperAdmission

inductive WrapperKind where
  | current
  | legacy
deriving DecidableEq, Repr

inductive WrapperReject where
  | noCanonicalWrapper
  | missingArkProofBytes
deriving DecidableEq, Repr

structure DecodeAttempt where
  decodeOk : Bool
  exactConsumption : Bool
  canonicalReencode : Bool
  arkProofBytesPresent : Bool
deriving DecidableEq, Repr

structure WrapperAdmissionInput where
  current : DecodeAttempt
  legacy : DecodeAttempt
deriving DecidableEq, Repr

def canonicalWrapperAdmits (attempt : DecodeAttempt) : Bool :=
  attempt.decodeOk && attempt.exactConsumption && attempt.canonicalReencode

def selectedWrapperKind (input : WrapperAdmissionInput) : Option WrapperKind :=
  if canonicalWrapperAdmits input.current then
    some WrapperKind.current
  else if canonicalWrapperAdmits input.legacy then
    some WrapperKind.legacy
  else
    none

def evaluateWrapperRejection (input : WrapperAdmissionInput) :
    Option WrapperReject :=
  match selectedWrapperKind input with
  | none => some WrapperReject.noCanonicalWrapper
  | some WrapperKind.current =>
      if input.current.arkProofBytesPresent then
        none
      else
        some WrapperReject.missingArkProofBytes
  | some WrapperKind.legacy =>
      if input.legacy.arkProofBytesPresent then
        none
      else
        some WrapperReject.missingArkProofBytes

def wrapperAccepts (input : WrapperAdmissionInput) : Bool :=
  evaluateWrapperRejection input = none

def acceptedCurrentWrapperSurface (input : WrapperAdmissionInput) : Prop :=
  canonicalWrapperAdmits input.current = true
    ∧ input.current.arkProofBytesPresent = true
    ∧ selectedWrapperKind input = some WrapperKind.current

def acceptedLegacyWrapperSurface (input : WrapperAdmissionInput) : Prop :=
  canonicalWrapperAdmits input.current = false
    ∧ canonicalWrapperAdmits input.legacy = true
    ∧ input.legacy.arkProofBytesPresent = true
    ∧ selectedWrapperKind input = some WrapperKind.legacy

theorem wrapper_accepts_iff_selected_canonical_nonempty
    {input : WrapperAdmissionInput} :
    wrapperAccepts input = true ↔
      (canonicalWrapperAdmits input.current = true
        ∧ input.current.arkProofBytesPresent = true)
      ∨ (canonicalWrapperAdmits input.current = false
        ∧ canonicalWrapperAdmits input.legacy = true
        ∧ input.legacy.arkProofBytesPresent = true) := by
  unfold wrapperAccepts evaluateWrapperRejection selectedWrapperKind
  by_cases hCurrent : canonicalWrapperAdmits input.current
  · cases input.current.arkProofBytesPresent <;> simp [hCurrent]
  · by_cases hLegacy : canonicalWrapperAdmits input.legacy
    · cases input.legacy.arkProofBytesPresent <;> simp [hCurrent, hLegacy]
    · simp [hCurrent, hLegacy]

theorem current_wrapper_selected_precedes_legacy
    {input : WrapperAdmissionInput}
    (selected : selectedWrapperKind input = some WrapperKind.current) :
    canonicalWrapperAdmits input.current = true := by
  unfold selectedWrapperKind at selected
  cases hCurrent : canonicalWrapperAdmits input.current
  · simp [hCurrent] at selected
  · rfl

theorem legacy_wrapper_selected_requires_current_rejected
    {input : WrapperAdmissionInput}
    (selected : selectedWrapperKind input = some WrapperKind.legacy) :
    canonicalWrapperAdmits input.current = false
      ∧ canonicalWrapperAdmits input.legacy = true := by
  unfold selectedWrapperKind at selected
  cases hCurrent : canonicalWrapperAdmits input.current
  · cases hLegacy : canonicalWrapperAdmits input.legacy
    · simp [hCurrent, hLegacy] at selected
    · exact ⟨rfl, rfl⟩
  · simp [hCurrent] at selected

theorem accepted_current_wrapper_exposes_surface
    {input : WrapperAdmissionInput}
    (selected : selectedWrapperKind input = some WrapperKind.current)
    (accepted : wrapperAccepts input = true) :
    acceptedCurrentWrapperSurface input := by
  have hCurrent := current_wrapper_selected_precedes_legacy selected
  unfold wrapperAccepts evaluateWrapperRejection at accepted
  simp [selected] at accepted
  exact ⟨hCurrent, accepted, selected⟩

theorem accepted_legacy_wrapper_exposes_surface
    {input : WrapperAdmissionInput}
    (selected : selectedWrapperKind input = some WrapperKind.legacy)
    (accepted : wrapperAccepts input = true) :
    acceptedLegacyWrapperSurface input := by
  have hSelected := legacy_wrapper_selected_requires_current_rejected selected
  rcases hSelected with ⟨hCurrent, hLegacy⟩
  unfold wrapperAccepts evaluateWrapperRejection at accepted
  simp [selected] at accepted
  exact ⟨hCurrent, hLegacy, accepted, selected⟩

def validCurrentWrapper : WrapperAdmissionInput :=
  { current :=
      { decodeOk := true
        exactConsumption := true
        canonicalReencode := true
        arkProofBytesPresent := true }
    legacy :=
      { decodeOk := false
        exactConsumption := false
        canonicalReencode := false
        arkProofBytesPresent := false } }

def validLegacyWrapper : WrapperAdmissionInput :=
  { current :=
      { decodeOk := false
        exactConsumption := false
        canonicalReencode := false
        arkProofBytesPresent := false }
    legacy :=
      { decodeOk := true
        exactConsumption := true
        canonicalReencode := true
        arkProofBytesPresent := true } }

theorem valid_current_wrapper_accepts :
    evaluateWrapperRejection validCurrentWrapper = none := by
  decide

theorem valid_legacy_wrapper_accepts :
    evaluateWrapperRejection validLegacyWrapper = none := by
  decide

theorem current_empty_ark_rejects_before_legacy :
    evaluateWrapperRejection
      { validCurrentWrapper with
        current := { validCurrentWrapper.current with arkProofBytesPresent := false },
        legacy := validLegacyWrapper.legacy } =
      some WrapperReject.missingArkProofBytes := by
  decide

theorem legacy_empty_ark_rejects :
    evaluateWrapperRejection
      { validLegacyWrapper with
        legacy := { validLegacyWrapper.legacy with arkProofBytesPresent := false } } =
      some WrapperReject.missingArkProofBytes := by
  decide

theorem no_canonical_wrapper_rejects :
    evaluateWrapperRejection
      { validCurrentWrapper with
        current := { validCurrentWrapper.current with exactConsumption := false },
        legacy := { validLegacyWrapper.legacy with decodeOk := false } } =
      some WrapperReject.noCanonicalWrapper := by
  decide

end SmallWoodCandidateWrapperAdmission
end Transaction
end Hegemon
