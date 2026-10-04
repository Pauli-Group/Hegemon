import SmzaRp05NoteFrameCertificate

/-! Actual RP05 acceptance supplies the exact field equation for each of
the 78 emitted input-note source, padding, and capacity cells. The 11 private
absorbed words have no emitted copy cell and are deliberately not zeroed. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NoteFrameSource

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false

theorem accepted_cell_field
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : NoteCell) (bound : boundCell cell) :
    (packed.getD
        (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val) 0 :
        Goldilocks) -
      (if cell.2.1.val = 0 then 0 else
        (packed.getD
          (hashFinalIndex (noteCall cell.1 + cell.2.1.val - 1)
            cell.2.2.val) 0 : Goldilocks)) -
      (match sourceIndex cell with
        | none => 0
        | some index => (packed.getD index 0 : Goldilocks)) =
      (expectedConstant cell : Goldilocks) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD 1 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.one
  have negative : (values.getD 160 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated certificate.negative
  have target :
      (values.getD (expectedTarget cell) 0 : Goldilocks) =
        (expectedConstant cell : Goldilocks) := by
    simpa [SourceTerm.eval] using
      csr_node_value certificate.canonical evaluated
        (certificate.target cell)
  have oneOption : ((values[1]?.getD 0 : Nat) : Goldilocks) = 1 := by
    simpa only [List.getD_eq_getElem?_getD] using one
  have negativeOption : ((values[160]?.getD 0 : Nat) : Goldilocks) = -1 := by
    simpa only [List.getD_eq_getElem?_getD] using negative
  have targetOption :
      ((values[expectedTarget cell]?.getD 0 : Nat) : Goldilocks) =
        (expectedConstant cell : Goldilocks) := by
    simpa only [List.getD_eq_getElem?_getD] using target
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (certificate.member cell bound))
  rw [certificate.exactTerms cell bound,
    certificate.exactTarget cell bound] at equation
  by_cases first : cell.2.1.val = 0
  · cases source : sourceIndex cell with
    | none =>
        simp [expectedTerms, first, source, csrFieldSum,
          oneOption, targetOption] at equation
        simpa [first, source, sub_eq_add_neg] using equation
    | some index =>
        simp [expectedTerms, first, source, csrFieldSum,
          oneOption, negativeOption, targetOption] at equation
        simpa [first, source, sub_eq_add_neg, add_assoc] using equation
  · cases source : sourceIndex cell with
    | none =>
        simp [expectedTerms, first, source, csrFieldSum,
          oneOption, negativeOption, targetOption] at equation
        simpa [first, source, sub_eq_add_neg, add_assoc] using equation
    | some index =>
        simp [expectedTerms, first, source, csrFieldSum,
          oneOption, negativeOption, targetOption] at equation
        simpa [first, source, sub_eq_add_neg, add_assoc] using equation

theorem expected_constant_canonical (cell : NoteCell) :
    expectedConstant cell <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  unfold expectedConstant noteConstant
  split_ifs <;> decide

/-- All source-free emitted cells (capacity and final-block padding) have
the exact sponge control value. This never applies to private rate cells. -/
theorem accepted_no_source_cell
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : NoteCell) (bound : boundCell cell)
    (noSource : sourceIndex cell = none) :
    packed.getD
        (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val) 0 =
      if cell.2.1.val = 0 then expectedConstant cell
      else fieldAdd
        (packed.getD
          (hashFinalIndex (noteCall cell.1 + cell.2.1.val - 1)
            cell.2.2.val) 0)
        (expectedConstant cell) := by
  have equation := accepted_cell_field certificate accepted cell bound
  rw [noSource] at equation
  simp only at equation
  have initialBound := packed_word_canonical accepted.2.1
    (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val)
  by_cases first : cell.2.1.val = 0
  · rw [if_pos first]
    have fieldEq :
        (packed.getD
          (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val) 0 : Goldilocks) =
          (expectedConstant cell : Goldilocks) := by
      simpa [first, List.getD_eq_getElem?_getD] using equation
    exact canonical_nat_cast_injective initialBound
      (expected_constant_canonical cell) fieldEq
  · rw [if_neg first]
    simp [first] at equation
    have equationGetD :
        (packed.getD
          (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val) 0 : Goldilocks) -
          (packed.getD
            (hashFinalIndex (noteCall cell.1 + cell.2.1.val - 1)
              cell.2.2.val) 0 : Goldilocks) =
          (expectedConstant cell : Goldilocks) := by
      simpa only [List.getD_eq_getElem?_getD] using equation
    have fieldEq :
        (packed.getD
          (hashInitialIndex (noteCall cell.1 + cell.2.1.val) cell.2.2.val) 0 : Goldilocks) =
          (fieldAdd
            (packed.getD
              (hashFinalIndex (noteCall cell.1 + cell.2.1.val - 1)
                cell.2.2.val) 0)
            (expectedConstant cell) : Goldilocks) := by
      rw [field_add_cast]
      linear_combination equationGetD
    exact canonical_nat_cast_injective initialBound
      (Nat.mod_lt _ (by decide)) fieldEq

end HegemonCrypto.SmallWood.SmzaRp05NoteFrameSource
