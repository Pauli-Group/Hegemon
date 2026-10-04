import SmzaRp05MerkleFrameCertificate
import HegemonCrypto.Poseidon2V8ExpressionRootSemantics

/-!
# RP05 accepted orientation gate

The seven checked nonlinear roots are a compact description of all 448
oriented Merkle limbs: lane `slot % 64` selects one limb from the source row
group `slot / 64`.  This theorem consumes only finite source syntax and
actual RP05 packed acceptance; it does not import RP03 acceptance.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05MerkleOrientation

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.SmzaRp05MerkleFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false

private theorem packed_inline_row (packed : List Nat)
    {step limb component : Nat} (stepBound : step < 64)
    (limbBound : limb < 7) (componentBound : component < 4) :
    (packedWitnessLaneRows packed ((step * 7 + limb) % 64)).getD
        (252 + 4 * ((step * 7 + limb) / 64) + component) 0 =
      packed.getD (inlineIndex step limb component) 0 := by
  have groupBound : (step * 7 + limb) / 64 < 7 := by omega
  have rowBound : 252 + 4 * ((step * 7 + limb) / 64) + component <
      relationRowCount := by
    simp only [relationRowCount]
    omega
  simp [packedWitnessLaneRows, inlineIndex, rowBound, packingFactor,
    List.getD_eq_getElem?_getD]

/-- The exact current nonlinear gate enforces `current = left + bit*(right-left)`
for every Merkle step and digest limb. This is a field equality; the following
selected-side theorem will use the current Boolean direction certificate to
lift it to canonical natural-word equality. -/
theorem accepted_orientation_field
    {components : RelationProgramComponents}
    (certificate : OrientationCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    (packed.getD (inlineIndex step limb 0) 0 : Goldilocks) =
      (packed.getD (inlineIndex step limb 1) 0 : Goldilocks) +
        (packed.getD (inlineIndex step limb 3) 0 : Goldilocks) *
          ((packed.getD (inlineIndex step limb 2) 0 : Goldilocks) -
            (packed.getD (inlineIndex step limb 1) 0 : Goldilocks)) := by
  let slot := step * 7 + limb
  let group : Fin 7 := ⟨slot / 64, by dsimp [slot]; omega⟩
  let lane := slot % 64
  have laneBound : lane < packingFactor := by
    dsimp [lane, packingFactor]
    omega
  obtain ⟨values, evaluated, rootZero⟩ :=
    HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted_packed_program_checks_every_nonlinear_lane accepted laneBound)
      (certificate.member group)
  have source := fieldAt_refines_source components.nonlinearExecutable
    publicWords (packedWitnessLaneRows packed lane) values certificate.canonical
    evaluated (certificate.root group)
    (realizes_bound (certificate.realizes group))
  rw [fieldAt_of_realizes (certificate.realizes group)] at source
  have rootField :
      SourceTerm.eval
        (fun index => (publicWords.getD index 0 : Goldilocks))
        (fun row => ((packedWitnessLaneRows packed lane).getD row 0 : Goldilocks))
        (.sub (.witness (252 + 4 * group.val))
          (.add (.witness (253 + 4 * group.val))
            (.mul (.witness (255 + 4 * group.val))
              (.sub (.witness (254 + 4 * group.val))
                (.witness (253 + 4 * group.val)))))) = 0 := by
    have rootValueZero :
        (values.getD (certificate.root group) 0 : Goldilocks) = 0 := by
      simp only [List.getD_eq_getElem?_getD, rootZero,
        Option.getD_some, Nat.cast_zero]
    exact source.trans rootValueZero
  have row (component : Fin 4) :
      (packedWitnessLaneRows packed lane).getD
          (252 + 4 * group.val + component.val) 0 =
        packed.getD (inlineIndex step limb component.val) 0 := by
    exact packed_inline_row packed stepBound limbBound component.isLt
  have current := row ⟨0, by decide⟩
  have left := row ⟨1, by decide⟩
  have right := row ⟨2, by decide⟩
  have direction := row ⟨3, by decide⟩
  simp only [SourceTerm.eval] at rootField
  simp only [Nat.add_zero] at current
  have oneIndex : 253 + 4 * group.val = 252 + 4 * group.val + 1 := by omega
  have twoIndex : 254 + 4 * group.val = 252 + 4 * group.val + 2 := by omega
  have threeIndex : 255 + 4 * group.val = 252 + 4 * group.val + 3 := by omega
  rw [oneIndex, twoIndex, threeIndex, current, left, right, direction] at rootField
  exact sub_eq_zero.mp rootField

/-- Canonical selected-side equality; the Boolean bit is independently
certified by the RP05 direction roots, while family18 copies that exact bit
into each of the seven orientation gates. -/
theorem accepted_selected_current
    {components : RelationProgramComponents}
    (frame : FrameCertificate components)
    (orientation : OrientationCertificate components)
    (directions : HegemonCrypto.SmallWood.SmzaRp05NullifierSource.DirectionCertificate
      components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    packed.getD (inlineIndex step limb 0) 0 =
      packed.getD
        (inlineIndex step limb
          (if packed.getD (directionIndex step) 0 = 0 then 1 else 2)) 0 := by
  have directionCopy := accepted_direction_copy frame accepted
    (⟨step, stepBound⟩, ⟨limb, limbBound⟩)
  have orientationField := accepted_orientation_field orientation accepted
    stepBound limbBound
  rw [directionCopy] at orientationField
  have inputBound : step / 32 < 2 := by omega
  have bitBound : step % 32 < 32 := Nat.mod_lt _ (by decide)
  rcases HegemonCrypto.SmallWood.SmzaRp05NullifierSource.accepted_direction_bit_boolean
      directions accepted ⟨step / 32, inputBound⟩
        ⟨step % 32, bitBound⟩ with zero | one
  · have bit : packed.getD (directionIndex step) 0 = 0 := by
      simpa [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
        HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
        directionIndex] using zero
    rw [bit, Nat.cast_zero, zero_mul, add_zero] at orientationField
    rw [if_pos bit]
    exact canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _) orientationField
  · have bit : packed.getD (directionIndex step) 0 = 1 := by
      simpa [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.directionWord,
        HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
        directionIndex] using one
    rw [bit, Nat.cast_one, one_mul] at orientationField
    rw [if_neg (by omega)]
    apply canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _)
    simp only [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord]
    linear_combination orientationField

end HegemonCrypto.SmallWood.SmzaRp05MerkleOrientation
