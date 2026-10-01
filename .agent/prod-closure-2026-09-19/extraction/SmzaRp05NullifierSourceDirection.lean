import SmzaRp05NullifierBinding
import SmzaRp05TypedRelation
import Hegemon.Transaction.Poseidon2Width16Kernel
import SmzaRp05NullifierSourceBase

/-! Internal source chunk SmzaRp05NullifierSourceDirection. Original declaration bodies and statements are retained. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex rawRowStart hashInitialIndex hashFinalIndex inputDirectionRow)
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

theorem accepted_direction_bit_boolean
    {components : RelationProgramComponents}
    (certificate : DirectionCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (bit : Fin 32) :
    packed.getD (rawIndex (inputDirectionRow input.val bit.val)) 0 = 0 ∨
      packed.getD (rawIndex (inputDirectionRow input.val bit.val)) 0 = 1 := by
  have laneAccepted := accepted.2.2.1 0 (by decide)
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      laneAccepted (certificate.member input bit)
  have rootBound := certificate.canonical.2 _ (certificate.member input bit)
  have refined := fieldAt_refines_source components.nonlinearExecutable
    publicWords (packedWitnessLaneRows packed 0) values
    certificate.canonical evaluated (certificate.root input bit) rootBound
  rw [fieldAt_of_realizes (certificate.realizes input bit)] at refined
  have valueZero : values.getD (certificate.root input bit) 0 = 0 := by
    simp [List.getD_eq_getElem?_getD, rootZero]
  have rowBound : inputDirectionRow input.val bit.val < relationRowCount := by
    have hi := input.isLt
    have hb := bit.isLt
    simp [inputDirectionRow, relationRowCount]
    omega
  have laneZeroMap :
      (packedWitnessLaneRows packed 0).getD (inputDirectionRow input.val bit.val) 0 =
        packed.getD (rawIndex (inputDirectionRow input.val bit.val)) 0 := by
    have laneReadback :
        (packedWitnessLaneRows packed 0).getD
            (inputDirectionRow input.val bit.val) 0 =
          packed.getD (inputDirectionRow input.val bit.val * packingFactor + 0) 0 := by
      rw [List.getD_eq_getElem _ _ (by
        simpa [packedWitnessLaneRows] using rowBound)]
      simp only [packedWitnessLaneRows, List.getElem_map, List.getElem_range]
    simpa [rawIndex, rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor] using laneReadback
  rw [valueZero] at refined
  have equation :
      (packed.getD (rawIndex (inputDirectionRow input.val bit.val)) 0 : Goldilocks) *
        ((packed.getD (rawIndex (inputDirectionRow input.val bit.val)) 0 : Goldilocks) - 1) =
          0 := by
    simp only [SourceTerm.eval] at refined
    rw [laneZeroMap] at refined
    simpa using refined
  rcases mul_eq_zero.mp equation with zero | one
  · left
    exact canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _) (by decide) zero
  · right
    exact canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _) (by decide) (sub_eq_zero.mp one)

theorem accepted_position_lt_32
    {components : RelationProgramComponents}
    (certificate : DirectionCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) :
    projectPosition packed input.val < 2 ^ 32 := by
  unfold projectPosition
  apply binary_natural_sum_bound
  intro bit bound
  obtain zero | one := accepted_direction_bit_boolean certificate accepted input
    ⟨bit, bound⟩
  · rw [directionWord, packedWord, zero]
    omega
  · rw [directionWord, packedWord, one]


end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
