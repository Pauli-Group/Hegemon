import SmzaRp05SingleKeyPrfSourceCertificate
import SmzaRp05SingleKeyPrfSourceData
import SmzaRp05AuthSourceBridge
import SmzaRp05TypedRelation
import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Accepted-run corollaries of the checked split SingleKey PRF source
certificate. Poseidon permutation refinement remains a separate theorem. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.SmzaRp05AuthSourceBridge
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem traceNodeValue
    {components : RelationProgramComponents}
    (canonical : ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions = some values)
    {node : Nat} {term : SourceTerm}
    (realizes : Realizes components.csrExpressions node term) :
    (values.getD node 0 : Goldilocks) =
      term.eval (fun i => (publicWords.getD i 0 : Goldilocks)) (fun _ => 0) := by
  have source := fieldAt_refines_source
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values canonical evaluated node (by
      induction realizes with
      | constant found => exact (List.getElem?_eq_some_iff.mp found).1
      | publicInput found => exact (List.getElem?_eq_some_iff.mp found).1
      | witness found => exact (List.getElem?_eq_some_iff.mp found).1
      | add found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
      | sub found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1
      | mul found _ _ _ _ _ _ => exact (List.getElem?_eq_some_iff.mp found).1)
  rw [fieldAt_of_realizes realizes] at source
  simpa using source.symm

private theorem coefficientValues
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions = some values) :
    (values.getD 0 0 : Goldilocks) = 0 ∧
    (values.getD 1 0 : Goldilocks) = 1 ∧
    (values.getD 3 0 : Goldilocks) = -1 ∧
    (values.getD 160 0 : Goldilocks) = -1 := by
  constructor
  · simpa [SourceTerm.eval] using traceNodeValue certificate.canonical evaluated
      certificate.zeroRealizes
  constructor
  · simpa [SourceTerm.eval] using traceNodeValue certificate.canonical evaluated
      certificate.oneRealizes
  constructor
  · have literal := traceNodeValue certificate.canonical evaluated
      certificate.literalMinusOneRealizes
    have castMinusOne : (18446744069414584320 : Goldilocks) = -1 := by decide
    simpa [SourceTerm.eval, castMinusOne] using literal
  · simpa [SourceTerm.eval] using traceNodeValue certificate.canonical evaluated
      certificate.derivedMinusOneRealizes

private theorem hashInitial0_index (lane : Nat) :
    hashInitialIndex 0 lane = 18112 + 64 * lane := by
  simp [hashInitialIndex, Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart]
  omega

private theorem hashFinal0_index (lane : Nat) :
    hashFinalIndex 0 lane = 28736 + 64 * lane := by
  simp [hashFinalIndex, Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalRowOffset]
  omega

/-- The accepted CSR trace fixes call 0's input: the five words of global
key row 227, two zero pads, and the exact source domain/frame cells. -/
theorem accepted_call0_initial_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (lane : Fin 16) :
    (packed.getD (hashInitialIndex 0 lane.val) 0 : Goldilocks) =
      if lane.val < 5 then
        (packed.getD (227 * 64 + lane.val) 0 : Goldilocks)
      else if lane.val < 8 then 0 else (initialExpected lane : Goldilocks) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have coeff := coefficientValues certificate evaluated
  have target := traceNodeValue certificate.canonical evaluated
    (certificate.initialTargetRealizes lane)
  have targetEq : (values.getD (initialTarget lane) 0 : Goldilocks) =
      (initialExpected lane : Goldilocks) := by
    simpa [SourceTerm.eval] using target
  have equation := accepted_csr_attempt_field_equality
    (attempts (initialAttempt lane) (certificate.initialMember lane))
  have one := coeff.2.1
  have keyMinusOne := coeff.2.2.2
  by_cases keyLane : lane.val < 5
  · simp only [initialAttempt, if_pos keyLane] at equation
    simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
      List.sum_nil, one, one_mul, keyMinusOne, targetEq] at equation
    have expectedZero : (initialExpected lane : Goldilocks) = 0 := by
      have ne8 : lane.val ≠ 8 := by omega
      have ne9 : lane.val ≠ 9 := by omega
      have ne10 : lane.val ≠ 10 := by omega
      have ne11 : lane.val ≠ 11 := by omega
      have ne15 : lane.val ≠ 15 := by omega
      simp [initialExpected, ne8, ne9, ne10, ne11, ne15]
    rw [expectedZero] at equation
    have fieldEq :
        (packed.getD (hashInitialIndex 0 lane.val) 0 : Goldilocks) =
          (packed.getD (227 * 64 + lane.val) 0 : Goldilocks) := by
      rw [hashInitial0_index]
      linear_combination equation
    simpa [keyLane] using fieldEq
  · simp only [initialAttempt, if_neg (by omega)] at equation
    simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
      List.sum_nil, one, one_mul, targetEq] at equation
    rw [hashInitial0_index]
    by_cases padLane : lane.val < 8
    · have expectedZero : (initialExpected lane : Goldilocks) = 0 := by
        have ne8 : lane.val ≠ 8 := by omega
        have ne9 : lane.val ≠ 9 := by omega
        have ne10 : lane.val ≠ 10 := by omega
        have ne11 : lane.val ≠ 11 := by omega
        have ne15 : lane.val ≠ 15 := by omega
        simp [initialExpected, ne8, ne9, ne10, ne11, ne15]
      rw [expectedZero] at equation
      simp only [if_neg (by omega), if_pos padLane] at equation ⊢
      simpa only [add_zero] using equation
    · simpa only [if_neg keyLane, if_neg padLane, add_zero] using equation

/-- Lift the five input-key equalities to canonical natural packed words. -/
theorem accepted_call0_global_key_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (limb : Fin 5) :
    packed.getD (hashInitialIndex 0 limb.val) 0 =
      packed.getD (227 * 64 + limb.val) 0 := by
  have fieldEquality := accepted_call0_initial_word accepted
    (⟨limb.val, by omega⟩ : Fin 16)
  have fieldEqualityNat :
      (packed.getD (hashInitialIndex 0 limb.val) 0 : Goldilocks) =
        (packed.getD (227 * 64 + limb.val) 0 : Goldilocks) := by
    simpa using fieldEquality
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (hashInitialIndex 0 limb.val))
    (packed_word_canonical accepted.2.1 (227 * 64 + limb.val))
    fieldEqualityNat

/-- The accepted call-0 output is copied word-for-word into legacy auth. -/
theorem accepted_legacy_digest_word
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (limb : Fin 7) :
    packed.getD (106 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 0 limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have coeff := coefficientValues certificate evaluated
  have equation := accepted_csr_attempt_field_equality
    (attempts (legacyAttempt limb) (certificate.legacyMember limb))
  have one := coeff.2.1
  have zero := coeff.1
  have minusOne := coeff.2.2.1
  simp only [legacyAttempt] at equation
  simp only [csrFieldSum, List.map_cons, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, one_mul, minusOne, zero] at equation
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (106 * 64 + limb.val))
    (packed_word_canonical accepted.2.1 (hashFinalIndex 0 limb.val))
  simp only [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
    hashFinal0_index]
  linear_combination equation

/-- The strongest source-only composition licensed by these 23 attempts:
the five-word global key and two zero words are call-0 input, and the full
seven-word call-0 output is the legacy digest. The call-0 permutation itself
is established by the separate accepted-hash recurrence theorem. -/
theorem accepted_legacy_digest_source_binding
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    (∀ limb : Fin 5,
      packed.getD (hashInitialIndex 0 limb.val) 0 =
        packed.getD (227 * 64 + limb.val) 0) ∧
    (∀ limb : Fin 2,
      (packed.getD (hashInitialIndex 0 (5 + limb.val)) 0 : Goldilocks) = 0) ∧
    (∀ limb : Fin 7,
      packed.getD (106 * 64 + limb.val) 0 =
        packed.getD (hashFinalIndex 0 limb.val) 0) := by
  refine ⟨?_, ?_, ?_⟩
  · exact fun limb => accepted_call0_global_key_word accepted limb
  · intro limb
    have initial := accepted_call0_initial_word accepted
      (⟨5 + limb.val, by omega⟩ : Fin 16)
    have notKey : ¬ 5 + limb.val < 5 := by omega
    have pad : 5 + limb.val < 8 := by omega
    simpa [notKey, pad] using initial
  · exact fun limb => accepted_legacy_digest_word accepted limb

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate
