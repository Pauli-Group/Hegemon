import HegemonCrypto.SmallWoodV8Smz9AuthorizationDigestCopies
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorizationNonSingle
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationHashBindings

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt FieldExpression packedWitnessLaneRows)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

private theorem csr36_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ V8Smz9ProgramCanonicalityCsr36.chunkList)
    (entryMem : entry ∈ chunk) : entry ∈ exactCsrAttempts := by
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  apply List.mem_flatten_of_mem _ entryMem
  unfold V8Smz9ProgramCanonicalityGenerated.csrChunks000
    V8Smz9ProgramCanonicalityGenerated.csrChunks001
    V8Smz9ProgramCanonicalityGenerated.csrChunks002
    V8Smz9ProgramCanonicalityGenerated.csrChunks003
    V8Smz9ProgramCanonicalityGenerated.csrChunks004
    V8Smz9ProgramCanonicalityGenerated.csrChunks005
    V8Smz9ProgramCanonicalityGenerated.csrChunks006
    V8Smz9ProgramCanonicalityGenerated.csrChunks007
    V8Smz9ProgramCanonicalityGenerated.csrChunks008
    V8Smz9ProgramCanonicalityGenerated.csrChunks009
    V8Smz9ProgramCanonicalityGenerated.csrChunks010
    V8Smz9ProgramCanonicalityGenerated.csrChunks011
    V8Smz9ProgramCanonicalityGenerated.csrChunks012
    V8Smz9ProgramCanonicalityGenerated.csrChunks013
    V8Smz9ProgramCanonicalityGenerated.csrChunks014
    V8Smz9ProgramCanonicalityGenerated.csrChunks015
    V8Smz9ProgramCanonicalityGenerated.csrChunks016
    V8Smz9ProgramCanonicalityGenerated.csrChunks017
    V8Smz9ProgramCanonicalityGenerated.csrChunks018
    V8Smz9ProgramCanonicalityGenerated.csrChunks019
    V8Smz9ProgramCanonicalityGenerated.csrChunks020
    V8Smz9ProgramCanonicalityGenerated.csrChunks021
    V8Smz9ProgramCanonicalityGenerated.csrChunks022
    V8Smz9ProgramCanonicalityGenerated.csrChunks023
    V8Smz9ProgramCanonicalityGenerated.csrChunks024
    V8Smz9ProgramCanonicalityGenerated.csrChunks025
    V8Smz9ProgramCanonicalityGenerated.csrChunks026
    V8Smz9ProgramCanonicalityGenerated.csrChunks027
    V8Smz9ProgramCanonicalityGenerated.csrChunks028
    V8Smz9ProgramCanonicalityGenerated.csrChunks029
    V8Smz9ProgramCanonicalityGenerated.csrChunks030
    V8Smz9ProgramCanonicalityGenerated.csrChunks031
    V8Smz9ProgramCanonicalityGenerated.csrChunks032
    V8Smz9ProgramCanonicalityGenerated.csrChunks033
    V8Smz9ProgramCanonicalityGenerated.csrChunks034
    V8Smz9ProgramCanonicalityGenerated.csrChunks035
    V8Smz9ProgramCanonicalityGenerated.csrChunks036
  simp only [List.mem_append]
  aesop

def policyHashBridgeAttempt (limb kind : Nat) : CsrExecutableAttempt :=
  attempt (18779 + 3 * limb + kind) 27 (3 * limb + kind) 0
    (if kind = 0 then [(17920 + limb, 1), (rawIndex (138 + limb), 158)]
    else if kind = 1 then [(17984 + limb, 1), (hashFinalIndex 97 limb, 158)]
    else [(18048 + limb, 1), (rawIndex 93, 158), (rawIndex 94, 158)]) 0

theorem policy_hash_bridge_source (limb : Fin 7) (kind : Fin 3) :
    policyHashBridgeAttempt limb.val kind.val ∈ exactCsrAttempts := by
  have checked : ∀ limb : Fin 7, ∀ kind : Fin 3,
      policyHashBridgeAttempt limb.val kind.val ∈ V8Smz9ProgramCanonicalityCsr36.chunk010 ∨
      policyHashBridgeAttempt limb.val kind.val ∈ V8Smz9ProgramCanonicalityCsr36.chunk011 := by decide
  rcases checked limb kind with first | second
  · exact csr36_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr36.chunkList]) first
  · exact csr36_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr36.chunkList]) second

theorem accepted_policy_hash_bridge {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (limb : Fin 7) :
    (packedWord packed (17920 + limb.val) : F) = (authorizationRawWord packed (138 + limb.val) : F) ∧
    (packedWord packed (17984 + limb.val) : F) = (packedWord packed (hashFinalIndex 97 limb.val) : F) ∧
    (packedWord packed (18048 + limb.val) : F) =
      (authorizationWord packed 1 : F) + (authorizationWord packed 2 : F) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have first := accepted_csr_attempt_field_equality (attempts _ (policy_hash_bridge_source limb ⟨0, by decide⟩))
  have second := accepted_csr_attempt_field_equality (attempts _ (policy_hash_bridge_source limb ⟨1, by decide⟩))
  have third := accepted_csr_attempt_field_equality (attempts _ (policy_hash_bridge_source limb ⟨2, by decide⟩))
  simp only [policyHashBridgeAttempt, attempt, Nat.one_ne_zero, show (2 : Nat) ≠ 0 by decide,
    show (2 : Nat) ≠ 1 by decide, if_true, if_false, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    one, zero, negative, one_mul, neg_one_mul, add_zero] at first second third
  simp only [rawIndex, Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] at first second third
  change (packedWord packed (17920 + limb.val) : F) + -(authorizationRawWord packed (138 + limb.val) : F) = 0 at first
  change (packedWord packed (17984 + limb.val) : F) + -(packedWord packed (hashFinalIndex 97 limb.val) : F) = 0 at second
  change (packedWord packed (18048 + limb.val) : F) +
    (-(authorizationWord packed 1 : F) + -(authorizationWord packed 2 : F)) = 0 at third
  refine ⟨?_, ?_, ?_⟩
  · linear_combination first
  · linear_combination second
  · linear_combination third

private theorem lane_row_word (packed : List Nat) (lane row : Nat) (bound : row < 686) :
    (packedWitnessLaneRows packed lane).getD row 0 = packedWord packed (row * 64 + lane) := by
  simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound, packedWord,
    Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor]

/-- Family27 fills the three actual nonlinear bridge rows; root1233 is applied
at each digest limb's packed lane, with the accepted non-single mode sum one. -/
theorem accepted_non_single_policy_hash_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) (limb : Fin 7) :
    authorizationRawWord packed (138 + limb.val) = packedWord packed (hashFinalIndex 97 limb.val) := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := limb.val) (root := 1233) (by have := limb.isLt; omega) (by decide)
  have left := equations 404 (.witnessRow 280) (by decide)
  have right := equations 405 (.witnessRow 281) (by decide)
  have gate := equations 406 (.witnessRow 282) (by decide)
  have difference := equations 1232 (.sub 404 405) (by decide)
  have root := equations 1233 (.mul 406 1232) (by decide)
  simp only [expressionField, lane_row_word packed limb.val 280 (by decide),
    lane_row_word packed limb.val 281 (by decide), lane_row_word packed limb.val 282 (by decide),
    Nat.reduceMul] at left right gate difference root
  have bridge := accepted_policy_hash_bridge accepted limb
  have sum := congrArg (fun word : Nat => (word : F)) (accepted_non_single_mode_sum accepted mode)
  simp only [Nat.cast_add, Nat.cast_one] at sum
  rw [rootZero, gate, difference, left, right, bridge.1, bridge.2.1, bridge.2.2, sum, one_mul] at root
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp root.symm)

theorem accepted_non_single_current_policy_hash {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    (projectAuthorization packed).current.policyRoot = (packedFinalState packed 97).take digestWords := by
  apply List.ext_getElem
  · simp [projectAuthorization, projectAccumulator, packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have bound : limb < 7 := by simpa [projectAuthorization, projectAccumulator] using leftBound
    simp only [projectAuthorization, projectAccumulator, packedFinalState,
      List.getElem_map, List.getElem_range, List.getElem_take]
    exact (accepted_current_opening_source_word accepted (by omega : limb < 23)).trans
      (accepted_non_single_policy_hash_word accepted mode ⟨limb, bound⟩)

def actionHashCopyAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (18708 + limb) 25 limb 0 [(rawIndex (131 + limb), 1), (hashFinalIndex 93 limb, 3)] 0

theorem action_hash_copy_source (limb : Fin 7) : actionHashCopyAttempt limb.val ∈ exactCsrAttempts := by
  have checked : ∀ limb : Fin 7,
      actionHashCopyAttempt limb.val ∈ V8Smz9ProgramCanonicalityCsr36.chunk008 := by decide
  exact csr36_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr36.chunkList]) (checked limb)

theorem accepted_action_hash_copy_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (limb : Fin 7) :
    authorizationRawWord packed (131 + limb.val) = packedWord packed (hashFinalIndex 93 limb.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 3 0 : F) = -1 := by
    have source := equations 3 (.constant 18446744069414584320) (by decide)
    simp only [expressionField] at source
    rw [source]
    change ((Hegemon.Transaction.Poseidon2V8RelationProgram.fieldSub 0 1 : Nat) : F) = -1
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have equation := accepted_csr_attempt_field_equality (attempts _ (action_hash_copy_source limb))
  simp only [actionHashCopyAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, zero, negative, one_mul, neg_one_mul, add_zero,
    ← sub_eq_add_neg] at equation
  have result := canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp equation)
  simpa only [authorizationRawWord, packedWord, rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using result

def finalIntentExpressions (limb : Nat) : List (Nat × FieldExpression) :=
  [(218, .witnessRow 94), (269 + limb, .witnessRow (145 + limb)),
    (255 + limb, .witnessRow (131 + limb)),
    (2000 + 2 * limb, .sub (269 + limb) (255 + limb)),
    (2001 + 2 * limb, .mul 218 (2000 + 2 * limb))]

theorem final_intent_source (limb : Fin 7) :
    (finalIntentExpressions limb.val).all (fun entry =>
      exactNonlinearExpressions[entry.1]? == some entry.2) = true := by
  have checked : ∀ limb : Fin 7,
      (finalIntentExpressions limb.val).all (fun entry =>
        exactNonlinearExpressions[entry.1]? == some entry.2) = true := by decide
  exact checked limb

theorem final_intent_root (limb : Fin 7) : 2001 + 2 * limb.val ∈ exactNonlinearRoots := by
  have checked : ∀ limb : Fin 7, 2001 + 2 * limb.val ∈ exactNonlinearRoots := by decide
  exact checked limb

theorem accepted_final_intent_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) (limb : Fin 7) :
    authorizationRawWord packed (145 + limb.val) = authorizationRawWord packed (131 + limb.val) := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 2001 + 2 * limb.val) (by decide) (final_intent_root limb)
  have source (index : Nat) (expression : FieldExpression)
      (member : (index, expression) ∈ finalIntentExpressions limb.val) :
      exactNonlinearExpressions[index]? = some expression :=
    eq_of_beq (List.all_eq_true.mp (final_intent_source limb) (index, expression) member)
  have gate := equations 218 (.witnessRow 94) (source _ _ (by simp [finalIntentExpressions]))
  have left := equations (269 + limb.val) (.witnessRow (145 + limb.val))
    (source _ _ (by simp [finalIntentExpressions]))
  have right := equations (255 + limb.val) (.witnessRow (131 + limb.val))
    (source _ _ (by simp [finalIntentExpressions]))
  have difference := equations (2000 + 2 * limb.val) (.sub (269 + limb.val) (255 + limb.val))
    (source _ _ (by simp [finalIntentExpressions]))
  have root := equations (2001 + 2 * limb.val) (.mul 218 (2000 + 2 * limb.val))
    (source _ _ (by simp [finalIntentExpressions]))
  simp only [expressionField] at gate left right difference root
  rw [authorization_lane_zero_word packed (by decide : 94 < 686), show 94 = 92 + 2 by decide,
    authorization_raw_mode_word, accepted_final_mode_word accepted mode, Nat.cast_one] at gate
  rw [authorization_lane_zero_word packed (by have := limb.isLt; omega : 145 + limb.val < 686)] at left
  rw [authorization_lane_zero_word packed (by have := limb.isLt; omega : 131 + limb.val < 686)] at right
  rw [rootZero, gate, one_mul, difference, left, right] at root
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp root.symm)

theorem accepted_final_current_intent_hash {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    (projectAuthorization packed).current.intentDigest = (packedFinalState packed 93).take digestWords := by
  apply List.ext_getElem
  · simp [projectAuthorization, projectAccumulator, packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have bound : limb < 7 := by simpa [projectAuthorization, projectAccumulator] using leftBound
    simp only [projectAuthorization, projectAccumulator, packedFinalState,
      List.getElem_map, List.getElem_range, List.getElem_take]
    have current := accepted_current_opening_source_word accepted (by omega : 7 + limb < 23)
    have row : 138 + (7 + limb) = 145 + limb := by omega
    rw [row] at current
    exact current.trans ((accepted_final_intent_word accepted mode ⟨limb, bound⟩).trans
      (accepted_action_hash_copy_word accepted ⟨limb, bound⟩))


end HegemonCrypto.SmallWood.V8Smz9AuthorizationHashBindings
