import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorizationNonSingle

/-!
Scratch-only source proof work for the non-single authorization canonicality endpoint.
This module deliberately states only consequences discharged from the accepted repaired
program; it does not add a semantic canonicality premise.
-/

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (packedWitnessLaneRows)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def weightedSix (packed : List Nat) (row : Nat) : Nat :=
  authorizationRawWord packed row +
    2 * authorizationRawWord packed (row + 1) +
    3 * authorizationRawWord packed (row + 2) +
    4 * authorizationRawWord packed (row + 3) +
    5 * authorizationRawWord packed (row + 4) +
    6 * authorizationRawWord packed (row + 5)

theorem boolean_weighted_six_bounds (word : Nat → Nat)
    (boolean : ∀ index, index < 6 → BooleanWord (word index))
    (oneHot : ((List.range 6).map word).sum = 1) :
    0 < word 0 + 2 * word 1 + 3 * word 2 + 4 * word 3 + 5 * word 4 + 6 * word 5 ∧
      word 0 + 2 * word 1 + 3 * word 2 + 4 * word 3 + 5 * word 4 + 6 * word 5 ≤ 6 := by
  have b0 := boolean 0 (by decide)
  have b1 := boolean 1 (by decide)
  have b2 := boolean 2 (by decide)
  have b3 := boolean 3 (by decide)
  have b4 := boolean 4 (by decide)
  have b5 := boolean 5 (by decide)
  simp only [List.range_succ, List.range_zero, List.map_append, List.map_cons, List.map_nil,
    List.sum_append, List.sum_cons, List.sum_nil, Nat.add_zero, zero_add] at oneHot
  rcases b0 with b0 | b0 <;> rcases b1 with b1 | b1 <;>
    rcases b2 with b2 | b2 <;> rcases b3 with b3 | b3 <;>
    rcases b4 with b4 | b4 <;> rcases b5 with b5 | b5 <;> omega

theorem boolean_weighted_six_upper (word : Nat → Nat)
    (boolean : ∀ index, index < 6 → BooleanWord (word index)) :
    word 0 + 2 * word 1 + 3 * word 2 + 4 * word 3 + 5 * word 4 + 6 * word 5 ≤ 21 := by
  have b0 := boolean 0 (by decide)
  have b1 := boolean 1 (by decide)
  have b2 := boolean 2 (by decide)
  have b3 := boolean 3 (by decide)
  have b4 := boolean 4 (by decide)
  have b5 := boolean 5 (by decide)
  rcases b0 with b0 | b0 <;> rcases b1 with b1 | b1 <;>
    rcases b2 with b2 | b2 <;> rcases b3 with b3 | b3 <;>
    rcases b4 with b4 | b4 <;> rcases b5 with b5 | b5 <;> omega

structure WeightedScalarSource where
  scalarRow : Nat
  flagRow : Nat
  scalarNode : Nat
  flagNode : Nat
  mul2 : Nat
  sum2 : Nat
  mul3 : Nat
  sum3 : Nat
  constant4 : Nat
  mul4 : Nat
  sum4 : Nat
  constant5 : Nat
  mul5 : Nat
  sum5 : Nat
  constant6 : Nat
  mul6 : Nat
  sum6 : Nat
  difference : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def WeightedScalarSource.Valid (entry : WeightedScalarSource) : Prop :=
  entry.scalarRow < 686 ∧ entry.flagRow + 6 ≤ 686 ∧
    exactNonlinearExpressions[entry.scalarNode]? = some (.witnessRow entry.scalarRow) ∧
    (∀ index, index < 6 →
      exactNonlinearExpressions[entry.flagNode + index]? = some (.witnessRow (entry.flagRow + index))) ∧
    exactNonlinearExpressions[entry.mul2]? = some (.mul 2 (entry.flagNode + 1)) ∧
    exactNonlinearExpressions[entry.sum2]? = some (.add entry.flagNode entry.mul2) ∧
    exactNonlinearExpressions[entry.mul3]? = some (.mul (entry.flagNode + 2) 829) ∧
    exactNonlinearExpressions[entry.sum3]? = some (.add entry.sum2 entry.mul3) ∧
    exactNonlinearExpressions[entry.constant4]? = some (.constant 4) ∧
    exactNonlinearExpressions[entry.mul4]? = some (.mul (entry.flagNode + 3) entry.constant4) ∧
    exactNonlinearExpressions[entry.sum4]? = some (.add entry.sum3 entry.mul4) ∧
    exactNonlinearExpressions[entry.constant5]? = some (.constant 5) ∧
    exactNonlinearExpressions[entry.mul5]? = some (.mul (entry.flagNode + 4) entry.constant5) ∧
    exactNonlinearExpressions[entry.sum5]? = some (.add entry.sum4 entry.mul5) ∧
    exactNonlinearExpressions[entry.constant6]? = some (.constant 6) ∧
    exactNonlinearExpressions[entry.mul6]? = some (.mul (entry.flagNode + 5) entry.constant6) ∧
    exactNonlinearExpressions[entry.sum6]? = some (.add entry.sum5 entry.mul6) ∧
    exactNonlinearExpressions[entry.difference]? = some (.sub entry.scalarNode entry.sum6) ∧
    exactNonlinearExpressions[entry.root]? = some (.mul 1234 entry.difference) ∧
    entry.root ∈ exactNonlinearRoots

instance (entry : WeightedScalarSource) : Decidable entry.Valid := by
  unfold WeightedScalarSource.Valid
  infer_instance

theorem accepted_raw_scalar_weighted {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    (entry : WeightedScalarSource) (scalarData : entry.Valid)
    (boolean : ∀ index, index < 6 → BooleanWord
      (authorizationRawWord packed (entry.flagRow + index))) :
    authorizationRawWord packed entry.scalarRow = weightedSix packed entry.flagRow := by
  rcases entry with ⟨scalarRow, flagRow, scalarNode, flagNode, mul2, sum2, mul3, sum3,
    constant4, mul4, sum4, constant5, mul5, sum5, constant6, mul6, sum6,
    differenceNode, root⟩
  change ∀ index, index < 6 →
    BooleanWord (authorizationRawWord packed (flagRow + index)) at boolean
  change authorizationRawWord packed scalarRow = weightedSix packed flagRow
  simp only [WeightedScalarSource.Valid] at scalarData
  obtain ⟨scalarBound, flagsBound, scalarFound, flagsFound, n2, a2, n3, a3, c4, n4,
    a4, c5, n5, a5, c6, n6, a6, differenceFound, rootFound, rootMember⟩ := scalarData
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := root) (by decide) rootMember
  have gateOne := authorization_trace_gate_one accepted equations (Or.inr ⟨rfl, mode⟩)
  have scalar := equations scalarNode (.witnessRow scalarRow) scalarFound
  have flags : ∀ index, index < 6 →
      (values.getD (flagNode + index) 0 : F) =
        (authorizationRawWord packed (flagRow + index) : F) := by
    intro index bound
    have lane := authorization_lane_zero_word packed (row := flagRow + index) (by omega)
    have equation := equations (flagNode + index) (.witnessRow (flagRow + index))
      (flagsFound index bound)
    simpa only [expressionField, lane] using equation
  have f0 := flags 0 (by decide)
  have f1 := flags 1 (by decide)
  have f2 := flags 2 (by decide)
  have f3 := flags 3 (by decide)
  have f4 := flags 4 (by decide)
  have f5 := flags 5 (by decide)
  simp only [Nat.add_zero] at f0
  have two := equations 2 (.constant 2) (by decide)
  have three := equations 829 (.constant 3) (by decide)
  have four := equations constant4 (.constant 4) c4
  have five := equations constant5 (.constant 5) c5
  have six := equations constant6 (.constant 6) c6
  simp only [expressionField, Nat.cast_ofNat] at two three four five six
  have v2 := equations mul2 (.mul 2 (flagNode + 1)) n2
  have s2 := equations sum2 (.add flagNode mul2) a2
  have v3 := equations mul3 (.mul (flagNode + 2) 829) n3
  have s3 := equations sum3 (.add sum2 mul3) a3
  have v4 := equations mul4 (.mul (flagNode + 3) constant4) n4
  have s4 := equations sum4 (.add sum3 mul4) a4
  have v5 := equations mul5 (.mul (flagNode + 4) constant5) n5
  have s5 := equations sum5 (.add sum4 mul5) a5
  have v6 := equations mul6 (.mul (flagNode + 5) constant6) n6
  have s6 := equations sum6 (.add sum5 mul6) a6
  have difference := equations differenceNode (.sub scalarNode sum6) differenceFound
  have rootEquation := equations root (.mul 1234 differenceNode) rootFound
  simp only [expressionField, authorization_lane_zero_word packed scalarBound] at scalar
  simp only [expressionField, two, f1] at v2
  simp only [expressionField, f0, v2] at s2
  simp only [expressionField, f2, three] at v3
  simp only [expressionField, s2, v3] at s3
  simp only [expressionField, f3, four] at v4
  simp only [expressionField, s3, v4] at s4
  simp only [expressionField, f4, five] at v5
  simp only [expressionField, s4, v5] at s5
  simp only [expressionField, f5, six] at v6
  simp only [expressionField, s5, v6] at s6
  simp only [expressionField, scalar, s6] at difference
  simp only [expressionField, gateOne, one_mul, difference] at rootEquation
  have fieldEquality := sub_eq_zero.mp (rootEquation.symm.trans rootZero)
  have weightedBound := boolean_weighted_six_upper
    (fun index => authorizationRawWord packed (flagRow + index)) boolean
  simp only [Nat.add_zero] at weightedBound
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by
      have modulus : 21 < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
      unfold weightedSix
      omega) (by
      simpa only [weightedSix, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat,
        Nat.add_assoc, add_assoc, add_comm, add_left_comm, mul_comm] using fieldEquality)

def thresholdScalarSource : WeightedScalarSource :=
  ⟨152, 170, 276, 294, 1456, 1457, 1458, 1459, 1460, 1461, 1462,
    1463, 1464, 1465, 1466, 1467, 1468, 1469, 1470⟩

def signerScalarSource : WeightedScalarSource :=
  ⟨153, 176, 277, 300, 1496, 1497, 1498, 1499, 1460, 1500, 1501,
    1463, 1502, 1503, 1466, 1504, 1505, 1506, 1507⟩

theorem exact_threshold_scalar_data : thresholdScalarSource.Valid := by decide
theorem exact_signer_scalar_data : signerScalarSource.Valid := by decide

theorem accepted_threshold_raw_weighted {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationRawWord packed 152 = weightedSix packed 170 := by
  exact accepted_raw_scalar_weighted accepted mode thresholdScalarSource
    exact_threshold_scalar_data (by
      intro index bound
      exact accepted_threshold_flag_boolean accepted mode bound)

theorem accepted_signer_raw_weighted {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    authorizationRawWord packed 153 = weightedSix packed 176 := by
  exact accepted_raw_scalar_weighted accepted mode signerScalarSource
    exact_signer_scalar_data (by
      intro index bound
      exact accepted_signer_flag_boolean accepted mode bound)

theorem accepted_current_threshold_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (projectAuthorization packed).current.threshold = authorizationRawWord packed 152 := by
  have source := accepted_current_opening_source_word accepted (word := 14) (by decide)
  simpa [projectAuthorization, projectAccumulator] using source

theorem accepted_current_signer_count_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (projectAuthorization packed).current.signerCount = authorizationRawWord packed 153 := by
  have source := accepted_current_opening_source_word accepted (word := 15) (by decide)
  simpa [projectAuthorization, projectAccumulator] using source

theorem accepted_non_single_threshold_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    0 < (projectAuthorization packed).current.threshold ∧
      (projectAuthorization packed).current.threshold ≤ signerCountMaximum := by
  rw [accepted_current_threshold_source accepted, accepted_threshold_raw_weighted accepted mode]
  have bounds := boolean_weighted_six_bounds
    (fun index => authorizationRawWord packed (170 + index))
    (by intro index bound; exact accepted_threshold_flag_boolean accepted mode bound)
    (by
      change authorizationRawSum packed 170 6 = 1
      exact accepted_threshold_flags_sum_one accepted mode)
  simpa [weightedSix, signerCountMaximum] using bounds

theorem accepted_non_single_signer_count_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    0 < (projectAuthorization packed).current.signerCount ∧
      (projectAuthorization packed).current.signerCount ≤ signerCountMaximum := by
  rw [accepted_current_signer_count_source accepted, accepted_signer_raw_weighted accepted mode]
  have bounds := boolean_weighted_six_bounds
    (fun index => authorizationRawWord packed (176 + index))
    (by intro index bound; exact accepted_signer_flag_boolean accepted mode bound)
    (by
      change authorizationRawSum packed 176 6 = 1
      exact accepted_signer_flags_sum_one accepted mode)
  simpa [weightedSix, signerCountMaximum] using bounds

theorem accepted_non_single_current_approval_count_sum {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    (projectAuthorization packed).current.approvalCount =
      (projectAuthorization packed).current.approvedSlots.sum := by
  have countSource := accepted_current_opening_source_word accepted (word := 16) (by decide)
  have slots : (List.range 6).map (fun slot => spongeSourceWord packed 98 (17 + slot)) =
      (List.range 6).map (fun slot => authorizationRawWord packed (155 + slot)) := by
    apply List.map_congr_left
    intro slot member
    have source := accepted_current_opening_source_word accepted (word := 17 + slot)
      (by have := List.mem_range.mp member; omega)
    have address : 138 + (17 + slot) = 155 + slot := by omega
    simpa only [address] using source
  simp only [projectAuthorization, projectAccumulator]
  rw [countSource, slots]
  exact accepted_current_raw_count accepted mode

theorem accepted_non_single_current_shape {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    ExactWords digestWords (projectAuthorization packed).current.policyRoot ∧
      ExactWords digestWords (projectAuthorization packed).current.intentDigest ∧
      0 < (projectAuthorization packed).current.threshold ∧
      (projectAuthorization packed).current.signerCount ≤ signerCountMaximum ∧
      (projectAuthorization packed).current.approvalCount ≤ signerCountMaximum ∧
      (projectAuthorization packed).current.approvedSlots.length = signerCountMaximum ∧
      (∀ slot, slot < signerCountMaximum →
        BooleanWord (wordAt (projectAuthorization packed).current.approvedSlots slot)) ∧
      (projectAuthorization packed).current.approvalCount =
        (projectAuthorization packed).current.approvedSlots.sum := by
  have threshold := accepted_non_single_threshold_bounds accepted mode
  have signer := accepted_non_single_signer_count_bounds accepted mode
  have approvedBound : (projectAuthorization packed).current.approvalCount ≤ signerCountMaximum := by
    have countSource := accepted_current_opening_source_word accepted (word := 16) (by decide)
    have sumBound := boolean_range_sum_le_count
      (fun slot => authorizationRawWord packed (155 + slot)) 6
      (by intro slot bound; exact accepted_current_bitmap_boolean accepted mode bound)
    change authorizationRawSum packed 155 6 ≤ 6 at sumBound
    have rawBound := (accepted_current_raw_count accepted mode).trans_le sumBound
    simpa [projectAuthorization, projectAccumulator, signerCountMaximum, countSource] using rawBound
  refine ⟨?_, ?_, threshold.1, signer.2, approvedBound, ?_, ?_, ?_⟩
  · apply exact_words_range_map
    intro limb bound
    exact sponge_source_word_canonical accepted.2.1 98 limb
  · apply exact_words_range_map
    intro limb bound
    exact sponge_source_word_canonical accepted.2.1 98 (7 + limb)
  · simp [projectAuthorization, projectAccumulator, signerCountMaximum]
  · intro slot bound
    change slot < 6 at bound
    rw [accepted_current_bitmap_word accepted bound]
    exact accepted_current_bitmap_boolean accepted mode bound
  · exact accepted_non_single_current_approval_count_sum accepted mode

theorem accepted_signer_tags_exact_shape {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (projectAuthorization packed).policySignerTags.length = signerCountMaximum ∧
      ∀ slot, slot < signerCountMaximum →
        ExactWords signerTagWords ((projectAuthorization packed).policySignerTags.getD slot []) := by
  constructor
  · simp [projectAuthorization, signerCountMaximum]
  · intro slot slotBound
    change slot < 6 at slotBound
    rw [project_authorization_signer_tag packed slotBound]
    apply exact_words_range_map
    intro limb limbBound
    exact packed_word_canonical accepted.2.1 _


end HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
