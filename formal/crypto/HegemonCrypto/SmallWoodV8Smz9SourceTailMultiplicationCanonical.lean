import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericCanonical
import HegemonCrypto.SmallWoodV8Smz9SourceTailRolesCanonical

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization (AuthHashFinals auth_exact_words_getD)
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
  (boolean_word_canonical boolean_getD actual_source_aux_boolean
   valid_source_boolean_values_boolean source_sub_canonical)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

theorem one_sub_canonical (value : Nat) : 1 - value < fieldModulus :=
  lt_of_le_of_lt (Nat.sub_le _ _) (by decide)

theorem actual_numeric_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Nat) :
    (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD index 0 < fieldModulus :=
  auth_exact_words_getD (valid_numeric_values_canonical statement witness valid) index

theorem actual_boolean_word_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Nat) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD index 0 < fieldModulus :=
  boolean_word_canonical _ (boolean_getD _ (valid_source_boolean_values_boolean statement witness valid) index)

theorem actual_base_multiplication_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat) :
    MulTupleCanonical (sourceBaseMultiplication statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin) lane) := by
  have bounds := valid_numeric_input_bounds statement witness valid
  have booleans := actual_source_aux_boolean statement.stablecoin witness.stablecoin
  have epochCanonical := boolean_word_canonical _ booleans.2.1
  have epochGapCanonical := actual_scalar_values_canonical statement witness bounds
    (sourceAux statement.stablecoin witness.stablecoin).epochGap
    (by simp [sourceScalarValues])
  have beforeCanonical : (decodeV8StablecoinBefore witness.stablecoin).mintedInEpoch < fieldModulus :=
    lt_trans bounds.beforeMinted (by decide)
  simp only [sourceBaseMultiplication]
  by_cases low5 : lane < 5
  · rw [if_pos low5]
    refine ⟨?_,?_,?_⟩
    · split_ifs
      · exact (by decide : 1 < fieldModulus)
      · exact lt_of_le_of_lt (actual_decimal_accumulator_bound statement witness bounds
          (lane - 1) (by omega)) (by decide)
    · have power := decimal_power_bound lane low5
      have bit := booleans.2.2.1 lane
      rcases bit with zero | one
      · rw [zero]
        simp only [Nat.zero_mul, Nat.add_zero]
        decide
      · rw [one]
        simp only [Nat.one_mul]
        have modulus : 1 + 10 ^ 16 < fieldModulus := by decide
        omega
    · exact lt_of_le_of_lt (actual_decimal_accumulator_bound statement witness bounds lane low5) (by decide)
  rw [if_neg low5]
  by_cases low10 : lane < 10
  · rw [if_pos low10]
    exact mul3_lane_canonical _ (actual_left_mul3_bounds statement witness bounds) _ _
      bounds.numerator (by decide) _
  rw [if_neg low10]
  by_cases low15 : lane < 15
  · rw [if_pos low15]
    exact mul3_lane_canonical _ (actual_right_mul3_bounds statement witness bounds) _ _
      bounds.denominator bounds.ratio _
  rw [if_neg low15]
  by_cases at15 : lane = 15
  · rw [if_pos at15]
    exact ⟨epochGapCanonical,source_inverse_canonical _,one_sub_canonical _⟩
  rw [if_neg at15]
  by_cases at16 : lane = 16
  · rw [if_pos at16]
    refine ⟨epochCanonical,beforeCanonical,?_⟩
    rcases booleans.2.1 with zero | one
    · rw [zero]
      simp only [Nat.zero_mul]
      decide
    · rw [one]
      simpa only [Nat.one_mul] using beforeCanonical
  rw [if_neg at16]
  by_cases at17 : lane = 17
  · rw [if_pos at17]
    exact ⟨epochCanonical,epochGapCanonical,(by decide : 0 < fieldModulus)⟩
  rw [if_neg at17]
  exact ⟨by decide,by decide,by decide⟩

theorem actual_multiplication_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat) :
    MulTupleCanonical (sourceMultiplication statement witness
      (sourceAux statement.stablecoin witness.stablecoin) lane) := by
  let mint : Nat := if statement.stablecoin.direction = .mint then 1 else 0
  have mintCanonical : mint < fieldModulus := by
    unfold mint
    split_ifs <;> decide
  have source4 := valid_stable_source_word_canonical statement witness valid 4
  have source5 := valid_stable_source_word_canonical statement witness valid 5
  have gateCanonical : mint * stableSourceWord statement witness 4 < fieldModulus := by
    unfold mint
    split_ifs
    · simpa only [Nat.one_mul] using source4
    · simp only [Nat.zero_mul]
      decide
  simp only [sourceMultiplication]
  by_cases low18 : lane < 18
  · rw [if_pos low18]
    exact actual_base_multiplication_canonical statement witness valid lane
  rw [if_neg low18]
  by_cases low24 : lane < 24
  · rw [if_pos low24]
    refine ⟨?_,?_,mintCanonical⟩
    · exact lt_of_le_of_lt (Nat.sub_le _ _) (by decide : limbBase - 1 < fieldModulus)
    · split_ifs
      all_goals first | exact source_inverse_canonical _ | exact (by decide : 0 < fieldModulus)
  rw [if_neg low24]
  by_cases at24 : lane = 24
  · rw [if_pos at24]
    exact ⟨one_sub_canonical _,source5,(by decide : 0 < fieldModulus)⟩
  rw [if_neg at24]
  by_cases low29 : lane < 29
  · rw [if_pos low29]
    refine ⟨gateCanonical,?_,(by decide : 0 < fieldModulus)⟩
    apply auth_exact_words_getD (count := 4)
    refine ⟨rfl,?_⟩
    intro word member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    all_goals exact source_sub_canonical _ _
  rw [if_neg low29]
  by_cases low33 : lane < 33
  · rw [if_pos low33]
    refine ⟨one_sub_canonical _,?_,(by decide : 0 < fieldModulus)⟩
    apply auth_exact_words_getD (count := 4)
    refine ⟨rfl,?_⟩
    intro word member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    · exact actual_numeric_word_canonical statement witness valid 2
    · exact actual_numeric_word_canonical statement witness valid 3
    · exact actual_boolean_word_canonical statement witness valid 27
    · exact actual_boolean_word_canonical statement witness valid 28
  rw [if_neg low33]
  exact ⟨by decide,by decide,by decide⟩

theorem valid_source_multiplication_a_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 13 lane < fieldModulus := by
  rw [source_tail_at_13]
  exact (actual_multiplication_canonical statement witness valid lane).1

theorem valid_source_multiplication_b_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 14 lane < fieldModulus := by
  rw [source_tail_at_14]
  exact (actual_multiplication_canonical statement witness valid lane).2.1

theorem valid_source_multiplication_c_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 15 lane < fieldModulus := by
  rw [source_tail_at_15]
  exact (actual_multiplication_canonical statement witness valid lane).2.2

theorem valid_source_multiplication_rows_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (row : Fin 3) (lane : Nat) :
    sourceTailWord statement witness hashes (13 + row.val) lane < fieldModulus := by
  fin_cases row
  · exact valid_source_multiplication_a_canonical statement witness valid hashes lane
  · exact valid_source_multiplication_b_canonical statement witness valid hashes lane
  · exact valid_source_multiplication_c_canonical statement witness valid hashes lane


end HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
