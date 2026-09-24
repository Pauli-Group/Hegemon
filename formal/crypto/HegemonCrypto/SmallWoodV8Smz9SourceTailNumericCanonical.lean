import HegemonCrypto.SmallWoodV8Smz9SourceTailMulBounds

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization (AuthHashFinals auth_exact_words_getD)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

def sourceScalarValues (aux : SourceAux) : List Nat :=
  [aux.pathQuotient,aux.enabledAge,aux.retirementOrderGap,aux.retirementHeightGap,
   aux.oracleAge,aux.oracleSlack,aux.attestationAge,aux.attestationSlack,aux.ratioSlack,
   aux.beforeCapSlack,aux.afterCapSlack,aux.epochGap,aux.epochRemainder]

theorem actual_decimal_accumulator_bound (statement : V8PublicStatement) (witness : V8Witness)
    (bounds : NumericInputBounds statement witness) (bit : Nat) (bitBound : bit < 5) :
    (sourceAux statement.stablecoin witness.stablecoin).decimalAccumulators bit ≤ 10 ^ 18 := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled]
    change 1 ≤ 10 ^ 18
    decide
  · simp only [sourceAux, if_neg disabled]
    exact decimal_accumulator_bound _ bit bounds.decimals bitBound

theorem actual_left_mul3_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (bounds : NumericInputBounds statement witness) :
    Mul3Bounds (sourceAux statement.stablecoin witness.stablecoin).collateral.left := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled]
    exact zero_mul3_bounds
  · simp only [sourceAux, if_neg disabled]
    split_ifs
    · exact source_mul3_bounds _ _ _ bounds.amount bounds.numerator (by decide)
    · exact zero_mul3_bounds

theorem actual_right_mul3_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (bounds : NumericInputBounds statement witness) :
    Mul3Bounds (sourceAux statement.stablecoin witness.stablecoin).collateral.right := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled]
    exact zero_mul3_bounds
  · simp only [sourceAux, if_neg disabled]
    split_ifs
    · exact source_mul3_bounds _ _ _ bounds.debt bounds.denominator bounds.ratio
    · exact zero_mul3_bounds

theorem actual_difference_bound (statement : V8PublicStatement) (witness : V8Witness) (index : Nat) :
    (sourceAux statement.stablecoin witness.stablecoin).collateral.difference index < limbBase := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled]
    change 0 < limbBase
    decide
  · simp only [sourceAux, if_neg disabled]
    split_ifs
    · exact source_collateral_difference_bound _ _ _ _ _ index
    · change 0 < limbBase
      decide

theorem actual_scalar_values_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (bounds : NumericInputBounds statement witness) (word : Nat)
    (member : word ∈ sourceScalarValues (sourceAux statement.stablecoin witness.stablecoin)) :
    word < fieldModulus := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled] at member
    change word ∈ List.replicate 13 0 at member
    have zero := (List.mem_replicate.mp member).2
    rw [zero]
    decide
  · have hAsset : statement.stablecoin.assetId < fieldModulus :=
      lt_trans bounds.asset (by decide)
    have hHeight : statement.stablecoin.parentHeight < fieldModulus :=
      lt_trans bounds.height (by decide)
    have hRatio : (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm < fieldModulus :=
      lt_trans bounds.ratio (by decide)
    have hRetired : (decodeV8StablecoinConfig witness.stablecoin).retiredAt < fieldModulus :=
      lt_trans bounds.retiredAt (by decide)
    have hOracle : (decodeV8StablecoinConfig witness.stablecoin).oracleMaxAge < fieldModulus :=
      lt_trans bounds.oracleMax (by decide)
    have hAttestation : (decodeV8StablecoinConfig witness.stablecoin).attestationMaxAge < fieldModulus :=
      lt_trans bounds.attestationMax (by decide)
    have hCap : (decodeV8StablecoinConfig witness.stablecoin).maxMintPerEpoch < fieldModulus :=
      lt_trans bounds.cap (by decide)
    have assetDiv := Nat.div_le_self statement.stablecoin.assetId 16
    have epochDiv := Nat.div_le_self statement.stablecoin.parentHeight 4096
    simp only [sourceScalarValues, sourceAux, if_neg disabled] at member
    simp only [List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals (try split_ifs) <;> omega

theorem valid_numeric_values_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    ExactWords 46 (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)) := by
  let aux := sourceAux statement.stablecoin witness.stablecoin
  have bounds := valid_numeric_input_bounds statement witness valid
  refine ⟨source_numeric_shape aux, ?_⟩
  intro word member
  change word ∈ sourceScalarValues aux ++
    List.ofFn (fun bit : Fin 5 => aux.decimalAccumulators bit.val) ++
    aux.collateral.left.rangeValues ++ aux.collateral.right.rangeValues ++
    List.ofFn (fun index : Fin 4 => aux.collateral.difference index.val) at member
  simp only [List.mem_append] at member
  rcases member with (((scalar | decimal) | left) | right) | difference
  · exact actual_scalar_values_canonical statement witness bounds word scalar
  · obtain ⟨bit,rfl⟩ := List.mem_ofFn.mp decimal
    have bound := actual_decimal_accumulator_bound statement witness bounds bit.val bit.isLt
    have modulus : 10 ^ 18 < fieldModulus := by decide
    exact lt_of_le_of_lt bound modulus
  · exact lt_trans (mul3_range_word_bound _ (actual_left_mul3_bounds statement witness bounds) word left) (by decide)
  · exact lt_trans (mul3_range_word_bound _ (actual_right_mul3_bounds statement witness bounds) word right) (by decide)
  · obtain ⟨index,rfl⟩ := List.mem_ofFn.mp difference
    exact lt_trans (actual_difference_bound statement witness index.val) (by decide)

theorem valid_source_numeric_row_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (lane : Nat) :
    sourceTailWord statement witness hashes 12 lane < fieldModulus := by
  rw [source_tail_at_12]
  exact auth_exact_words_getD (valid_numeric_values_canonical statement witness valid) lane


end HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
