import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceTailCheckedSubtractions
import HegemonCrypto.SmallWoodV8Smz9SourceRoleAlgebra

namespace HegemonCrypto.SmallWood.V8Smz9SourceBaseMultiplication

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem low_carry_recomposition (x y carry : Nat) :
    (x % limbBase) * y + carry = (x * y + carry) % limbBase +
      limbBase * (((x % limbBase) * y + carry) / limbBase) := by
  have same : ((x % limbBase) * y + carry) % limbBase = (x * y + carry) % limbBase := by
    simp only [Nat.add_mod, Nat.mul_mod, Nat.mod_mod]
  rw [← same]
  exact (Nat.mod_add_div _ _).symm

theorem high_carry_recomposition (x y carry : Nat) :
    (x / limbBase) * y + ((x % limbBase) * y + carry) / limbBase =
      (x * y + carry) / limbBase := by
  have source := congrArg (fun value : Nat => value * y + carry) (Nat.mod_add_div x limbBase)
  simp only [Nat.add_mul, Nat.mul_assoc] at source
  have low := low_carry_recomposition x y carry
  have target := Nat.mod_add_div (x * y + carry) limbBase
  norm_num [limbBase] at source low target ⊢
  omega

theorem actual_product_high_bounds (x y z : Nat) (xb : x < 2 ^ 56)
    (yb : y < 2 ^ 32) (zb : z < 2 ^ 32) :
    x * y / limbBase ^ 2 < limbBase ∧ x * y * z / limbBase ^ 3 < limbBase := by
  have first := Nat.mul_le_mul (show x ≤ 72057594037927935 by omega)
    (show y ≤ 4294967295 by omega)
  have firstBound : x * y ≤ 309485009821345068724781055 := by norm_num at first ⊢; omega
  have second := Nat.mul_le_mul firstBound (show z ≤ 4294967295 by omega)
  norm_num [limbBase] at first second ⊢
  constructor <;> omega

theorem source_mul3_recompositions (x y z : Nat) (xb : x < 2 ^ 56)
    (yb : y < 2 ^ 32) (zb : z < 2 ^ 32) :
    let limbs := sourceMul3 x y z
    limbs.x0 * y = limbs.p0 + limbBase * limbs.c0 ∧
    limbs.x1 * y + limbs.c0 = limbs.p1 + limbBase * limbs.p2 ∧
    limbs.p0 * z = limbs.out 0 + limbBase * limbs.c1 ∧
    limbs.p1 * z + limbs.c1 = limbs.out 1 + limbBase * limbs.c2 ∧
    limbs.p2 * z + limbs.c2 = limbs.out 2 + limbBase * limbs.out 3 := by
  have bounds := actual_product_high_bounds x y z xb yb zb
  have p2 : (x * y / limbBase ^ 2) % limbBase = x * y / limbBase ^ 2 := Nat.mod_eq_of_lt bounds.1
  have out3 : (x * y * z / limbBase ^ 3) % limbBase = x * y * z / limbBase ^ 3 := Nat.mod_eq_of_lt bounds.2
  have firstLow := low_carry_recomposition x y 0
  have firstHigh := high_carry_recomposition x y 0
  have firstParts := Nat.mod_add_div (x * y / limbBase) limbBase
  have secondLow := low_carry_recomposition (x * y) z 0
  have secondHigh := high_carry_recomposition (x * y) z 0
  have middleLow := low_carry_recomposition (x * y / limbBase) z ((x * y % limbBase) * z / limbBase)
  have middleHigh := high_carry_recomposition (x * y / limbBase) z ((x * y % limbBase) * z / limbBase)
  have lastParts := Nat.mod_add_div (x * y * z / limbBase ^ 2) limbBase
  simp only [Nat.add_zero] at firstLow firstHigh secondLow secondHigh
  rw [secondHigh] at middleLow middleHigh
  simp only [Nat.div_div_eq_div_mul, ← pow_two] at firstParts middleHigh
  have divLast : x * y * z / limbBase ^ 2 / limbBase = x * y * z / limbBase ^ 3 := by
    rw [Nat.div_div_eq_div_mul]
    congr 1
  rw [divLast] at lastParts
  dsimp only [sourceMul3]
  simp only [p2, out3, pow_zero, Nat.div_one]
  refine ⟨firstLow, ?_, secondLow, ?_, ?_⟩
  · exact firstHigh.trans firstParts.symm
  · simpa only [pow_one] using middleLow
  · exact middleHigh.trans lastParts.symm

theorem source_mul3_lane_nat_equation (x y z : Nat) (xb : x < 2 ^ 56)
    (yb : y < 2 ^ 32) (zb : z < 2 ^ 32) (lane : Nat) :
    let tuple := sourceMul3Lane (sourceMul3 x y z) y z lane
    tuple.a * tuple.b = tuple.c := by
  obtain ⟨e0,e1,e2,e3,e4⟩ := source_mul3_recompositions x y z xb yb zb
  unfold sourceMul3Lane
  split <;> dsimp only
  · exact e0
  · rw [← e1, Nat.add_sub_cancel]
  · exact e2
  · rw [← e3, Nat.add_sub_cancel]
  · rw [← e4, Nat.add_sub_cancel]

theorem zero_mul3_lane_nat_equation (y z lane : Nat) :
    let tuple := sourceMul3Lane ({} : SourceMul3) y z lane
    tuple.a * tuple.b = tuple.c := by
  unfold sourceMul3Lane
  split <;> simp

theorem decimal_step (decimals lane : Nat) :
    (if lane = 0 then 1 else sourceDecimalAccumulator decimals ((lane - 1) + 1)) *
      (1 + sourceBit decimals lane * (10 ^ (2 ^ lane) - 1)) =
      sourceDecimalAccumulator decimals (lane + 1) := by
  have previous : (if lane = 0 then 1 else sourceDecimalAccumulator decimals ((lane - 1) + 1)) =
      sourceDecimalAccumulator decimals lane := by
    cases lane <;> simp [sourceDecimalAccumulator]
  rw [previous, sourceDecimalAccumulator]
  rcases source_bit_boolean decimals lane with zero | one
  · simp [zero]
  · have positive : 0 < 10 ^ (2 ^ lane) := Nat.pow_pos (by decide)
    have power : 1 + (10 ^ (2 ^ lane) - 1) = 10 ^ (2 ^ lane) := by omega
    simp [one, power]

def TupleEquation (tuple : SourceMulTuple) : Prop := (tuple.a : F) * (tuple.b : F) = (tuple.c : F)

theorem tuple_equation_of_nat (tuple : SourceMulTuple) (equal : tuple.a * tuple.b = tuple.c) :
    TupleEquation tuple := by
  have equation := congrArg (fun value : Nat => (value : F)) equal
  simpa only [TupleEquation, Nat.cast_mul] using equation

theorem actual_epoch_alternative (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    (aux.sameEpoch = 1 ∧ aux.epochGap = 0) ∨ (aux.sameEpoch = 0 ∧ aux.epochGap ≠ 0) := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simp [sourceAux, disabled, disabledSourceAux]
  have ordered := (valid_source_checked_subtraction_inputs statement witness valid).epoch disabled
  by_cases same : (decodeV8StablecoinBefore witness.stablecoin).epochId = statement.stablecoin.parentHeight / 4096
  · left
    simp [sourceAux, disabled, same]
  · right
    simp only [sourceAux, if_neg disabled, if_neg same]
    exact ⟨trivial, by omega⟩

theorem typed_source_base_multiplication_equation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Nat) :
    TupleEquation (sourceBaseMultiplication statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin) lane) := by
  have bounds := valid_numeric_input_bounds statement witness valid
  by_cases low5 : lane < 5
  · apply tuple_equation_of_nat
    by_cases disabled : statement.stablecoin.direction = .disabled
    · simp [sourceBaseMultiplication, low5, sourceAux, disabled, disabledSourceAux]
    · simpa only [sourceBaseMultiplication, if_pos low5, sourceAux, if_neg disabled] using
        decimal_step (decodeV8StablecoinConfig witness.stablecoin).collateralDecimals lane
  by_cases low10 : lane < 10
  · apply tuple_equation_of_nat
    by_cases disabled : statement.stablecoin.direction = .disabled
    · simpa only [sourceBaseMultiplication, if_neg low5, if_pos low10, sourceAux, if_pos disabled, disabledSourceAux] using
        zero_mul3_lane_nat_equation (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator 1000000 (lane - 5)
    · by_cases mint : statement.stablecoin.direction = .mint
      · simpa only [sourceBaseMultiplication, if_neg low5, if_pos low10, sourceAux, if_neg disabled, if_pos mint, sourceCollateral] using
          source_mul3_lane_nat_equation _ _ _ bounds.amount bounds.numerator (by decide : 1000000 < 2 ^ 32) (lane - 5)
      · simpa only [sourceBaseMultiplication, if_neg low5, if_pos low10, sourceAux, if_neg disabled, if_neg mint] using
          zero_mul3_lane_nat_equation (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator 1000000 (lane - 5)
  by_cases low15 : lane < 15
  · apply tuple_equation_of_nat
    by_cases disabled : statement.stablecoin.direction = .disabled
    · simpa only [sourceBaseMultiplication, if_neg low5, if_neg low10, if_pos low15, sourceAux, if_pos disabled, disabledSourceAux] using
        zero_mul3_lane_nat_equation (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
          (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm (lane - 10)
    · by_cases mint : statement.stablecoin.direction = .mint
      · simpa only [sourceBaseMultiplication, if_neg low5, if_neg low10, if_pos low15, sourceAux, if_neg disabled, if_pos mint, sourceCollateral] using
          source_mul3_lane_nat_equation _ _ _ bounds.debt bounds.denominator bounds.ratio (lane - 10)
      · simpa only [sourceBaseMultiplication, if_neg low5, if_neg low10, if_pos low15, sourceAux, if_neg disabled, if_neg mint] using
          zero_mul3_lane_nat_equation (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
            (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm (lane - 10)
  by_cases at15 : lane = 15
  · subst lane
    simp only [TupleEquation, sourceBaseMultiplication, show ¬(15:Nat)<5 by decide, show ¬(15:Nat)<10 by decide,
      show ¬(15:Nat)<15 by decide, if_false, if_true]
    have canonical : (sourceAux statement.stablecoin witness.stablecoin).epochGap < fieldModulus :=
      lt_trans (valid_aux_epoch_and_path_ranges statement witness valid).1 (by decide)
    rw [canonical_inverse_cast _ canonical]
    rcases actual_epoch_alternative statement witness valid with ⟨same,gap⟩ | ⟨same,gap⟩
    · simp [same, gap]
    · simp only [same, Nat.sub_zero, Nat.cast_one]
      exact mul_inv_cancel₀ (canonical_nonzero_cast _ canonical gap)
  by_cases at16 : lane = 16
  · subst lane
    simp [TupleEquation, sourceBaseMultiplication, Nat.cast_mul]
  by_cases at17 : lane = 17
  · subst lane
    rcases actual_epoch_alternative statement witness valid with ⟨same,gap⟩ | ⟨same,gap⟩
    all_goals simp [TupleEquation, sourceBaseMultiplication, same, gap]
  simp [TupleEquation, sourceBaseMultiplication, low5, low10, low15, at15, at16, at17]




end HegemonCrypto.SmallWood.V8Smz9SourceBaseMultiplication
