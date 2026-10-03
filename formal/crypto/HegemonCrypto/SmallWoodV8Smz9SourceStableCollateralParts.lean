import HegemonCrypto.SmallWoodV8Smz9SourceStableCounterArithmetic
import HegemonCrypto.SmallWoodV8Smz9SourceBaseMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralParts
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceBaseMultiplication
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def laneLow (limbs : SourceMul3) : Nat → Nat
  | 0 => limbs.p0
  | 1 => limbs.p1
  | 2 => limbs.out 0
  | 3 => limbs.out 1
  | 4 => limbs.out 2
  | _ => 0

def laneHigh (limbs : SourceMul3) : Nat → Nat
  | 0 => limbs.c0
  | 1 => limbs.p2
  | 2 => limbs.c1
  | 3 => limbs.c2
  | 4 => limbs.out 3
  | _ => 0

def lanePrevious (limbs : SourceMul3) : Nat → Nat
  | 1 => limbs.c0
  | 3 => limbs.c1
  | 4 => limbs.c2
  | _ => 0

theorem source_mul3_lane_carry_recomposition (x y z : Nat)
    (xb : x < 2^56) (yb : y < 2^32) (zb : z < 2^32) (lane : Fin 5) :
    let limbs := sourceMul3 x y z
    (sourceMul3Lane limbs y z lane.val).c + lanePrevious limbs lane.val =
      laneLow limbs lane.val + limbBase * laneHigh limbs lane.val := by
  obtain ⟨e0,e1,e2,e3,e4⟩ := source_mul3_recompositions x y z xb yb zb
  fin_cases lane
  · simp [sourceMul3Lane,lanePrevious,laneLow,laneHigh]
  · have bound : (sourceMul3 x y z).c0 ≤ (sourceMul3 x y z).p1 +
        limbBase * (sourceMul3 x y z).p2 := by omega
    exact Nat.sub_add_cancel bound
  · simp [sourceMul3Lane,lanePrevious,laneLow,laneHigh]
  · have bound : (sourceMul3 x y z).c1 ≤ (sourceMul3 x y z).out 1 +
        limbBase * (sourceMul3 x y z).c2 := by omega
    exact Nat.sub_add_cancel bound
  · have bound : (sourceMul3 x y z).c2 ≤ (sourceMul3 x y z).out 2 +
        limbBase * (sourceMul3 x y z).out 3 := by omega
    exact Nat.sub_add_cancel bound

theorem zero_mul3_lane_carry_recomposition (y z : Nat) (lane : Fin 5) :
    let limbs : SourceMul3 := {}
    (sourceMul3Lane limbs y z lane.val).c + lanePrevious limbs lane.val =
      laneLow limbs lane.val + limbBase * laneHigh limbs lane.val := by
  fin_cases lane <;> simp [sourceMul3Lane,lanePrevious,laneLow,laneHigh]

theorem actual_left_carry_recomposition (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 5) :
    let limbs := (sourceAux statement.stablecoin witness.stablecoin).collateral.left
    let numerator := (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator
    (sourceMul3Lane limbs numerator 1000000 lane.val).c + lanePrevious limbs lane.val =
      laneLow limbs lane.val + limbBase * laneHigh limbs lane.val := by
  have bounds := valid_numeric_input_bounds statement witness valid
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simpa only [sourceAux,if_pos disabled,disabledSourceAux] using zero_mul3_lane_carry_recomposition
      (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator 1000000 lane
  · by_cases mint : statement.stablecoin.direction = .mint
    · simpa only [sourceAux,if_neg disabled,if_pos mint,sourceCollateral] using
        source_mul3_lane_carry_recomposition _ _ _ bounds.amount bounds.numerator
          (by decide : 1000000 < 2^32) lane
    · simpa only [sourceAux,if_neg disabled,if_neg mint] using zero_mul3_lane_carry_recomposition
        (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator 1000000 lane

theorem actual_right_carry_recomposition (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 5) :
    let limbs := (sourceAux statement.stablecoin witness.stablecoin).collateral.right
    let config := decodeV8StablecoinConfig witness.stablecoin
    (sourceMul3Lane limbs config.oraclePriceDenominator config.minCollateralRatioPpm lane.val).c +
      lanePrevious limbs lane.val = laneLow limbs lane.val + limbBase * laneHigh limbs lane.val := by
  have bounds := valid_numeric_input_bounds statement witness valid
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simpa only [sourceAux,if_pos disabled,disabledSourceAux] using zero_mul3_lane_carry_recomposition
      (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
      (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm lane
  · by_cases mint : statement.stablecoin.direction = .mint
    · simpa only [sourceAux,if_neg disabled,if_pos mint,sourceCollateral] using
        source_mul3_lane_carry_recomposition _ _ _ bounds.debt bounds.denominator bounds.ratio lane
    · simpa only [sourceAux,if_neg disabled,if_neg mint] using zero_mul3_lane_carry_recomposition
        (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator
        (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm lane

noncomputable section
theorem actual_left_carry_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 5) :
    let limbs := (sourceAux statement.stablecoin witness.stablecoin).collateral.left
    let numerator := (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator
    ((sourceMul3Lane limbs numerator 1000000 lane.val).c : F) - (laneLow limbs lane.val : F) -
      4294967296 * (laneHigh limbs lane.val : F) + (lanePrevious limbs lane.val : F) = 0 := by
  have equation := congrArg (fun value : Nat => (value : F)) (actual_left_carry_recomposition statement witness valid lane)
  simp only [Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at equation
  dsimp only
  linear_combination equation

theorem actual_right_carry_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 5) :
    let limbs := (sourceAux statement.stablecoin witness.stablecoin).collateral.right
    let config := decodeV8StablecoinConfig witness.stablecoin
    ((sourceMul3Lane limbs config.oraclePriceDenominator config.minCollateralRatioPpm lane.val).c : F) -
      (laneLow limbs lane.val : F) - 4294967296 * (laneHigh limbs lane.val : F) +
      (lanePrevious limbs lane.val : F) = 0 := by
  have equation := congrArg (fun value : Nat => (value : F)) (actual_right_carry_recomposition statement witness valid lane)
  simp only [Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at equation
  dsimp only
  linear_combination equation
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralParts
