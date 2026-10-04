import HegemonCrypto.SmallWoodV8Smz9SourceSimpleStableCsr
import HegemonCrypto.SmallWoodV8Smz9SourceTailCheckedSubtractions

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableArithmetic04
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def sourceFourBits (bits : Nat → Nat) : Nat := bits 0 + 2 * bits 1 + 4 * bits 2 + 8 * bits 3
def sourceFiveBits (bits : Nat → Nat) : Nat := sourceFourBits bits + 16 * bits 4

theorem source_bit_low_four (value : Nat) : sourceFourBits (sourceBit value) = value % 16 := by
  simp only [sourceFourBits,sourceBit,Nat.pow_zero,Nat.pow_one,Nat.reducePow,Nat.div_one]
  omega

theorem source_bit_low_five (value : Nat) (bound : value < 32) :
    sourceFiveBits (sourceBit value) = value := by
  simp only [sourceFiveBits,sourceFourBits,sourceBit,Nat.pow_zero,Nat.pow_one,Nat.reducePow,Nat.div_one]
  omega

theorem typed_stable_enabled_transition (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (enabled : statement.stablecoin.direction ≠ .disabled) :
    exactV8StablecoinEnabledValid (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin := by
  have transition := typed_stable_transition statement witness valid
  cases mode : statement.stablecoin.direction <;>
    simp only [exactV8StableTransition,mode] at transition
  · exact False.elim (enabled mode)
  · exact transition
  · exact transition

theorem valid_source_asset_reconstruction (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    sourceFourBits aux.pathBits + 16 * aux.pathQuotient = statement.stablecoin.assetId := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · have asset := typed_disabled_asset_zero statement witness valid disabled
    simp [sourceAux,disabled,disabledSourceAux,sourceFourBits,asset]
  · simp only [sourceAux,if_neg disabled,source_bit_low_four]
    have recompose := Nat.mod_add_div statement.stablecoin.assetId 16
    omega

theorem valid_source_decimal_reconstruction (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (decodeV8StablecoinConfig witness.stablecoin).collateralDecimals =
      sourceFiveBits (sourceAux statement.stablecoin witness.stablecoin).decimalBits := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · have words := stable_zero_word witness.stablecoin
      (typed_disabled_source_words_zero statement witness valid disabled)
    simp [sourceAux,disabled,disabledSourceAux,sourceFiveBits,sourceFourBits,decodeV8StablecoinConfig,words]
  · have numeric := valid_numeric_input_bounds statement witness valid
    have decimals := numeric.decimals
    simp only [sourceAux,if_neg disabled]
    exact (source_bit_low_five _ (by omega)).symm

theorem valid_source_decimal_slack (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (decodeV8StablecoinConfig witness.stablecoin).collateralDecimals +
      sourceFiveBits (sourceAux statement.stablecoin witness.stablecoin).decimalSlackBits =
        18 * (if statement.stablecoin.direction = .disabled then 0 else 1) := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · have words := stable_zero_word witness.stablecoin
      (typed_disabled_source_words_zero statement witness valid disabled)
    simp [sourceAux,disabled,disabledSourceAux,sourceFiveBits,sourceFourBits,decodeV8StablecoinConfig,words]
  · have numeric := valid_numeric_input_bounds statement witness valid
    have decimals := numeric.decimals
    simp only [sourceAux,if_neg disabled]
    rw [source_bit_low_five _ (by omega)]
    omega

theorem source_decimal_accumulator_five (decimals : Nat) (bound : decimals ≤ 18) :
    sourceDecimalAccumulator decimals 5 = 10 ^ decimals := by
  interval_cases decimals <;> decide

theorem valid_source_collateral_scale (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (enabled : statement.stablecoin.direction ≠ .disabled) :
    (decodeV8StablecoinConfig witness.stablecoin).collateralScale =
      (sourceAux statement.stablecoin witness.stablecoin).decimalAccumulators 4 := by
  have transition := typed_stable_enabled_transition statement witness valid enabled
  have common := transition.2.2.2.2.2.2.2.2.2.2.2.2.1
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,decimals,scale⟩ := common
  simp only [sourceAux,if_neg enabled]
  rw [source_decimal_accumulator_five _ decimals]
  exact scale

end HegemonCrypto.SmallWood.V8Smz9SourceStableArithmetic04
