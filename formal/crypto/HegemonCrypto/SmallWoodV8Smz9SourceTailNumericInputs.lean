import HegemonCrypto.SmallWoodV8Smz9SourceTailReadbacks

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

structure NumericInputBounds (statement : V8PublicStatement) (witness : V8Witness) : Prop where
  asset : statement.stablecoin.assetId < 2 ^ 32
  height : statement.stablecoin.parentHeight < 2 ^ 63
  ratio : (decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm < 2 ^ 32
  numerator : (decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator < 2 ^ 32
  denominator : (decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator < 2 ^ 32
  cap : (decodeV8StablecoinConfig witness.stablecoin).maxMintPerEpoch < 2 ^ 56
  amount : (decodeV8StablecoinConfig witness.stablecoin).collateralAmount < 2 ^ 56
  debt : statement.stablecoin.after.totalDebt < 2 ^ 56
  beforeMinted : (decodeV8StablecoinBefore witness.stablecoin).mintedInEpoch < 2 ^ 56
  retiredAt : (decodeV8StablecoinConfig witness.stablecoin).retiredAt < 2 ^ 63
  oracleMax : (decodeV8StablecoinConfig witness.stablecoin).oracleMaxAge < 2 ^ 63
  attestationMax : (decodeV8StablecoinConfig witness.stablecoin).attestationMaxAge < 2 ^ 63
  decimals : (decodeV8StablecoinConfig witness.stablecoin).collateralDecimals ≤ 18
  retiredBoolean : BooleanWord (decodeV8StablecoinConfig witness.stablecoin).retiredPresent

theorem stable_zero_word (witness : V8StablecoinWitness) (zero : StableZeroWords witness.words)
    (index : Nat) : stableWitnessWord witness index = 0 := by
  unfold stableWitnessWord
  cases found : witness.words[index]? with
  | none => simp only [List.getD_eq_getElem?_getD, found, Option.getD_none]
  | some value =>
      have isZero : value = 0 :=
        of_decide_eq_true (List.all_eq_true.mp zero value (List.mem_of_getElem? found))
      simp only [List.getD_eq_getElem?_getD, found, Option.getD_some, isZero]

theorem valid_numeric_input_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) : NumericInputBounds statement witness := by
  have transition : exactV8StableTransition (derivedRelationContext statement) statement.stablecoin
      witness.stablecoin := valid.2.2.2.2
  cases mode : statement.stablecoin.direction with
  | disabled =>
      simp only [exactV8StableTransition, mode] at transition
      have asset := transition.2.2.1
      have debt := transition.2.2.2.2.2.2.2.2.2.2.1
      have zero := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      have words := stable_zero_word witness.stablecoin zero
      refine ⟨?_, transition.2.1, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals simp only [decodeV8StablecoinConfig, decodeV8StablecoinBefore, words, asset, debt]
      all_goals first | decide | exact Or.inl rfl
  | mint =>
      simp only [exactV8StableTransition, mode] at transition
      have encoding := transition.1
      have common := transition.2.2.2.2.2.2.2.2.2.2.2.2.1
      have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp only [mode] at branch
      have afterDebt := branch.2.2.2.2.2.2.2.2.1
      obtain ⟨_, cap, amount, minted, _, _, retired, _, oracleMax, _, attestationMax,
        _, _, _, _, _, _, decimals, _⟩ := common
      refine ⟨?_, transition.2.2.1, encoding.2.2.2.2.2.1,
        encoding.2.2.2.2.2.2.1, encoding.2.2.2.2.2.2.2.1,
        cap, amount, afterDebt, minted, retired, oracleMax, attestationMax, decimals,
        encoding.2.2.2.2.1⟩
      rw [transition.2.2.2.2.2.2.2.2.2.2.1]
      exact encoding.2.1
  | burn =>
      simp only [exactV8StableTransition, mode] at transition
      have encoding := transition.1
      have common := transition.2.2.2.2.2.2.2.2.2.2.2.2.1
      have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp only [mode] at branch
      have afterDebt := branch.2.2.2.2.2.1
      obtain ⟨_, cap, amount, minted, debt, _, retired, _, oracleMax, _, attestationMax,
        _, _, _, _, _, _, decimals, _⟩ := common
      refine ⟨?_, transition.2.2.1, encoding.2.2.2.2.2.1,
        encoding.2.2.2.2.2.2.1, encoding.2.2.2.2.2.2.2.1,
        cap, amount, ?_, minted, retired, oracleMax, attestationMax, decimals,
        encoding.2.2.2.2.1⟩
      · rw [transition.2.2.2.2.2.2.2.2.2.2.1]
        exact encoding.2.1
      · rw [afterDebt]
        exact lt_of_le_of_lt (Nat.sub_le _ _) debt

theorem decimal_accumulator_bound (decimals bit : Nat) (decimalBound : decimals ≤ 18)
    (bitBound : bit < 5) : sourceDecimalAccumulator decimals (bit + 1) ≤ 10 ^ 18 := by
  have exactBound : ∀ d : Fin 19, ∀ b : Fin 5,
      sourceDecimalAccumulator d.val (b.val + 1) ≤ 10 ^ 18 := by decide
  exact exactBound ⟨decimals,by omega⟩ ⟨bit,bitBound⟩

theorem decimal_power_bound (bit : Nat) (bitBound : bit < 5) : 10 ^ (2 ^ bit) ≤ 10 ^ 16 := by
  have exactBound : ∀ b : Fin 5, 10 ^ (2 ^ b.val) ≤ 10 ^ 16 := by decide
  exact exactBound ⟨bit,bitBound⟩


end HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
