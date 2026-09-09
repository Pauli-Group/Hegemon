import HegemonCrypto.SmallWoodV8Smz9SourceStableArithmetic04
import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableCounterArithmetic
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableArithmetic04
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

structure SourceCounterArithmetic (statement : V8PublicStatement) (witness : V8Witness) : Prop where
  epoch : (decodeV8StablecoinBefore witness.stablecoin).epochId +
    (sourceAux statement.stablecoin witness.stablecoin).epochGap = statement.stablecoin.after.epochId
  clock : statement.stablecoin.direction ≠ .disabled →
    statement.stablecoin.after.epochId * 4096 +
      (sourceAux statement.stablecoin witness.stablecoin).epochRemainder = statement.stablecoin.parentHeight
  beforeCap : (decodeV8StablecoinBefore witness.stablecoin).mintedInEpoch +
    (sourceAux statement.stablecoin witness.stablecoin).beforeCapSlack =
      (decodeV8StablecoinConfig witness.stablecoin).maxMintPerEpoch
  afterCap : statement.stablecoin.after.mintedInEpoch +
    (sourceAux statement.stablecoin witness.stablecoin).afterCapSlack =
      (decodeV8StablecoinConfig witness.stablecoin).maxMintPerEpoch
  minted : statement.stablecoin.after.mintedInEpoch =
    (sourceAux statement.stablecoin witness.stablecoin).sameEpoch *
      (decodeV8StablecoinBefore witness.stablecoin).mintedInEpoch +
        (if statement.stablecoin.direction = .mint then statement.stablecoin.magnitude else 0)
  sequence : statement.stablecoin.after.sequence =
    (decodeV8StablecoinBefore witness.stablecoin).sequence +
      (if statement.stablecoin.direction = .disabled then 0 else 1)

theorem valid_source_counter_arithmetic (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) : SourceCounterArithmetic statement witness := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · have transition := typed_stable_transition statement witness valid
    simp only [exactV8StableTransition,disabled] at transition
    obtain ⟨_,_,_,_,_,_,_,_,epoch,minted,_,sequence,_,_,zero⟩ := transition
    have words := stable_zero_word witness.stablecoin zero
    refine ⟨?_,?_,?_,?_,?_,?_⟩
    all_goals simp [sourceAux,disabled,disabledSourceAux,decodeV8StablecoinConfig,
      decodeV8StablecoinBefore,words,epoch,minted,sequence]
  · have transition := typed_stable_enabled_transition statement witness valid disabled
    have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
    obtain ⟨_,beforeCap,afterCap,epoch,clock,_⟩ :=
      valid_source_aux_checked_arithmetic statement witness valid disabled
    have afterEpoch : statement.stablecoin.after.epochId = statement.stablecoin.parentHeight / 4096 := by
      cases mode : statement.stablecoin.direction <;> simp only [mode] at branch
      · exact branch.2.2.2.2.1
      · exact branch.2.2.1
    refine ⟨?_,?_,beforeCap,afterCap,?_,?_⟩
    · rw [afterEpoch]; exact epoch
    · intro _; rw [afterEpoch]; exact clock
    · cases mode : statement.stablecoin.direction <;> simp only [mode] at branch
      · have minted := branch.2.2.2.2.2.1
        rw [minted]
        simp [sourceAux,mode,stablecoinV8EpochHeightShift,ite_mul]
      · have minted := branch.2.2.2.1
        rw [minted]
        simp [sourceAux,mode,stablecoinV8EpochHeightShift,ite_mul]
    · cases mode : statement.stablecoin.direction <;> simp only [mode] at branch
      · simpa only [reduceCtorEq,if_false] using branch.2.2.2.2.2.2.2.2.2.1
      · simpa only [reduceCtorEq,if_false] using branch.2.2.2.2.2.2.1

theorem valid_source_mint_config (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (mint : statement.stablecoin.direction = .mint) :
    let config := decodeV8StablecoinConfig witness.stablecoin
    config.active = 1 ∧ config.attestationDisputed = 0 ∧ config.attestationPresent = 1 ∧
      1000000 + (sourceAux statement.stablecoin witness.stablecoin).ratioSlack = config.minCollateralRatioPpm := by
  have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
  have transition := typed_stable_enabled_transition statement witness valid active
  have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  simp only [mint] at branch
  obtain ⟨flag,_,_,_,_,_,_,_,_,present,_,disputed⟩ := branch.1
  have checked := (valid_source_aux_checked_arithmetic statement witness valid active).2.2.2.2.2 mint
  exact ⟨flag,disputed,present,checked.2.2.1⟩

theorem valid_source_mint_collateral (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (mint : statement.stablecoin.direction = .mint) :
    let config := decodeV8StablecoinConfig witness.stablecoin
    statement.stablecoin.after.totalDebt * config.oraclePriceDenominator * config.minCollateralRatioPpm ≤
      config.collateralAmount * config.oraclePriceNumerator * 1000000 := by
  have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
  have transition := typed_stable_enabled_transition statement witness valid active
  have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
  simp only [mint] at branch
  exact branch.2.2.2.2.2.2.2.2.2.2.1

noncomputable section
theorem typed_enabled_nat (statement : V8PublicStatement) :
    typedEnabled statement = ((if statement.stablecoin.direction = .disabled then 0 else 1 : Nat) : F) := by
  cases mode : statement.stablecoin.direction <;> simp [typedEnabled,typedMint,typedBurn,mode]

theorem typed_mint_nat_amount (statement : V8PublicStatement) :
    ((if statement.stablecoin.direction = .mint then statement.stablecoin.magnitude else 0 : Nat) : F) =
      typedMint statement * (statement.stablecoin.magnitude : F) := by
  cases mode : statement.stablecoin.direction <;> simp [typedMint,mode]

theorem valid_source_debt_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (statement.stablecoin.after.totalDebt : F) =
      ((decodeV8StablecoinBefore witness.stablecoin).totalDebt : F) +
        (typedMint statement - typedBurn statement) * (statement.stablecoin.magnitude : F) := by
  have transition := typed_stable_transition statement witness valid
  cases mode : statement.stablecoin.direction with
  | disabled =>
    simp only [exactV8StableTransition,mode] at transition
    obtain ⟨_,_,_,_,_,_,_,_,_,_,debt,_,_,_,zero⟩ := transition
    have words := stable_zero_word witness.stablecoin zero
    simp [typedMint,typedBurn,mode,debt,decodeV8StablecoinBefore,words]
  | mint =>
    simp only [exactV8StableTransition,mode] at transition
    have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
    simp only [mode] at branch
    rw [branch.2.2.2.2.2.2.2.1]
    simp [typedMint,typedBurn,mode,Nat.cast_add]
  | burn =>
    simp only [exactV8StableTransition,mode] at transition
    have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
    simp only [mode] at branch
    rw [branch.2.2.2.2.2.1,Nat.cast_sub branch.2.2.2.2.1]
    simp [typedMint,typedBurn,mode,sub_eq_add_neg]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableCounterArithmetic
