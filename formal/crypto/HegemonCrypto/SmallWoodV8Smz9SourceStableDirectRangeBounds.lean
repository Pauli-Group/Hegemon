import HegemonCrypto.SmallWoodV8Smz9SourceTailCheckedSubtractions
import HegemonCrypto.SmallWoodV8Smz9SourceSimpleStableCsr

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableDirectRangeBounds
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

structure SourceStableDirectBounds (statement : V8PublicStatement) (witness : V8Witness) : Prop where
  configAsset : (decodeV8StablecoinConfig witness.stablecoin).assetId < 2^32
  configPolicy : (decodeV8StablecoinConfig witness.stablecoin).policyVersion < 2^32
  collateralAsset : (decodeV8StablecoinConfig witness.stablecoin).collateralAssetId < 2^32
  enabledAt : (decodeV8StablecoinConfig witness.stablecoin).enabledAt < 2^63
  oracleSubmittedAt : (decodeV8StablecoinConfig witness.stablecoin).oracleSubmittedAt < 2^63
  attestationCreatedAt : (decodeV8StablecoinConfig witness.stablecoin).attestationCreatedAt < 2^63
  collateralScale : (decodeV8StablecoinConfig witness.stablecoin).collateralScale < 2^63
  beforeSequence : (decodeV8StablecoinBefore witness.stablecoin).sequence < 2^63
  afterSequence : statement.stablecoin.after.sequence < 2^63
  beforeEpoch : (decodeV8StablecoinBefore witness.stablecoin).epochId < 2^51
  afterEpoch : statement.stablecoin.after.epochId < 2^51
  magnitude : statement.stablecoin.magnitude < 2^56
  beforeTotalDebt : (decodeV8StablecoinBefore witness.stablecoin).totalDebt < 2^56
  afterMinted : statement.stablecoin.after.mintedInEpoch < 2^56

theorem valid_source_stable_direct_bounds (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) : SourceStableDirectBounds statement witness := by
  have numeric := valid_numeric_input_bounds statement witness valid
  have checked := valid_source_checked_subtraction_inputs statement witness valid
  have transition := typed_stable_transition statement witness valid
  by_cases disabled : statement.stablecoin.direction=.disabled
  · simp only [exactV8StableTransition,disabled] at transition
    obtain ⟨_,_,_,_,magnitude,_,_,_,afterEpoch,afterMinted,_,afterSequence,_,_,zero⟩ := transition
    have words := stable_zero_word witness.stablecoin zero
    refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩
    all_goals simp only [decodeV8StablecoinConfig,decodeV8StablecoinBefore,words,
      magnitude,afterEpoch,afterMinted,afterSequence]
    all_goals decide
  · have enabled : exactV8StablecoinEnabledValid (derivedRelationContext statement)
        statement.stablecoin witness.stablecoin := by
      cases mode : statement.stablecoin.direction <;>
        simp only [exactV8StableTransition,mode] at transition
      · exact False.elim (disabled mode)
      · exact transition
      · exact transition
    obtain ⟨canonical,_,_,_,afterSequence,_,_,_,_,magnitude,_,_,common,_,_,branch⟩ := enabled
    obtain ⟨_,configAsset,configPolicy,_,_,_,_,_,_,_,collateralAsset,_,_⟩ := canonical
    obtain ⟨_,_,_,_,beforeDebt,enabledAt,_,oracleSubmittedAt,_,attestationCreatedAt,_,
      collateralScale,_,beforeSequence,_,_,_,_,_⟩ := common
    have currentEpoch : statement.stablecoin.parentHeight/4096<2^51 :=
      (Nat.div_lt_iff_lt_mul (by decide : 0<4096)).mpr numeric.height
    have afterEpoch : statement.stablecoin.after.epochId=statement.stablecoin.parentHeight/4096 := by
      cases mode : statement.stablecoin.direction <;> simp only [mode] at branch
      · exact branch.2.2.2.2.1
      · exact branch.2.2.1
    refine ⟨configAsset,configPolicy,collateralAsset,enabledAt,oracleSubmittedAt,
      attestationCreatedAt,collateralScale,beforeSequence,afterSequence,
      lt_of_le_of_lt (checked.epoch disabled) currentEpoch,?_,magnitude,beforeDebt,
      lt_of_le_of_lt (checked.afterCap disabled) numeric.cap⟩
    rw [afterEpoch]
    exact currentEpoch

end HegemonCrypto.SmallWood.V8Smz9SourceStableDirectRangeBounds
