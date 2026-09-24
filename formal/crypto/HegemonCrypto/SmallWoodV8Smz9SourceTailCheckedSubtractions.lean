import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericCanonical

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

/-- Only the actual typed inputs; no freely supplied source auxiliary record. -/
structure SourceCheckedSubtractionInputs (stablePublic : V8StablecoinPublic)
    (witness : V8StablecoinWitness) : Prop where
  decimals : (decodeV8StablecoinConfig witness).collateralDecimals ≤ 18
  beforeCap : stablePublic.direction ≠ .disabled →
    (decodeV8StablecoinBefore witness).mintedInEpoch ≤ (decodeV8StablecoinConfig witness).maxMintPerEpoch
  afterCap : stablePublic.direction ≠ .disabled →
    stablePublic.after.mintedInEpoch ≤ (decodeV8StablecoinConfig witness).maxMintPerEpoch
  epoch : stablePublic.direction ≠ .disabled →
    (decodeV8StablecoinBefore witness).epochId ≤ stablePublic.parentHeight / 4096
  enabled : stablePublic.direction = .mint → (decodeV8StablecoinConfig witness).enabledAt ≤ stablePublic.parentHeight
  retired : stablePublic.direction = .mint → (decodeV8StablecoinConfig witness).retiredPresent = 1 →
    (decodeV8StablecoinConfig witness).enabledAt < (decodeV8StablecoinConfig witness).retiredAt ∧
    stablePublic.parentHeight < (decodeV8StablecoinConfig witness).retiredAt
  ratio : stablePublic.direction = .mint → 1000000 ≤ (decodeV8StablecoinConfig witness).minCollateralRatioPpm
  oracle : stablePublic.direction = .mint →
    (decodeV8StablecoinConfig witness).oracleSubmittedAt ≤ stablePublic.parentHeight ∧
    stablePublic.parentHeight - (decodeV8StablecoinConfig witness).oracleSubmittedAt ≤
      (decodeV8StablecoinConfig witness).oracleMaxAge
  attestation : stablePublic.direction = .mint →
    (decodeV8StablecoinConfig witness).attestationCreatedAt ≤ stablePublic.parentHeight ∧
    stablePublic.parentHeight - (decodeV8StablecoinConfig witness).attestationCreatedAt ≤
      (decodeV8StablecoinConfig witness).attestationMaxAge

theorem valid_source_checked_subtraction_inputs (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    SourceCheckedSubtractionInputs statement.stablecoin witness.stablecoin := by
  have numeric := valid_numeric_input_bounds statement witness valid
  have transition : exactV8StableTransition (derivedRelationContext statement) statement.stablecoin
      witness.stablecoin := valid.2.2.2.2
  cases mode : statement.stablecoin.direction with
  | disabled =>
      refine ⟨numeric.decimals, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals simp [mode]
  | mint =>
      simp only [exactV8StableTransition, mode] at transition
      have common := transition.2.2.2.2.2.2.2.2.2.2.2.2.1
      have epoch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1
      have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp only [mode] at branch
      have policy := branch.1
      have afterCap := branch.2.2.2.2.2.2.1
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,beforeCap,_,_,_,_⟩ := common
      obtain ⟨_,enabled,retired,ratio,_,_,oracle,oracleSlack,attestation,_,attestationSlack,_⟩ := policy
      exact ⟨numeric.decimals,fun _ => beforeCap,fun _ => afterCap,fun _ => epoch,
        fun _ => enabled,fun _ => retired,fun _ => ratio,
        fun _ => ⟨oracle,oracleSlack⟩,fun _ => ⟨attestation,attestationSlack⟩⟩
  | burn =>
      simp only [exactV8StableTransition, mode] at transition
      have common := transition.2.2.2.2.2.2.2.2.2.2.2.2.1
      have epoch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1
      have branch := transition.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp only [mode] at branch
      have afterMinted := branch.2.2.2.1
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,beforeCap,_,_,_,_⟩ := common
      refine ⟨numeric.decimals,fun _ => beforeCap,?_,fun _ => epoch,?_,?_,?_,?_,?_⟩
      · intro _
        rw [afterMinted]
        split_ifs
        · exact beforeCap
        · exact Nat.zero_le _
      all_goals intro mint; rw [mode] at mint; cases mint

/-- Recomposition proves that the corresponding Nat subtractions do not saturate.
This is not a claim that every Rust source constructor check has been discharged. -/
def SourceAuxCheckedArithmetic (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness) : Prop :=
  let config := decodeV8StablecoinConfig witness
  let before := decodeV8StablecoinBefore witness
  let aux := sourceAux stablePublic witness
  stablePublic.direction ≠ .disabled →
    config.collateralDecimals + (18 - config.collateralDecimals) = 18 ∧
    before.mintedInEpoch + aux.beforeCapSlack = config.maxMintPerEpoch ∧
    stablePublic.after.mintedInEpoch + aux.afterCapSlack = config.maxMintPerEpoch ∧
    before.epochId + aux.epochGap = stablePublic.parentHeight / 4096 ∧
    (stablePublic.parentHeight / 4096) * 4096 + aux.epochRemainder = stablePublic.parentHeight ∧
    (stablePublic.direction = .mint →
      config.enabledAt + aux.enabledAge = stablePublic.parentHeight ∧
      (config.retiredPresent = 1 →
        config.enabledAt + aux.retirementOrderGap + 1 = config.retiredAt ∧
        stablePublic.parentHeight + aux.retirementHeightGap + 1 = config.retiredAt) ∧
      1000000 + aux.ratioSlack = config.minCollateralRatioPpm ∧
      config.oracleSubmittedAt + aux.oracleAge = stablePublic.parentHeight ∧
      aux.oracleAge + aux.oracleSlack = config.oracleMaxAge ∧
      config.attestationCreatedAt + aux.attestationAge = stablePublic.parentHeight ∧
      aux.attestationAge + aux.attestationSlack = config.attestationMaxAge)

theorem source_aux_checked_arithmetic (stablePublic : V8StablecoinPublic) (witness : V8StablecoinWitness)
    (inputs : SourceCheckedSubtractionInputs stablePublic witness) : SourceAuxCheckedArithmetic stablePublic witness := by
  intro active
  have beforeCap := inputs.beforeCap active
  have afterCap := inputs.afterCap active
  have epoch := inputs.epoch active
  have decimals := inputs.decimals
  have epochProduct := Nat.div_mul_le_self stablePublic.parentHeight 4096
  simp only [sourceAux, if_neg active]
  refine ⟨by omega,by omega,by omega,by omega,by omega,?_⟩
  intro mint
  have enabled := inputs.enabled mint
  have ratio := inputs.ratio mint
  have oracle := inputs.oracle mint
  have attestation := inputs.attestation mint
  simp only [if_pos mint]
  refine ⟨by omega,?_,by omega,by omega,by omega,by omega,by omega⟩
  intro retired
  have retiredBounds := inputs.retired mint retired
  simp only [if_pos (And.intro mint retired)]
  omega

theorem valid_source_aux_checked_arithmetic (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    SourceAuxCheckedArithmetic statement.stablecoin witness.stablecoin :=
  source_aux_checked_arithmetic _ _ (valid_source_checked_subtraction_inputs statement witness valid)

theorem source_epoch_remainder (height : Nat) : height - (height / 4096) * 4096 = height % 4096 := by
  have equation := Nat.mod_add_div height 4096
  omega

theorem valid_aux_epoch_and_path_ranges (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    aux.epochGap < 2 ^ 51 ∧ aux.epochRemainder < 2 ^ 12 ∧ aux.pathQuotient < 2 ^ 28 := by
  have numeric := valid_numeric_input_bounds statement witness valid
  by_cases disabled : statement.stablecoin.direction = .disabled
  · rw [source_aux_disabled _ _ disabled]
    exact ⟨by decide,by decide,by decide⟩
  · have epoch : statement.stablecoin.parentHeight / 4096 < 2 ^ 51 :=
      (Nat.div_lt_iff_lt_mul (by decide : 0 < 4096)).mpr numeric.height
    have path : statement.stablecoin.assetId / 16 < 2 ^ 28 :=
      (Nat.div_lt_iff_lt_mul (by decide : 0 < 16)).mpr numeric.asset
    simp only [sourceAux, if_neg disabled]
    refine ⟨lt_of_le_of_lt (Nat.sub_le _ _) epoch,?_,path⟩
    rw [source_epoch_remainder]
    exact Nat.mod_lt _ (by decide)

/-- Both source three-factor products are below u128 from the actual typed bounds. -/
theorem typed_mul3_products_fit_u128 (x y z : Nat) (xBound : x < 2 ^ 56)
    (yBound : y < 2 ^ 32) (zBound : z < 2 ^ 32) :
    x * y < 2 ^ 128 ∧ x * y * z < 2 ^ 128 := by
  have first := Nat.mul_le_mul (show x ≤ 72057594037927935 by omega)
    (show y ≤ 4294967295 by omega)
  have firstBound : x * y ≤ 309485009821345068724781055 := by norm_num at first ⊢; omega
  have second := Nat.mul_le_mul firstBound (show z ≤ 4294967295 by omega)
  norm_num at second ⊢
  omega


end HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
