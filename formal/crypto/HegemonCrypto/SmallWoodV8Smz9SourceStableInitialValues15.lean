import HegemonCrypto.SmallWoodV8Smz9SourceStableCounterArithmetic

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableInitialValues15
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableArithmetic04
open HegemonCrypto.SmallWood.V8Smz9SourceStableCounterArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

def sourceInitialValue (statement : V8PublicStatement) (witness : V8Witness) (index : Nat) : F :=
  let config := decodeV8StablecoinConfig witness.stablecoin
  let before := decodeV8StablecoinBefore witness.stablecoin
  let aux := sourceAux statement.stablecoin witness.stablecoin
  let mint := typedMint statement
  let enabled := typedEnabled statement
  match index with
  | 0 => (statement.stablecoin.assetId : F) - ((sourceFourBits aux.pathBits : F) + 16 * (aux.pathQuotient : F))
  | 1 => (config.collateralDecimals : F) - (sourceFiveBits aux.decimalBits : F)
  | 2 => (config.collateralDecimals : F) + (sourceFiveBits aux.decimalSlackBits : F) - 18 * enabled
  | 3 => enabled * ((config.collateralScale : F) - (aux.decimalAccumulators 4 : F))
  | 4 => (before.epochId : F) + (aux.epochGap : F) - (statement.stablecoin.after.epochId : F)
  | 5 => enabled * ((statement.stablecoin.parentHeight : F) - (statement.stablecoin.after.epochId : F) * 4096 - (aux.epochRemainder : F))
  | 6 => (before.mintedInEpoch : F) + (aux.beforeCapSlack : F) - (config.maxMintPerEpoch : F)
  | 7 => (statement.stablecoin.after.mintedInEpoch : F) + (aux.afterCapSlack : F) - (config.maxMintPerEpoch : F)
  | 8 => (statement.stablecoin.after.mintedInEpoch : F) - (aux.sameEpoch : F) * (before.mintedInEpoch : F) - mint * (statement.stablecoin.magnitude : F)
  | 9 => (statement.stablecoin.after.totalDebt : F) - (before.totalDebt : F) - (mint - typedBurn statement) * (statement.stablecoin.magnitude : F)
  | 10 => (statement.stablecoin.after.sequence : F) - (before.sequence : F) - enabled
  | 11 => mint * ((config.active : F) - 1)
  | 12 => mint * (config.attestationDisputed : F)
  | 13 => mint * ((config.attestationPresent : F) - 1)
  | _ => mint * ((config.minCollateralRatioPpm : F) - (aux.ratioSlack : F) - 1000000)

theorem valid_source_initial_values_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 15) :
    sourceInitialValue statement witness index.val = 0 := by
  have asset := congrArg (fun value : Nat => (value : F)) (valid_source_asset_reconstruction statement witness valid)
  have decimal := congrArg (fun value : Nat => (value : F)) (valid_source_decimal_reconstruction statement witness valid)
  have slack := congrArg (fun value : Nat => (value : F)) (valid_source_decimal_slack statement witness valid)
  have counters := valid_source_counter_arithmetic statement witness valid
  have epoch := congrArg (fun value : Nat => (value : F)) counters.epoch
  have beforeCap := congrArg (fun value : Nat => (value : F)) counters.beforeCap
  have afterCap := congrArg (fun value : Nat => (value : F)) counters.afterCap
  have minted := congrArg (fun value : Nat => (value : F)) counters.minted
  have sequence := congrArg (fun value : Nat => (value : F)) counters.sequence
  have debt := valid_source_debt_field statement witness valid
  simp only [Nat.cast_add,Nat.cast_mul,Nat.cast_ofNat,typed_mint_nat_amount,←typed_enabled_nat] at asset slack epoch beforeCap afterCap minted sequence
  fin_cases index <;> norm_num only [sourceInitialValue]
  · linear_combination -asset
  · exact sub_eq_zero.mpr decimal
  · linear_combination slack
  · by_cases disabled : statement.stablecoin.direction = .disabled
    · simp [typed_enabled_nat,disabled]
    · have scale := congrArg (fun value : Nat => (value : F))
        (valid_source_collateral_scale statement witness valid disabled)
      rw [scale,sub_self,mul_zero]
  · linear_combination epoch
  · by_cases disabled : statement.stablecoin.direction = .disabled
    · simp [typed_enabled_nat,disabled]
    · have clock := congrArg (fun value : Nat => (value : F)) (counters.clock disabled)
      simp only [Nat.cast_add,Nat.cast_mul,Nat.cast_ofNat] at clock
      have zero : (statement.stablecoin.parentHeight : F) - (statement.stablecoin.after.epochId : F) * 4096 -
          ((sourceAux statement.stablecoin witness.stablecoin).epochRemainder : F) = 0 := by
        linear_combination -clock
      rw [zero,mul_zero]
  · linear_combination beforeCap
  · linear_combination afterCap
  · linear_combination minted
  · linear_combination debt
  · linear_combination sequence
  · by_cases mint : statement.stablecoin.direction = .mint
    · rw [(valid_source_mint_config statement witness valid mint).1,Nat.cast_one,sub_self,mul_zero]
    · simp [typedMint,mint]
  · by_cases mint : statement.stablecoin.direction = .mint
    · rw [(valid_source_mint_config statement witness valid mint).2.1,Nat.cast_zero,mul_zero]
    · simp [typedMint,mint]
  · by_cases mint : statement.stablecoin.direction = .mint
    · rw [(valid_source_mint_config statement witness valid mint).2.2.1,Nat.cast_one,sub_self,mul_zero]
    · simp [typedMint,mint]
  · change typedMint statement * (((decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm : F) -
        ((sourceAux statement.stablecoin witness.stablecoin).ratioSlack : F) - 1000000) = 0
    by_cases mint : statement.stablecoin.direction = .mint
    · have ratio := congrArg (fun value : Nat => (value : F))
        (valid_source_mint_config statement witness valid mint).2.2.2
      simp only [Nat.cast_add,Nat.cast_ofNat] at ratio
      have zero : ((decodeV8StablecoinConfig witness.stablecoin).minCollateralRatioPpm : F) -
          ((sourceAux statement.stablecoin witness.stablecoin).ratioSlack : F) - 1000000 = 0 := by
        linear_combination -ratio
      rw [zero,mul_zero]
    · simp [typedMint,mint]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableInitialValues15
