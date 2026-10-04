import HegemonCrypto.SmallWoodV8Smz9SourceLiveCsrCoefficients
import HegemonCrypto.SmallWoodV8Smz9SourceSimpleStableCsr
import HegemonCrypto.SmallWoodV8Smz9SourceRoleNonzero

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldSub fieldNormalize)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F field_sub_cast)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (normalize_cast)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

def typedMint (statement : V8PublicStatement) : F :=
  if statement.stablecoin.direction = .mint then 1 else 0
def typedBurn (statement : V8PublicStatement) : F :=
  if statement.stablecoin.direction = .burn then 1 else 0
def typedEnabled (statement : V8PublicStatement) : F := typedMint statement + typedBurn statement

def stableLinearRoleValue (statement : V8PublicStatement) (witness : V8Witness)
    (role limb : Nat) : F :=
  let enabled := typedEnabled statement
  let mint := typedMint statement
  let unit := (sourceUnitWord limb : F)
  let config := decodeV8StablecoinConfig witness.stablecoin
  if role < 5 then
    enabled * (sourceCommitmentWord witness.stablecoin role limb : F) + (1 - enabled) * unit
  else if role < 15 then
    let pair := sourceStablePairs.getD (role - 5) (0,0)
    enabled * ((sourceCommitmentWord witness.stablecoin pair.1 limb : F) -
      (sourceCommitmentWord witness.stablecoin pair.2 limb : F)) + (1 - enabled) * unit
  else if role = 15 then
    mint * (stableWitnessWord witness.stablecoin (87 + limb) : F) + (1 - mint) * unit
  else if role = 16 then
    enabled * (if limb = 0 then (statement.stablecoin.magnitude : F) else 0) + (1 - enabled) * unit
  else if role = 17 then
    mint * (if limb = 0 then (config.oraclePriceNumerator : F) else 0) + (1 - mint) * unit
  else if role = 18 then
    mint * (if limb = 0 then (config.oraclePriceDenominator : F) else 0) + (1 - mint) * unit
  else if role = 19 then
    enabled * (if limb = 0 then (statement.stablecoin.assetId : F) else 0) + (1 - enabled) * unit
  else
    enabled * (wordAt statement.stablecoin.actionIntent limb : F) + (1 - enabled) * unit

theorem source_stable_live_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 21) (limb : Fin 7) :
    (sourceStableRoleWord statement.stablecoin witness.stablecoin role.val limb.val : F) =
      stableLinearRoleValue statement witness role.val limb.val := by
  have subCast (left right : Nat) :
      (fieldSub (sourceCommitmentWord witness.stablecoin left limb.val)
        (sourceCommitmentWord witness.stablecoin right limb.val) : F) =
      (sourceCommitmentWord witness.stablecoin left limb.val : F) -
        (sourceCommitmentWord witness.stablecoin right limb.val : F) :=
    field_sub_cast _ _ (by
      have bound := valid_commitment_word_canonical statement witness valid right limb.val
      change sourceCommitmentWord witness.stablecoin right limb.val ≤
        sourceCommitmentWord witness.stablecoin left limb.val + fieldModulus
      omega)
  cases direction : statement.stablecoin.direction <;>
    simp only [sourceStableRoleWord,stableLinearRoleValue,direction,typedEnabled,typedMint,
      typedBurn,reduceCtorEq,↓reduceIte] <;>
    split_ifs <;> simp_all [sourceUnitWord,limb.isLt,normalize_cast] <;> omega

theorem source_commitment_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (role : Fin 5) (limb : Fin 7) :
    (stableSourceWord statement witness (roleCommitmentStart role.val + limb.val) : F) =
      (sourceCommitmentWord witness.stablecoin role.val limb.val : F) := by
  have bound : roleCommitmentStart role.val + limb.val < 55 := by
    fin_cases role <;> simp only [roleCommitmentStart,List.getD_cons_zero,List.getD_cons_succ] <;> omega
  rw [stable_source_config_readback statement witness _ bound]
  simp only [sourceCommitmentWord,if_pos limb.isLt,roleCommitmentStart]

def liveTypedPub (statement : V8PublicStatement) (index : Nat) : F :=
  ((encodePublicStatement statement).getD index 0 : F)

theorem live_typed_direction_coefficients (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    liveMint (liveTypedPub statement) = typedMint statement ∧
    liveBurn (liveTypedPub statement) = typedBurn statement ∧
    liveEnabled (liveTypedPub statement) = typedEnabled statement := by
  have encoded := (encoded_stable_public_scalars statement witness valid).1
  have zero_ne_two : (0 : F) ≠ 2 := by decide
  have one_ne_two : (1 : F) ≠ 2 := by decide
  have two_ne_one : (2 : F) ≠ 1 := by decide
  have mint : liveMint (liveTypedPub statement) = typedMint statement := by
    simp only [liveMint,liveTypedPub,encoded,typedMint]
    cases statement.stablecoin.direction <;>
      simp [StableDirection.word,two_ne_one]
  have burn : liveBurn (liveTypedPub statement) = typedBurn statement := by
    simp only [liveBurn,liveTypedPub,encoded,typedBurn]
    cases statement.stablecoin.direction <;>
      simp [StableDirection.word,zero_ne_two,one_ne_two]
  exact ⟨mint,burn,by rw [liveEnabled,typedEnabled,mint,burn]⟩

theorem live_typed_public_asset_val (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (liveTypedPub statement 84).val = statement.stablecoin.assetId := by
  have bounded := auth_exact_words_getD (valid_public_words_exact statement witness valid) 84
  change ((encodePublicStatement statement).getD 84 0) % fieldModulus = _
  rw [Nat.mod_eq_of_lt bounded]
  exact (encoded_stable_public_scalars statement witness valid).2.1


end HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
