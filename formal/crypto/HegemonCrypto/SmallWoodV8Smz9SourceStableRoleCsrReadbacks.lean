import HegemonCrypto.SmallWoodV8Smz9SourceStableRoleCsrSymbolic
import HegemonCrypto.SmallWoodV8Smz9SourceSimpleLiveCsrRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrReadbacks

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleLiveCsrRoots
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
open HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrSymbolic
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

def fullSourceField (statement : V8PublicStatement) (witness : V8Witness) (index : Nat) : F :=
  ((fullTypedSourceCandidate statement witness).getD index 0 : F)

theorem full_source_commitment (statement : V8PublicStatement) (witness : V8Witness)
    (role : Fin 5) (limb : Fin 7) :
    fullSourceField statement witness (41408 + roleCommitmentStart role.val + limb.val) =
      (sourceCommitmentWord witness.stablecoin role.val limb.val : F) := by
  have bound : roleCommitmentStart role.val + limb.val < 128 := by
    fin_cases role <;> simp only [roleCommitmentStart,List.getD_cons_zero,List.getD_cons_succ] <;> omega
  have address : 41408 + roleCommitmentStart role.val + limb.val =
      41408 + (roleCommitmentStart role.val + limb.val) := by omega
  unfold fullSourceField
  rw [address,full_live_source_field statement witness ⟨_,bound⟩]
  exact source_commitment_field_readback statement witness role limb

theorem full_source_issuer (statement : V8PublicStatement) (witness : V8Witness) (limb : Fin 7) :
    fullSourceField statement witness (41491 + limb.val) =
      (stableWitnessWord witness.stablecoin (87 + limb.val) : F) := by
  have address : 41491 + limb.val = 41408 + (83 + limb.val) := by omega
  unfold fullSourceField
  rw [address,full_live_source_field statement witness ⟨83 + limb.val,by omega⟩]
  exact congrArg (fun word : Nat => (word : F))
    (stable_source_issuer_readback statement witness limb.val limb.isLt)

theorem full_source_oracle_numerator (statement : V8PublicStatement) (witness : V8Witness) :
    fullSourceField statement witness 41425 =
      ((decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator : F) := by
  exact congrArg (fun word : Nat => (word : F))
    (full_candidate_source_word_readback statement witness ⟨17,by decide⟩)

theorem full_source_oracle_denominator (statement : V8PublicStatement) (witness : V8Witness) :
    fullSourceField statement witness 41426 =
      ((decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator : F) := by
  exact congrArg (fun word : Nat => (word : F))
    (full_candidate_source_word_readback statement witness ⟨18,by decide⟩)

theorem full_source_asset (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    fullSourceField statement witness 41408 = (statement.stablecoin.assetId : F) := by
  exact (full_live_source_field statement witness ⟨0,by decide⟩).trans
    (congrArg (fun word : Nat => (word : F))
      (typed_stable_public_scalar_copies statement witness valid).1)

theorem full_source_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 21) (limb : Fin 7) :
    fullSourceField statement witness (41536 + role.val + 64 * limb.val) =
      stableLinearRoleValue statement witness role.val limb.val := by
  have address : (647 + TailFamily.roleDifference.base + limb.val) * 64 + role.val =
      41536 + role.val + 64 * limb.val := by simp only [TailFamily.base]; omega
  have readback := full_candidate_tail_flat_field_readback statement witness .roleDifference
    limb.val limb.isLt ⟨role.val,by omega⟩
  rw [address] at readback
  change fullSourceField statement witness _ =
    (sourceRoleWord statement witness (typedSourceFinals statement witness) role.val limb.val : F) at readback
  rw [sourceRoleWord,if_pos role.isLt] at readback
  exact readback.trans (source_stable_live_role_linear statement witness valid role limb)

def typedStableExtra (statement : V8PublicStatement) (witness : V8Witness) (role limb : Nat) : F :=
  if role < 5 then -typedEnabled statement * (sourceCommitmentWord witness.stablecoin role limb : F)
  else if role < 15 then
    -typedEnabled statement * (sourceCommitmentWord witness.stablecoin (rolePair role).1 limb : F) +
      typedEnabled statement * (sourceCommitmentWord witness.stablecoin (rolePair role).2 limb : F)
  else if role = 15 then -typedMint statement * (stableWitnessWord witness.stablecoin (87 + limb) : F)
  else if role = 16 then 0
  else if role = 17 then
    (if limb = 0 then -typedMint statement else 0) *
      ((decodeV8StablecoinConfig witness.stablecoin).oraclePriceNumerator : F)
  else if role = 18 then
    (if limb = 0 then -typedMint statement else 0) *
      ((decodeV8StablecoinConfig witness.stablecoin).oraclePriceDenominator : F)
  else if role = 19 then
    (if limb = 0 then -typedEnabled statement else 0) * (statement.stablecoin.assetId : F)
  else 0

def typedStableTarget (statement : V8PublicStatement) (role limb : Nat) : F :=
  if role < 15 then (1 - typedEnabled statement) * fieldUnit limb
  else if role = 15 then (1 - typedMint statement) * fieldUnit limb
  else if role = 16 then
    (1 - typedEnabled statement + (statement.stablecoin.magnitude : F) * typedEnabled statement) * fieldUnit limb
  else if role = 17 ∨ role = 18 then (1 - typedMint statement) * fieldUnit limb
  else if role = 19 then (1 - typedEnabled statement) * fieldUnit limb
  else typedEnabled statement * (wordAt statement.stablecoin.actionIntent limb : F) +
    (1 - typedEnabled statement) * fieldUnit limb

theorem role_pair_bounds (role : Fin 15) (lower : 5 ≤ role.val) :
    (rolePair role.val).1 < 5 ∧ (rolePair role.val).2 < 5 := by
  have checked : ∀ r : Fin 15, 5 ≤ r.val →
      (rolePair r.val).1 < 5 ∧ (rolePair r.val).2 < 5 := by decide
  exact checked role lower

theorem stable_extra_full_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 21) (limb : Fin 7) :
    stableExtraContribution (liveTypedPub statement) (fullSourceField statement witness) role.val limb.val =
      typedStableExtra statement witness role.val limb.val := by
  have coefficients := live_typed_direction_coefficients statement witness valid
  by_cases small : role.val < 5
  · simp only [stableExtraContribution,typedStableExtra,if_pos small,coefficients.2.2]
    rw [full_source_commitment statement witness ⟨role.val,small⟩ limb]
  by_cases pair : role.val < 15
  · have bounds := role_pair_bounds ⟨role.val,pair⟩ (by change 5 ≤ role.val; omega)
    simp only [stableExtraContribution,typedStableExtra,if_neg small,if_pos pair,coefficients.2.2]
    rw [full_source_commitment statement witness ⟨(rolePair role.val).1,bounds.1⟩ limb,
      full_source_commitment statement witness ⟨(rolePair role.val).2,bounds.2⟩ limb]
  have choices : role.val = 15 ∨ role.val = 16 ∨ role.val = 17 ∨
      role.val = 18 ∨ role.val = 19 ∨ role.val = 20 := by omega
  rcases choices with r | r | r | r | r | r <;>
    simp [stableExtraContribution,typedStableExtra,r,coefficients.1,coefficients.2.2,
      full_source_issuer statement witness limb,full_source_oracle_numerator,
      full_source_oracle_denominator,full_source_asset statement witness valid]

theorem stable_target_typed_readback (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 21) (limb : Fin 7) :
    stableTargetValue (liveTypedPub statement) role.val limb.val =
      typedStableTarget statement role.val limb.val := by
  have coefficients := live_typed_direction_coefficients statement witness valid
  have magnitude : liveTypedPub statement 86 = (statement.stablecoin.magnitude : F) :=
    congrArg (fun word : Nat => (word : F))
      (encoded_stable_public_scalars statement witness valid).2.2.2
  have intent : liveTypedPub statement (87 + limb.val) =
      (wordAt statement.stablecoin.actionIntent limb.val : F) :=
    congrArg (fun word : Nat => (word : F))
      (encoded_stable_action_intent_word statement witness valid limb)
  simp only [stableTargetValue,typedStableTarget,coefficients.1,coefficients.2.2,magnitude,intent]

theorem typed_stable_role_cancellation (statement : V8PublicStatement) (witness : V8Witness)
    (role : Fin 21) (limb : Nat) :
    stableLinearRoleValue statement witness role.val limb +
      typedStableExtra statement witness role.val limb - typedStableTarget statement role.val limb = 0 := by
  have pairs : sourceStablePairs =
      [(0,1),(0,2),(0,3),(0,4),(1,2),(1,3),(1,4),(2,3),(2,4),(3,4)] := by decide
  fin_cases role <;> by_cases zero : limb = 0 <;>
    simp [stableLinearRoleValue,typedStableExtra,typedStableTarget,pairs,
      rolePair,sourceUnitWord,fieldUnit,zero] <;> ring

theorem full_stable_role_kernel_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 21) (limb : Fin 7) :
    roleCsrFieldKernel (liveTypedPub statement) (fullSourceField statement witness) role.val limb.val = 0 := by
  rw [stable_role_field_kernel_symbolic,full_source_role_linear statement witness valid,
    stable_extra_full_readback statement witness valid,stable_target_typed_readback statement witness valid]
  exact typed_stable_role_cancellation statement witness role limb.val


end
end HegemonCrypto.SmallWood.V8Smz9SourceStableRoleCsrReadbacks
