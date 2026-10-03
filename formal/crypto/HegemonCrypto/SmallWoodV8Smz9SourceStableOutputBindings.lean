import HegemonCrypto.SmallWoodV8Smz9SourceStableStateForward
import HegemonCrypto.SmallWoodV8Smz9SourceSimpleStableCsr

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableOutputBindings
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateForward
open HegemonCrypto.SmallWood.V8Smz9SourceStablePathFrames
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
attribute [local irreducible] Poseidon2Width16Kernel.permutation poseidon2V8Compress14

theorem typed_stable_enabled_state_roots (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (enabled : statement.stablecoin.direction=.mint ∨ statement.stablecoin.direction=.burn) :
    exactV8StablecoinRoot statement.stablecoin.assetId
        (exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin))
        (decodeV8StablecoinBefore witness.stablecoin)
        (decodeV8StablecoinSiblings witness.stablecoin) = statement.stablecoin.beforeRoot ∧
    exactV8StablecoinRoot statement.stablecoin.assetId
        (exactV8StablecoinConfigDigest (decodeV8StablecoinConfig witness.stablecoin))
        statement.stablecoin.after (decodeV8StablecoinSiblings witness.stablecoin) =
      statement.stablecoin.afterRoot := by
  rcases enabled with mint | burn
  · have transition := typed_stable_transition statement witness valid
    simp only [exactV8StableTransition,mint] at transition
    dsimp only [exactV8StablecoinEnabledValid] at transition
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,beforeRoot,_,branch⟩ := transition
    simp only [mint] at branch
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,afterRoot⟩ := branch
    exact ⟨beforeRoot,afterRoot⟩
  · have transition := typed_stable_transition statement witness valid
    simp only [exactV8StableTransition,burn] at transition
    dsimp only [exactV8StablecoinEnabledValid] at transition
    obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,beforeRoot,_,branch⟩ := transition
    simp only [burn] at branch
    obtain ⟨_,_,_,_,_,_,_,afterRoot⟩ := branch
    exact ⟨beforeRoot,afterRoot⟩

theorem typed_stable_disabled_roots (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (disabled : statement.stablecoin.direction=.disabled) :
    statement.stablecoin.beforeRoot=statement.stablecoin.afterRoot := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition,disabled] at transition
  obtain ⟨_,_,_,_,_,_,before,after,_⟩ := transition
  exact before.trans after.symm

theorem typed_stable_mint_issuer_links (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness)
    (mint : statement.stablecoin.direction=.mint) :
    exactV8StablecoinIssuerCommitment statement.stablecoin.assetId
        statement.stablecoin.policyVersion (decodeV8StablecoinIssuerSecret witness.stablecoin) =
      (decodeV8StablecoinConfig witness.stablecoin).issuerCommitment ∧
    exactV8StablecoinIssuerAuthorization statement.stablecoin.actionIntent
        (decodeV8StablecoinIssuerSecret witness.stablecoin) = statement.stablecoin.issuerAuthorization := by
  have transition := typed_stable_transition statement witness valid
  simp only [exactV8StableTransition,mint] at transition
  dsimp only [exactV8StablecoinEnabledValid] at transition
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,branch⟩ := transition
  simp only [mint] at branch
  obtain ⟨_,_,commitment,authorization,_⟩ := branch
  exact ⟨commitment,authorization⟩

theorem encoded_stable_before_root_word (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (encodePublicStatement statement).getD (95+limb.val) 0 =
      statement.stablecoin.beforeRoot.getD limb.val 0 := by
  have source := encoded_stable_public_word statement valid.1 (12+limb.val)
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,before,after,_⟩ := valid.1
  fin_cases limb <;>
    simpa [encodeStablecoinPublic,List.getD_eq_getElem?_getD,List.getElem?_append,
      List.length_append,intent.1,before.1,after.1,digestWords] using source

theorem encoded_stable_after_root_word (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (encodePublicStatement statement).getD (102+limb.val) 0 =
      statement.stablecoin.afterRoot.getD limb.val 0 := by
  have source := encoded_stable_public_word statement valid.1 (19+limb.val)
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,before,after,_⟩ := valid.1
  fin_cases limb <;>
    simpa [encodeStablecoinPublic,List.getD_eq_getElem?_getD,List.getElem?_append,
      List.length_append,intent.1,before.1,after.1,digestWords] using source

theorem encoded_stable_issuer_authorization_word (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (encodePublicStatement statement).getD (113+limb.val) 0 =
      statement.stablecoin.issuerAuthorization.getD limb.val 0 :=
  encoded_stable_issuer_word statement witness valid limb

theorem full_candidate_issuer_commitment_word (statement : V8PublicStatement)
    (witness : V8Witness) (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (41414+lane.val) 0 =
      (decodeV8StablecoinConfig witness.stablecoin).issuerCommitment.getD lane.val 0 := by
  have address : 41414+lane.val=41408+(6+lane.val) := by omega
  rw [address,full_candidate_source_word_readback statement witness ⟨6+lane.val,by omega⟩,
    stable_source_config_readback statement witness (6+lane.val) (by omega)]
  simp [decodeV8StablecoinConfig,stableWitnessSlice,List.getD_eq_getElem?_getD,lane.isLt]

theorem full_candidate_enabled_root_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (enabled : statement.stablecoin.direction=.mint ∨ statement.stablecoin.direction=.burn)
    (which : Fin 2) (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (hashFinalIndex (121+which.val) lane.val) 0 =
      (encodePublicStatement statement).getD ((if which.val=0 then 95 else 102)+lane.val) 0 := by
  rw [← full_candidate_digest_word statement witness ⟨121+which.val,by omega⟩ lane,
    scheduled_stable_state_root_digest statement witness valid which]
  have roots := typed_stable_enabled_state_roots statement witness valid enabled
  fin_cases which
  · simpa only [typedCounters,if_true,roots.1] using
      (encoded_stable_before_root_word statement witness valid lane).symm
  · simpa only [typedCounters,Nat.one_ne_zero,if_false,roots.2] using
      (encoded_stable_after_root_word statement witness valid lane).symm

theorem full_candidate_mint_commitment_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (mint : statement.stablecoin.direction=.mint)
    (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (hashFinalIndex 123 lane.val) 0 =
      (fullTypedSourceCandidate statement witness).getD (41414+lane.val) 0 := by
  rw [← full_candidate_digest_word statement witness ⟨123,by decide⟩ lane,
    scheduled_stable_issuer_commitment_digest statement witness valid,
    (typed_stable_mint_issuer_links statement witness valid mint).1,
    full_candidate_issuer_commitment_word statement witness lane]

theorem full_candidate_mint_authorization_word (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (mint : statement.stablecoin.direction=.mint)
    (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (hashFinalIndex 124 lane.val) 0 =
      (encodePublicStatement statement).getD (113+lane.val) 0 := by
  rw [← full_candidate_digest_word statement witness ⟨124,by decide⟩ lane,
    scheduled_stable_issuer_authorization_digest statement witness valid,
    (typed_stable_mint_issuer_links statement witness valid mint).2,
    encoded_stable_issuer_authorization_word statement witness valid lane]

end HegemonCrypto.SmallWood.V8Smz9SourceStableOutputBindings
