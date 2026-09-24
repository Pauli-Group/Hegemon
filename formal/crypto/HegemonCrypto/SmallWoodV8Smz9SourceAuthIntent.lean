import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootClosure
import HegemonCrypto.SmallWoodV8Smz9SourceAuthorizationDigests

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthIntent
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem intent_segment_plan (statement : V8PublicStatement) (witness : V8Witness) (block : Fin 15) :
    sourceCallPlan statement witness (79+block.val) (scheduledFinal statement witness) =
      .sponge (.actionIntent block.val) poseidon2V8ActionIntentDomain
        (exactV8ActionIntentProjection statement) 15 block.val
        (previousSponge (79+block.val) block.val) := by
  fin_cases block <;> rfl

theorem intent_projection_length (statement : V8PublicStatement) :
    (exactV8ActionIntentProjection statement).length = 120 := by
  simp only [exactV8ActionIntentProjection,List.length_map,List.length_range,publicWordCount]

theorem typed_intent_digest_exact (statement : V8PublicStatement) (witness : V8Witness) :
    (stateWords (scheduledFinal statement witness 93)).take 7 = exactV8ActionIntent statement := by
  exact source_sponge_segment_digest statement witness 79 15 poseidon2V8ActionIntentDomain
    (exactV8ActionIntentProjection statement) .actionIntent (by decide) (by decide)
    (fun block bound => intent_segment_plan statement witness ⟨block,bound⟩)
    (by decide) (by rw [intent_projection_length]; decide)
    (by rw [intent_projection_length]; rfl)

theorem typed_intent_hash_word (statement : V8PublicStatement) (witness : V8Witness) (limb : Fin 7) :
    authHashWord (typedSourceFinals statement witness) 93 limb.val =
      (exactV8ActionIntent statement).getD limb.val 0 := by
  rw [auth_hash_word_readback _ ⟨93,by decide⟩ limb]
  change callFinalWord (typedLiveInitialStates statement witness) 93 limb.val = _
  rw [typed_call_final_word_is_scheduled statement witness ⟨93,by decide⟩]
  exact first_seven_readback _ _ (typed_intent_digest_exact statement witness) limb

theorem final_intent_word_binding (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (finalMode : witness.authorization.mode = .finalThresholdSpend) (limb : Fin 7) :
    wordAt witness.authorization.current.intentDigest limb.val =
      authHashWord (typedSourceFinals statement witness) 93 limb.val := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,finalMode] at auth
  have intent : witness.authorization.current.intentDigest = exactV8ActionIntent statement :=
    auth.2.2.2.2.2.2.1
  rw [intent,typed_intent_hash_word]
  rfl

theorem source_final_intent_product (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 7) :
    (authModeFlag witness.authorization.mode 2 : HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.F) *
      ((wordAt witness.authorization.current.intentDigest limb.val : HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.F) -
        (authHashWord (typedSourceFinals statement witness) 93 limb.val : HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.F)) = 0 := by
  by_cases finalMode : witness.authorization.mode = .finalThresholdSpend
  · rw [final_intent_word_binding statement witness valid finalMode limb,sub_self,mul_zero]
  · have gate : authModeFlag witness.authorization.mode 2 = 0 := by
      cases mode : witness.authorization.mode <;> simp_all [authModeFlag,authBit]
    rw [gate,Nat.cast_zero,zero_mul]

end HegemonCrypto.SmallWood.V8Smz9SourceAuthIntent
