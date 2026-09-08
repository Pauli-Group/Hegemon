import HegemonCrypto.SmallWoodV8Smz9SourceStablePathFrames
import HegemonCrypto.SmallWoodV8Smz9StableHashWiring

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableIssuerFrames
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def typedIssuerRight (statement : V8PublicStatement) (which : Nat) : List Nat :=
  if which=0 then [statement.stablecoin.assetId,statement.stablecoin.policyVersion,0,0,0,0,0]
  else fixedWords 7 statement.stablecoin.actionIntent

theorem actual_stable_issuer_frame (statement : V8PublicStatement) (witness : V8Witness) (which : Fin 2) :
    actualSourceFrame statement witness ⟨123+which.val,by omega⟩ =
      compressFrameWords (issuerDomain which.val) (stableSecret witness) (typedIssuerRight statement which.val) := by
  fin_cases which <;> rfl

theorem typed_issuer_right_encoded (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (limb : Fin 7) :
    (typedIssuerRight statement which.val).getD limb.val 0 =
      (issuerRight (encodePublicStatement statement) which.val).getD limb.val 0 := by
  fin_cases which
  · have scalar := encoded_stable_public_scalars statement witness valid
    simp only [List.getD_eq_getElem?_getD] at scalar
    fin_cases limb <;> simp [typedIssuerRight,issuerRight,scalar.2.1,scalar.2.2.1]
  · have source := encoded_stable_action_intent_word statement witness valid limb
    simpa [typedIssuerRight,issuerRight,fixedWords,List.getD_eq_getElem?_getD,limb.isLt] using source.symm

theorem full_candidate_issuer_secret (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 7) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (123+which.val) lane.val) 0 =
      (fullTypedSourceCandidate statement witness).getD (41491+lane.val) 0 := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨123+which.val,by omega⟩ ⟨lane.val,by omega⟩,
    actual_stable_issuer_frame,compress_frame_word _ _ _ ⟨lane.val,by omega⟩,if_pos lane.isLt]
  have address : 41491+lane.val=41408+(83+lane.val) := by omega
  rw [address,full_candidate_source_word_readback statement witness ⟨83+lane.val,by omega⟩,
    stable_source_issuer_readback statement witness lane.val lane.isLt]
  simp only [stableSecret,stableWitnessSlice,List.getD_eq_getElem?_getD,List.getElem?_map,
    List.getElem?_range,lane.isLt,Option.map_some,Option.getD_some]

theorem full_candidate_issuer_high (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 16)
    (high : 7 ≤ lane.val) :
    (fullTypedSourceCandidate statement witness).getD (hashInitialIndex (123+which.val) lane.val) 0 =
      (compressFrameWords (issuerDomain which.val) [] (issuerRight (encodePublicStatement statement) which.val)).getD lane.val 0 := by
  rw [full_candidate_initial_source_readback statement witness valid ⟨123+which.val,by omega⟩ lane,
    actual_stable_issuer_frame,compress_frame_word,compress_frame_word]
  simp only [if_neg (show ¬lane.val<7 by omega)]
  by_cases rate : lane.val<14
  · simp only [if_pos rate]
    exact typed_issuer_right_encoded statement witness valid which ⟨lane.val-7,by omega⟩
  · simp only [if_neg rate]

end HegemonCrypto.SmallWood.V8Smz9SourceStableIssuerFrames
