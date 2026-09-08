import HegemonCrypto.SmallWoodV8Smz9SourceStableOutputBindings
import HegemonCrypto.SmallWoodV8Smz9SourceStableOutputCoefficients
import HegemonCrypto.SmallWoodV8Smz9StableStateRoots

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableOutput28
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableOutputBindings
open HegemonCrypto.SmallWood.V8Smz9SourceStableOutputCoefficients
open HegemonCrypto.SmallWood.V8Smz9StableStateRoots
open HegemonCrypto.SmallWood.V8Smz9StableIssuerEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem full_candidate_root_output_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (rootOutputAttempt which.val lane.val) = 0 := by
  have gate := (live_typed_direction_coefficients statement witness valid).2.2
  have target := actual_stable_root_target (liveTypedPub statement) which lane
  simp only [rootOutputAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_306,add_zero,target,gate]
  cases direction : statement.stablecoin.direction with
  | disabled =>
    have roots := typed_stable_disabled_roots statement witness valid direction
    have words : liveTypedPub statement (95+lane.val)=liveTypedPub statement (102+lane.val) := by
      simp only [liveTypedPub,encoded_stable_before_root_word statement witness valid lane,
        encoded_stable_after_root_word statement witness valid lane,roots]
    fin_cases which <;> simp [typedEnabled,typedMint,typedBurn,direction,words]
  | mint =>
    have source := full_candidate_enabled_root_word statement witness valid (Or.inl direction) which lane
    rw [source]
    fin_cases which <;> simp [typedEnabled,typedMint,typedBurn,direction,liveTypedPub]
  | burn =>
    have source := full_candidate_enabled_root_word statement witness valid (Or.inr direction) which lane
    rw [source]
    fin_cases which <;> simp [typedEnabled,typedMint,typedBurn,direction,liveTypedPub]

theorem full_candidate_issuer_output_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (issuerOutputAttempt which.val lane.val) = 0 := by
  have gate := (live_typed_direction_coefficients statement witness valid).1
  have target := actual_stable_issuer_auth_target (liveTypedPub statement) lane
  fin_cases which
  · simp only [issuerOutputAttempt,if_true,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_304,
      live_coefficient_323,live_coefficient_0,gate,add_zero,sub_zero]
    cases direction : statement.stablecoin.direction with
    | disabled => simp [typedMint,direction]
    | burn => simp [typedMint,direction]
    | mint =>
      rw [full_candidate_mint_commitment_word statement witness valid direction lane]
      simp [typedMint,direction]
  · simp only [issuerOutputAttempt,Nat.one_ne_zero,if_false,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_304,target,gate,add_zero]
    cases direction : statement.stablecoin.direction with
    | disabled => simp [typedMint,direction]
    | burn => simp [typedMint,direction]
    | mint =>
      rw [full_candidate_mint_authorization_word statement witness valid direction lane]
      simp [typedMint,direction,liveTypedPub]

def stableOutputGlobal (index : Nat) : Nat :=
  if index<14 then 20132+index else 20178+(index-14)

theorem stable_output28_distinct_count : ((List.range 28).map stableOutputGlobal).length=28 ∧
    ((List.range 28).map stableOutputGlobal).Nodup := by decide

theorem full_candidate_actual_output28_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 28) :
    (exactCsrAttempts[stableOutputGlobal index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  by_cases root : index.val<14
  · have found := exact_attempt_lookup _
      (exact_root_output_attempts ⟨index.val%2,by omega⟩ ⟨index.val/2,by omega⟩)
    change exactCsrAttempts[20132+2*(index.val/2)+index.val%2]? = _ at found
    have address : 20132+2*(index.val/2)+index.val%2=20132+index.val := by omega
    rw [address] at found
    simp only [stableOutputGlobal,if_pos root,found,Option.map_some]
    rw [full_candidate_root_output_attempt_zero statement witness valid ⟨index.val%2,by omega⟩ ⟨index.val/2,by omega⟩]
  · let offset := index.val-14
    have bound : offset<14 := by dsimp only [offset]; omega
    have found := exact_attempt_lookup _
      (exact_issuer_output_attempts ⟨offset/7,by omega⟩ ⟨offset%7,by omega⟩)
    have address : (issuerOutputAttempt (offset/7) (offset%7)).globalIndex=20178+offset := by
      dsimp only [issuerOutputAttempt]
      split <;> simp only [attempt] <;> omega
    rw [address] at found
    change exactCsrAttempts[20178+(index.val-14)]? = _ at found
    simp only [stableOutputGlobal,if_neg root,found,Option.map_some]
    rw [full_candidate_issuer_output_attempt_zero statement witness valid ⟨offset/7,by omega⟩ ⟨offset%7,by omega⟩]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableOutput28
