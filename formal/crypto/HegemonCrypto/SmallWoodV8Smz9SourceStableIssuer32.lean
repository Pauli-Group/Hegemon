import HegemonCrypto.SmallWoodV8Smz9SourceStableIssuerFrames

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableIssuer32
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableStateCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableIssuerFrames
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false
noncomputable section

theorem actual_issuer_high_target (publicWords : List Nat) (which : Fin 2) (lane : Fin 16)
    (high : 7 ≤ lane.val) :
    actualCsrCoefficients (fun slot => (publicWords.getD slot 0 : F)) (issuerAttempt which.val lane.val).targetRoot =
      ((compressFrameWords (issuerDomain which.val) [] (issuerRight publicWords which.val)).getD lane.val 0 : F) := by
  let pub : Nat → F := fun slot => (publicWords.getD slot 0 : F)
  change actualCsrCoefficients pub _ = _
  have p84 := actual_public_coefficient pub ⟨84,by decide⟩
  have p85 := actual_public_coefficient pub ⟨85,by decide⟩
  have p87 := actual_public_coefficient pub ⟨87,by decide⟩
  have p88 := actual_public_coefficient pub ⟨88,by decide⟩
  have p89 := actual_public_coefficient pub ⟨89,by decide⟩
  have p90 := actual_public_coefficient pub ⟨90,by decide⟩
  have p91 := actual_public_coefficient pub ⟨91,by decide⟩
  have p92 := actual_public_coefficient pub ⟨92,by decide⟩
  have p93 := actual_public_coefficient pub ⟨93,by decide⟩
  simp only [Nat.reduceAdd] at p84 p85 p87 p88 p89 p90 p91 p92 p93
  have commit : actualCsrCoefficients pub 563 = (stablecoinV8DomainIssuerCommitment : F) :=
    actual_csr_node_field_equation pub (show exactCsrExpressions[563]? = some (.constant stablecoinV8DomainIssuerCommitment) by decide)
  have auth : actualCsrCoefficients pub 564 = (stablecoinV8DomainIssuerAuthorization : F) :=
    actual_csr_node_field_equation pub (show exactCsrExpressions[564]? = some (.constant stablecoinV8DomainIssuerAuthorization) by decide)
  have marker : actualCsrCoefficients pub 544 = (poseidon2V8SuiteMarker : F) :=
    actual_csr_node_field_equation pub (show exactCsrExpressions[544]? = some (.constant poseidon2V8SuiteMarker) by decide)
  have zero := (actual_csr_zero_one pub).1
  rw [compress_frame_word]
  fin_cases which <;> fin_cases lane <;>
    simp_all [issuerAttempt,attempt,issuerDomain,issuerRight,List.range_succ,pub]

theorem full_candidate_issuer_attempt_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (which : Fin 2) (lane : Fin 16) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (issuerAttempt which.val lane.val) = 0 := by
  by_cases low : lane.val<7
  · simp only [issuerAttempt,if_pos low]
    rw [actual_copy_residual_formula,full_candidate_issuer_secret statement witness valid which ⟨lane.val,low⟩,sub_self]
  · have target := actual_issuer_high_target (encodePublicStatement statement) which lane (by omega)
    change actualCsrCoefficients (liveTypedPub statement) (issuerAttempt which.val lane.val).targetRoot = _ at target
    have initial := full_candidate_issuer_high statement witness valid which lane (by omega)
    simp only [issuerAttempt,if_neg low,attempt] at target
    simp only [issuerAttempt,if_neg low,attempt,actualCsrResidual,actualCsrTerms,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one (liveTypedPub statement)).2,one_mul,add_zero]
    rw [target,initial,sub_self]

theorem stable_issuer32_distinct_count : ((List.range 32).map (20146+·)).length = 32 ∧
    ((List.range 32).map (20146+·)).Nodup := by decide

theorem full_candidate_actual_issuer32_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 32) :
    (exactCsrAttempts[20146+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  have found := exact_attempt_lookup _ (exact_issuer_attempts (index.val/16) (by omega) (index.val%16) (by omega))
  have address : 20146+16*(index.val/16)+index.val%16=20146+index.val := by omega
  change exactCsrAttempts[20146+16*(index.val/16)+index.val%16]? = _ at found
  rw [address] at found
  rw [found,Option.map_some,full_candidate_issuer_attempt_zero statement witness valid
    ⟨index.val/16,by omega⟩ ⟨index.val%16,by omega⟩]

end
end HegemonCrypto.SmallWood.V8Smz9SourceStableIssuer32
