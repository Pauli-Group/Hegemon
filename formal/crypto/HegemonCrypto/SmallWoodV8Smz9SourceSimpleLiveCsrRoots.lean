import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrReadbacks

namespace HegemonCrypto.SmallWood.V8Smz9SourceSimpleLiveCsrRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem full_live_source_field (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 128) :
    ((fullTypedSourceCandidate statement witness).getD (41408 + slot.val) 0 : F) =
      (stableSourceWord statement witness slot.val : F) :=
  congrArg (fun word : Nat => (word : F))
    (full_candidate_source_word_readback statement witness slot)

theorem full_live_boolean_field (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 64) :
    ((fullTypedSourceCandidate statement witness).getD (42112 + slot.val) 0 : F) =
      ((sourceBooleanValues statement.stablecoin witness.stablecoin
        (sourceAux statement.stablecoin witness.stablecoin)).getD slot.val 0 : F) := by
  have address : 42112 + slot.val = (647 + TailFamily.booleans.base + 0) * 64 + slot.val := by
    rfl
  rw [address,full_candidate_tail_flat_field_readback statement witness .booleans 0 (by decide) slot]
  rfl

theorem full_disabled_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 94) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .disabled index.val) = 0 := by
  have enabled := (live_typed_direction_coefficients statement witness valid).2.2
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_307,
    live_coefficient_0,add_zero,sub_zero,enabled]
  rw [full_live_source_field statement witness ⟨index.val,by have := index.isLt; omega⟩]
  cases mode : statement.stablecoin.direction with
  | disabled =>
      rw [stable_source_disabled_zero statement witness valid mode index]
      simp
  | mint => simp [typedEnabled,typedMint,typedBurn,mode]
  | burn => simp [typedEnabled,typedMint,typedBurn,mode]

theorem full_compatibility_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 18) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .compatibility index.val) = 0 := by
  have address : 41502 + index.val = 41408 + (94 + index.val) := by omega
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_1,
    live_coefficient_0,one_mul,add_zero,sub_zero]
  rw [address,full_live_source_field statement witness ⟨94 + index.val,by omega⟩,
    stable_source_reserved_zero statement witness valid index,Nat.cast_zero]

theorem full_issuer_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .issuer index.val) = 0 := by
  have mint := (live_typed_direction_coefficients statement witness valid).1
  have address : 41491 + index.val = 41408 + (83 + index.val) := by omega
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_308,
    live_coefficient_0,add_zero,sub_zero,mint]
  rw [address,full_live_source_field statement witness ⟨83 + index.val,by omega⟩]
  by_cases mode : statement.stablecoin.direction = .mint
  · simp [typedMint,mode]
  · rw [stable_source_nonmint_issuer_zero statement witness valid mode index,Nat.cast_zero,mul_zero]

theorem full_burn_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .burn index.val) = 0 := by
  have padding := full_source_padding_field_zero statement witness ⟨0,by decide⟩
  have burn := (live_typed_direction_coefficients statement witness valid).2.1
  have target : actualCsrCoefficients (liveTypedPub statement) (309 + index.val) =
      liveTypedPub statement (113 + index.val) * liveBurn (liveTypedPub statement) := by
    fin_cases index <;> simp
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_1,one_mul,
    add_zero,target,burn]
  rw [show ((fullTypedSourceCandidate statement witness).getD 41528 0 : F) = 0 by exact padding]
  by_cases mode : statement.stablecoin.direction = .burn
  · rw [liveTypedPub,encoded_burn_issuer_zero statement witness valid mode index,Nat.cast_zero]
    simp
  · simp [typedBurn,mode]

theorem full_scalar_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 2) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .scalar index.val) = 0 := by
  have copy := congrArg (fun word : Nat => (word : F))
    (stable_source_public_scalar_bridge statement witness valid index)
  have source := full_live_source_field statement witness ⟨index.val,by omega⟩
  have target : actualCsrCoefficients (liveTypedPub statement) (88 + index.val) =
      liveTypedPub statement (84 + index.val) := by fin_cases index <;> simp
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_1,one_mul,
    add_zero,target,source]
  exact sub_eq_zero.mpr copy

theorem full_direction_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 3) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .direction index.val) = 0 := by
  have source := full_live_boolean_field statement witness ⟨index.val,by omega⟩
  have values := source_boolean_direction_values statement witness
    (sourceAux statement.stablecoin witness.stablecoin)
  have coefficients := live_typed_direction_coefficients statement witness valid
  have target : actualCsrCoefficients (liveTypedPub statement) ([306,304,305].getD index.val 0) =
      if index.val = 0 then typedEnabled statement
      else if index.val = 1 then typedMint statement else typedBurn statement := by
    fin_cases index <;> simp [coefficients.1,coefficients.2.1,coefficients.2.2]
  have formula : ((sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD index.val 0 : F) =
      if index.val = 0 then typedEnabled statement
      else if index.val = 1 then typedMint statement else typedBurn statement := by
    fin_cases index
    · rw [values.1]
      cases mode : statement.stablecoin.direction <;>
        simp [typedEnabled,typedMint,typedBurn,mode]
    · rw [values.2.1]
      cases mode : statement.stablecoin.direction <;>
        simp [typedMint,mode]
    · rw [values.2.2]
      cases mode : statement.stablecoin.direction <;>
        simp [typedBurn,mode]
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_1,
    one_mul,add_zero,target,source,formula,sub_self]

theorem full_asset_bits_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 4) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .assetBits index.val) = 0 := by
  have address : 42119 + index.val = 42112 + (7 + index.val) := by omega
  have source := full_live_boolean_field statement witness ⟨7 + index.val,by omega⟩
  have value := congrArg (fun word : Nat => (word : F))
    (source_boolean_asset_bit statement witness valid index)
  have target : actualCsrCoefficients (liveTypedPub statement) (316 + index.val) =
      (sourceBit (liveTypedPub statement 84).val index.val : F) := by
    fin_cases index <;> simp [sourceBit]
  simp only [expectedLiveCsrAttempt,attempt,actualCsrResidual,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,live_coefficient_1,one_mul,
    add_zero,target,live_typed_public_asset_val statement witness valid,address,source]
  exact sub_eq_zero.mpr value


end
end HegemonCrypto.SmallWood.V8Smz9SourceSimpleLiveCsrRoots
