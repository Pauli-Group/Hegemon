import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeResiduals
import HegemonCrypto.SmallWoodV8Smz9SourceStableTimeArithmetic
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTime15
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeResiduals
open HegemonCrypto.SmallWood.V8Smz9SourceStableTimeArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable (csr_chunks037_member)
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def timeNonmintAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt (20400+3*index) 75 (2+3*index) 1 [(42112+(timeAddition index).carry,308)] 0

def time15Attempt (index part : Nat) : CsrExecutableAttempt :=
  if part=0 then timeAdditionLowAttempt index else if part=1 then timeAdditionHighAttempt index else timeNonmintAttempt index

theorem time_nonmint_exact_member (index : Fin 5) : timeNonmintAttempt index.val ∈ exactCsrAttempts := by
  have member : timeNonmintAttempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk013 := by
    fin_cases index <;> decide
  have chunk : V8Smz9ProgramCanonicalityCsr39.chunk013 ∈ V8Smz9ProgramCanonicalityCsr39.chunkList := by
    simp only [V8Smz9ProgramCanonicalityCsr39.chunkList,List.mem_cons,List.not_mem_nil,or_false]
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl True.intro)))))))))))))
  rw [←csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨_,csr_chunks037_member _
    (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ chunk))),member⟩

theorem time15_exact_lookup (index : Fin 5) (part : Fin 3) :
    exactCsrAttempts[20398+3*index.val+part.val]? = some (time15Attempt index.val part.val) := by
  have member : time15Attempt index.val part.val ∈ exactCsrAttempts := by
    fin_cases part
    · exact (exact_time_addition_attempts index.val index.isLt).1
    · exact (exact_time_addition_attempts index.val index.isLt).2.1
    · exact time_nonmint_exact_member index
  have found := exact_attempt_lookup _ member
  have global : (time15Attempt index.val part.val).globalIndex = 20398+3*index.val+part.val := by
    fin_cases part <;> simp [time15Attempt,timeAdditionLowAttempt,timeAdditionHighAttempt,timeNonmintAttempt,attempt] <;> omega
  rwa [global] at found

noncomputable section
theorem full_candidate_time_low_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (timeAdditionLowAttempt index.val) = 0 := by
  rw [actual_time_low_residual]
  dsimp only
  rw [(live_typed_direction_coefficients statement witness valid).1]
  by_cases mint : statement.stablecoin.direction = .mint
  · have equation := congrArg (fun value : Nat => (value : F))
      (full_candidate_mint_time_parts statement witness valid mint index).1
    simp only [Nat.cast_add,Nat.cast_mul,Nat.cast_pow,Nat.cast_ofNat] at equation
    simp only [typedMint,if_pos mint,one_mul]
    linear_combination equation
  · rw [typedMint,if_neg mint,zero_mul]

theorem full_candidate_time_high_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (timeAdditionHighAttempt index.val) = 0 := by
  rw [actual_time_high_residual]
  dsimp only
  rw [(live_typed_direction_coefficients statement witness valid).1]
  by_cases mint : statement.stablecoin.direction = .mint
  · have equation := congrArg (fun value : Nat => (value : F))
      (full_candidate_mint_time_parts statement witness valid mint index).2
    simp only [Nat.cast_add] at equation
    simp only [typedMint,if_pos mint,one_mul]
    linear_combination equation
  · rw [typedMint,if_neg mint,zero_mul]

theorem full_candidate_time_nonmint_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (timeNonmintAttempt index.val) = 0 := by
  simp only [actualCsrResidual,timeNonmintAttempt,attempt,actualCsrTerms,List.map_cons,List.map_nil,
    List.sum_cons,List.sum_nil,live_coefficient_308,live_coefficient_0,add_zero,sub_zero,
    (live_typed_direction_coefficients statement witness valid).1]
  by_cases mint : statement.stablecoin.direction = .mint
  · rw [typedMint,if_pos mint,sub_self,zero_mul]
  · have carryBound := (exact_time_addition_attempts index.val index.isLt).2.2.2.2.2
    rw [full_candidate_boolean_at statement witness ⟨_,carryBound⟩,
      time_boolean_carry statement witness _ index,nonmint_time_carry_zero statement witness mint]
    simp only [Nat.cast_zero,mul_zero]

theorem full_candidate_actual_time15_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 5) (part : Fin 3) :
    (exactCsrAttempts[20398+3*index.val+part.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [time15_exact_lookup,Option.map_some]
  congr 1
  fin_cases part
  · exact full_candidate_time_low_zero statement witness valid index
  · exact full_candidate_time_high_zero statement witness valid index
  · exact full_candidate_time_nonmint_zero statement witness valid index
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableTime15
