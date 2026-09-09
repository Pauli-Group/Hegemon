import HegemonCrypto.SmallWoodV8Smz9SourceStableFinalBorrow
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrowCsr
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrow
open HegemonCrypto.SmallWood.V8Smz9SourceNonmintCsr40
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def finalBorrowAttempt : CsrExecutableAttempt := attempt 20375 72 0 0 [(42137,1)] 0

theorem final_borrow_exact_lookup : exactCsrAttempts[20375]? = some finalBorrowAttempt := by
  apply exact_attempt_lookup finalBorrowAttempt
  rw [←csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨_,nonmint_chunks_in_complete _ (Or.inr rfl),
    (by decide : finalBorrowAttempt ∈ V8Smz9ProgramCanonicalityCsr39.chunk012)⟩

noncomputable section
theorem full_candidate_actual_final_borrow_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (exactCsrAttempts[20375]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [final_borrow_exact_lookup,Option.map_some,actualCsrResidual,finalBorrowAttempt,
    attempt,actualCsrTerms,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
    (actual_csr_zero_one _).1,(actual_csr_zero_one _).2,
    full_candidate_final_borrow_zero statement witness valid,Nat.cast_zero,mul_zero,add_zero,sub_zero]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrowCsr
