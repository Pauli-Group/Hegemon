import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericCoefficients
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableCarry18
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable (csr_chunks037_member)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def selectedCarry (aux : SourceAux) (slot : Nat) : Nat :=
  (sourceNumericValues aux).getD ([23,28,29,35,40,41].getD slot 0) 0

theorem source_carry_a (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (slot : Fin 6) :
    (sourceMultiplication statement witness aux (18+slot.val)).a = limbBase - 1 - selectedCarry aux slot.val := by
  simp only [sourceMultiplication,if_neg (show ¬18+slot.val < 18 by omega),
    if_pos (show 18+slot.val < 24 by omega),Nat.add_sub_cancel_left,selectedCarry]

theorem source_carry_b (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (slot : Fin 6) :
    (sourceMultiplication statement witness aux (18+slot.val)).b =
      if statement.stablecoin.direction = .mint then fieldInverse (limbBase - 1 - selectedCarry aux slot.val) else 0 := by
  simp only [sourceMultiplication,if_neg (show ¬18+slot.val < 18 by omega),
    if_pos (show 18+slot.val < 24 by omega),Nat.add_sub_cancel_left,selectedCarry]
  by_cases mint : statement.stablecoin.direction = .mint <;> simp [mint]

theorem source_carry_c (statement : V8PublicStatement) (witness : V8Witness)
    (aux : SourceAux) (slot : Fin 6) :
    (sourceMultiplication statement witness aux (18+slot.val)).c =
      if statement.stablecoin.direction = .mint then 1 else 0 := by
  simp only [sourceMultiplication,if_neg (show ¬18+slot.val < 18 by omega),
    if_pos (show 18+slot.val < 24 by omega)]

def carry18Attempt (index : Nat) : CsrExecutableAttempt :=
  match index with
  | 0 => attempt 20476 83 0 1 [(42258, 1), (42199, 265)] 542
  | 1 => attempt 20477 83 1 1 [(42322, 308)] 0
  | 2 => attempt 20478 83 2 1 [(42386, 1)] 304
  | 3 => attempt 20479 83 3 1 [(42259, 1), (42204, 265)] 542
  | 4 => attempt 20480 83 4 1 [(42323, 308)] 0
  | 5 => attempt 20481 83 5 1 [(42387, 1)] 304
  | 6 => attempt 20482 83 6 1 [(42260, 1), (42205, 265)] 542
  | 7 => attempt 20483 83 7 1 [(42324, 308)] 0
  | 8 => attempt 20484 83 8 1 [(42388, 1)] 304
  | 9 => attempt 20485 83 9 1 [(42261, 1), (42211, 265)] 542
  | 10 => attempt 20486 83 10 1 [(42325, 308)] 0
  | 11 => attempt 20487 83 11 1 [(42389, 1)] 304
  | 12 => attempt 20488 83 12 1 [(42262, 1), (42216, 265)] 542
  | 13 => attempt 20489 83 13 1 [(42326, 308)] 0
  | 14 => attempt 20490 83 14 1 [(42390, 1)] 304
  | 15 => attempt 20491 83 15 1 [(42263, 1), (42217, 265)] 542
  | 16 => attempt 20492 83 16 1 [(42327, 308)] 0
  | _ => attempt 20493 83 17 1 [(42391, 1)] 304

theorem carry18_chunk_member (index : Fin 18) :
    carry18Attempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk015 ++
      V8Smz9ProgramCanonicalityCsr40.chunk000 := by
  fin_cases index <;> decide

theorem carry18_chunks_in_complete (chunk : List CsrExecutableAttempt)
    (selected : chunk = V8Smz9ProgramCanonicalityCsr39.chunk015 ∨
      chunk = V8Smz9ProgramCanonicalityCsr40.chunk000) : chunk ∈ csrChunks000 := by
  rcases selected with rfl | rfl
  · have member : V8Smz9ProgramCanonicalityCsr39.chunk015 ∈ V8Smz9ProgramCanonicalityCsr39.chunkList := by
      simp only [V8Smz9ProgramCanonicalityCsr39.chunkList,List.mem_cons,List.not_mem_nil,or_false]
      exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (True.intro)))))))))))))))
    exact csr_chunks037_member _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ member)))
  · have member : V8Smz9ProgramCanonicalityCsr40.chunk000 ∈ V8Smz9ProgramCanonicalityCsr40.chunkList := by
      simp only [V8Smz9ProgramCanonicalityCsr40.chunkList,List.mem_cons,List.not_mem_nil,or_false]
      exact Or.inl True.intro
    exact csr_chunks037_member _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_right _ member)))

theorem carry18_exact_lookup (index : Fin 18) :
    exactCsrAttempts[20476+index.val]? = some (carry18Attempt index.val) := by
  have member : carry18Attempt index.val ∈ exactCsrAttempts := by
    rw [←csr_chunks_equal_materialized_attempts]
    rcases List.mem_append.mp (carry18_chunk_member index) with first | second
    · exact List.mem_flatten.mpr ⟨_,carry18_chunks_in_complete _ (Or.inl rfl),first⟩
    · exact List.mem_flatten.mpr ⟨_,carry18_chunks_in_complete _ (Or.inr rfl),second⟩
  have found := exact_attempt_lookup _ member
  have global : (carry18Attempt index.val).globalIndex = 20476 + index.val := by
    fin_cases index <;> decide
  rwa [global] at found

noncomputable section
theorem source_carry_first_value_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6) :
    let aux := sourceAux statement.stablecoin witness.stablecoin
    ((sourceMultiplication statement witness aux (18+slot.val)).a : F) +
      (selectedCarry aux slot.val : F) - 4294967295 = 0 := by
  dsimp only
  rw [source_carry_a]
  have bound := typed_selected_carry_bound statement witness valid slot
  have equal : limbBase - 1 - selectedCarry (sourceAux statement.stablecoin witness.stablecoin) slot.val +
      selectedCarry (sourceAux statement.stablecoin witness.stablecoin) slot.val = 4294967295 := by
    dsimp only [selectedCarry]
    norm_num [limbBase] at bound ⊢
    omega
  have cast := congrArg (fun value : Nat => (value : F)) equal
  simpa only [Nat.cast_add,Nat.cast_ofNat] using sub_eq_zero.mpr cast

theorem source_carry_middle_value_zero (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 6) :
    (1-typedMint statement) * ((sourceMultiplication statement witness
      (sourceAux statement.stablecoin witness.stablecoin) (18+slot.val)).b : F) = 0 := by
  rw [source_carry_b]
  by_cases mint : statement.stablecoin.direction = .mint <;> simp [typedMint,mint]

theorem source_carry_last_value_zero (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 6) :
    ((sourceMultiplication statement witness
      (sourceAux statement.stablecoin witness.stablecoin) (18+slot.val)).c : F) - typedMint statement = 0 := by
  rw [source_carry_c]
  by_cases mint : statement.stablecoin.direction = .mint <;> simp [typedMint,mint]

theorem full_candidate_carry18_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 18) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (carry18Attempt index.val) = 0 := by
  have mint := (live_typed_direction_coefficients statement witness valid).1
  fin_cases index <;>
    simp only [carry18Attempt,actualCsrResidual,actualCsrTerms,attempt,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,
      live_coefficient_0,live_coefficient_1,live_coefficient_265,
      live_coefficient_304,live_coefficient_308,actual_csr_coefficient_542,mint,
      one_mul,add_zero,sub_zero]
  all_goals repeat first
    | rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_a_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_b_absolute statement witness _ (by decide) (by decide)]
    | rw [full_candidate_multiplication_c_absolute statement witness _ (by decide) (by decide)]
  · exact source_carry_first_value_zero statement witness valid ⟨0,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨0,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨0,by decide⟩
  · exact source_carry_first_value_zero statement witness valid ⟨1,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨1,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨1,by decide⟩
  · exact source_carry_first_value_zero statement witness valid ⟨2,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨2,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨2,by decide⟩
  · exact source_carry_first_value_zero statement witness valid ⟨3,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨3,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨3,by decide⟩
  · exact source_carry_first_value_zero statement witness valid ⟨4,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨4,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨4,by decide⟩
  · exact source_carry_first_value_zero statement witness valid ⟨5,by decide⟩
  · exact source_carry_middle_value_zero statement witness ⟨5,by decide⟩
  · exact source_carry_last_value_zero statement witness ⟨5,by decide⟩

theorem full_candidate_actual_carry18_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 18) :
    (exactCsrAttempts[20476+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)) = some 0 := by
  simp only [carry18_exact_lookup,Option.map_some,full_candidate_carry18_zero statement witness valid index]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableCarry18
