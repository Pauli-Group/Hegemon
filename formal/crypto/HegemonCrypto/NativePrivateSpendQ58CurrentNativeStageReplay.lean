import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate
import SmzaRp05CurrentBranchOracleAgreement
/-! Native stage replay on actual verifier reads. Source only, kernel pending.
The generic Program agreement lemma carries no old-profile stage types. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentNativeStageReplay
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
 (Wire Transcript ExecutionStages verifierProgram canonicalOpening pcsProgram matrixProgram)
end E
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (preMatrixLog stages_verifier_has_pre_matrix_log)
end S
open SmzaRp05CurrentBranchOracleAgreement (eval_eq_of_agrees_on_left_reads)
noncomputable section
set_option autoImplicit false
set_option Elab.async false

/-- The six stage data fields and transcript are retained by construction.
Agreement is confined to this actual left verifier log; no right execution
or requested stage output is an input. Endpoints derive agreement from claims. -/
def replay
 (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
 (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
 (pending : Bool) (nonce : Fin (2^32)) (wire : E.Wire) (left right : Oracle)
 (transcript : E.Transcript)
 (st : E.ExecutionStages ns relation pending nonce wire left transcript)
 (agree : ∀ input, (input,left input) ∈ ((E.verifierProgram ns relation pending nonce wire).record left).2 →
  left input = right input) : E.ExecutionStages ns relation pending nonce wire right transcript := by
 let full := E.verifierProgram ns relation pending nonce wire
 have logged := S.stages_verifier_has_pre_matrix_log ns relation pending nonce wire left transcript st
 have openingIncluded : ((E.canonicalOpening pending nonce wire.hPiop).record left).2 ⊆ (full.record left).2 := by
  intro call member
  rw [logged]
  simp only [S.preMatrixLog,List.mem_append]
  exact Or.inl (Or.inl member)
 have pcsIncluded : ((E.pcsProgram ns st.openingPending wire st.decoded st.opening).record left).2 ⊆ (full.record left).2 := by
  intro call member
  rw [logged]
  simp only [S.preMatrixLog,List.mem_append]
  exact Or.inl (Or.inr member)
 have matrixIncluded : ((E.matrixProgram st.pcs.pending st.pcs.hashFpp).record left).2 ⊆ (full.record left).2 := by
  intro call member
  rw [logged]
  simp only [List.mem_append]
  exact Or.inr (Or.inl member)
 have openingEq := eval_eq_of_agrees_on_left_reads (E.canonicalOpening pending nonce wire.hPiop) left right
  (fun input member => agree input (openingIncluded member))
 have pcsEq := eval_eq_of_agrees_on_left_reads (E.pcsProgram ns st.openingPending wire st.decoded st.opening) left right
  (fun input member => agree input (pcsIncluded member))
 have matrixEq := eval_eq_of_agrees_on_left_reads (E.matrixProgram st.pcs.pending st.pcs.hashFpp) left right
  (fun input member => agree input (matrixIncluded member))
 exact
  { decoded := st.decoded
    opening := st.opening
    openingPending := st.openingPending
    pcs := st.pcs
    matrix := st.matrix
    finalPending := st.finalPending
    decodedEq := st.decodedEq
    openingExecuted := openingEq.symm.trans st.openingExecuted
    pcsExecuted := pcsEq.symm.trans st.pcsExecuted
    matrixExecuted := matrixEq.symm.trans st.matrixExecuted
    reconstructed := st.reconstructed }

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentNativeStageReplay
