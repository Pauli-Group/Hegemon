import SmzaRp05SupplyClosureOutputInstance
import SmzaRp05SupplyClosureOutputSponge
import SmzaRp05SupplyClosureHashCalls

/-! Current accepted output openings bind to their public commitment stream.
No caller supplies output digest equalities or producer openings. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex)
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputFrame (noteCall)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputSponge
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHashCalls
open HegemonCrypto.SmallWood.SmzaRp05CurrentMerklePublic (csr_node_value)
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge (packedFinalState)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def outputAttempt (output : Fin 2) (limb : Fin 7) : CsrExecutableAttempt where
  globalIndex := 18448 + 7 * output.val + limb.val
  family := 25
  localIndex := 7 * output.val + limb.val
  emission := 1
  terms := [(hashFinalIndex (noteCall output + 2) limb.val, 6 + output.val)]
  targetRoot := 286 + 8 * output.val + limb.val

private theorem output_member (output : Fin 2) (limb : Fin 7) :
    outputAttempt output limb ∈ program.csrAttempts := by
  have lift576 {a : CsrExecutableAttempt} (member : a ∈ exactCsrAttemptsChunk0576) :
      a ∈ exactCsrAttempts := by
    unfold exactCsrAttempts
    exact List.mem_flatten_of_mem (List.getElem_mem (n := 576) (by decide)) member
  change outputAttempt output limb ∈ exactCsrAttempts
  apply lift576
  fin_cases output <;> fin_cases limb <;> decide

private theorem active_realizes (output : Fin 2) :
    Realizes program.csrExpressions (6 + output.val) (.publicInput (2 + output.val)) := by
  fin_cases output <;> exact Realizes.publicInput (by decide)

private theorem target_realizes (output : Fin 2) (limb : Fin 7) :
    Realizes program.csrExpressions (286 + 8 * output.val + limb.val)
      (.mul (.publicInput (2 + output.val))
        (.publicInput (18 + 7 * output.val + limb.val))) := by
  apply Realizes.mul (leftNode := 6 + output.val)
    (rightNode := 22 + 7 * output.val + limb.val)
  · fin_cases output <;> fin_cases limb <;> decide
  · have := output.isLt; omega
  · have := output.isLt; omega
  · exact active_realizes output
  · fin_cases output <;> fin_cases limb <;> exact Realizes.publicInput (by decide)

theorem accepted_output_word {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (output : Fin 2) (limb : Fin 7)
    (active : publicWords.getD (2 + output.val) 0 = 1) :
    packedWord packed (hashFinalIndex (noteCall output + 2) limb.val) =
      publicWords.getD (18 + 7 * output.val + limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have canonical := SmzaRp05SupplyClosureOutputInstance.certificate.canonical
  have gate : (values.getD (6 + output.val) 0 : Goldilocks) = 1 := by
    have relation := csr_node_value canonical evaluated (active_realizes output)
    have publicGate :
        (publicWords.getD (2 + output.val) 0 : Goldilocks) = 1 := by
      rw [active]
      norm_num
    exact relation.trans publicGate
  have target : (values.getD (286 + 8 * output.val + limb.val) 0 : Goldilocks) =
      (publicWords.getD (18 + 7 * output.val + limb.val) 0 : Goldilocks) := by
    have relation := csr_node_value canonical evaluated (target_realizes output limb)
    have publicGate :
        (publicWords.getD (2 + output.val) 0 : Goldilocks) = 1 := by
      rw [active]
      norm_num
    simp only [SourceTerm.eval] at relation
    rw [publicGate, one_mul] at relation
    exact relation
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (output_member output limb))
  simp only [outputAttempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, gate, target, one_mul, add_zero] at equation
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (canonical_public_coordinate accepted.1 (by
      have := output.isLt; have := limb.isLt
      simp only [publicStatementWordCount]
      omega)).2 equation

theorem accepted_output_opening {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (output : Fin 2)
    (active : publicWords.getD (2 + output.val) 0 = 1) :
    exactV8NoteCommitment (projectNote packed (noteCall output)) =
      (List.range 7).map (fun limb => publicWords.getD (18 + 7 * output.val + limb) 0) := by
  have finalState : FinalStateCorrect packed := by
    intro call bound
    exact current_hash_call_state accepted bound
  have digest := accepted_note_digest_eq_exact_commitment
    SmzaRp05SupplyClosureOutputInstance.certificate accepted finalState output
  rw [← digest]
  apply List.ext_getElem
  · simp [packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa using rightBound
    simp only [packedFinalState, List.getElem_take, List.getElem_map,
      List.getElem_range]
    exact accepted_output_word accepted output ⟨limb, limbBound⟩ active

/-- Native flattening retains active slots in their original 0,1 order. -/
def activeOutputSlots (publicWords : List Nat) : List (Fin 2) :=
  [⟨0, by decide⟩, ⟨1, by decide⟩].filter
    (fun output => publicWords.getD (2 + output.val) 0 = 1)

def outputOpenings (publicWords packed : List Nat) : List V8NoteOpening :=
  (activeOutputSlots publicWords).map (fun output => projectNote packed (noteCall output))

def outputCommitments (publicWords : List Nat) : List Digest :=
  (activeOutputSlots publicWords).map (fun output =>
    (List.range 7).map (fun limb => publicWords.getD (18 + 7 * output.val + limb) 0))

theorem accepted_output_stream {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    (outputOpenings publicWords packed).map exactV8NoteCommitment =
      outputCommitments publicWords := by
  unfold outputOpenings outputCommitments
  rw [List.map_map]
  apply List.map_congr_left
  intro output member
  have active : publicWords.getD (2 + output.val) 0 = 1 := by
    simpa using (List.mem_filter.mp member).2
  exact accepted_output_opening accepted output active

end HegemonCrypto.SmallWood.SmzaRp05SupplyClosureOutputs
