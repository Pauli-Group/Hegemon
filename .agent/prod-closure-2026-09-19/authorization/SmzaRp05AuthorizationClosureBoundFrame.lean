import SmzaRp05SupplyClosureHashCalls
import SmzaRp05SingleKeyPrfSourceCanonical

/-! Exact source frame for calls107/108: five selected-key words, two
literal zero pads, seven right-operand words, domain and suite. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureBoundFrame

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHashCalls

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def constantNode (cell : BoundCell) : Nat :=
  if cell.2.val = 14 then 551 else if cell.2.val = 15 then 541 else 0

def exactAttempt (cell : BoundCell) : CsrExecutableAttempt :=
  { globalIndex := 19077 + cell.1.val * 16 + cell.2.val
    family := 38 + cell.1.val
    localIndex := cell.2.val
    emission := 0
    terms := (hashInitialIndex (107 + cell.1.val) cell.2.val, 1) ::
      ((boundSource cell).toList.map fun index => (index, 160))
    targetRoot := constantNode cell }

private theorem constant_realizes (cell : BoundCell) :
    Realizes program.csrExpressions (constantNode cell)
      (.constant (boundConstant cell)) := by
  rcases cell with ⟨which, lane⟩
  fin_cases which <;> fin_cases lane <;> exact Realizes.constant (by decide)

private def attemptChunk (cell : BoundCell) : List CsrExecutableAttempt :=
  if cell.1.val * 16 + cell.2.val < 27 then exactCsrAttemptsChunk0596
  else exactCsrAttemptsChunk0597

private theorem attempt_chunk_member (cell : BoundCell) :
    exactAttempt cell ∈ attemptChunk cell := by
  rcases cell with ⟨which, lane⟩
  fin_cases which <;> fin_cases lane <;> decide

private theorem attempt_member (cell : BoundCell) :
    exactAttempt cell ∈ program.csrAttempts := by
  change exactAttempt cell ∈ exactCsrAttempts
  unfold exactCsrAttempts
  apply List.mem_flatten_of_mem (l := attemptChunk cell) _ (attempt_chunk_member cell)
  unfold attemptChunk
  split
  · exact List.getElem_mem (n := 596) (by decide)
  · exact List.getElem_mem (n := 597) (by decide)

def certificate : BoundFrameCertificate program where
  canonical := SmzaRp05SingleKeyPrfSourceCanonical.csrCanonical
  oneNode := 1
  negativeNode := 160
  constantNode := constantNode
  oneRealizes := Realizes.constant (by decide)
  negativeRealizes := Realizes.sub
    (leftNode := 0) (rightNode := 1)
    (by decide) (by decide) (by decide)
    (Realizes.constant (by decide)) (Realizes.constant (by decide))
  constantRealizes := constant_realizes
  attempt := exactAttempt
  member := attempt_member
  terms := by intro cell; rfl
  target := by intro cell; rfl

theorem current_bound_initial_state {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (which : Fin 2) :
    V8Smz9SemanticPoseidonKernelBinding.packedInitialState packed (107 + which.val) =
      boundFrame packed which :=
  accepted_bound_initial_state certificate accepted which

theorem current_bound_compress14 {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (which : Fin 2) :
    (SmzaRp05AccumulatorHashBridge.packedFinalState packed (107 + which.val)).take 7 =
      Poseidon2V8SemanticSpecification.poseidon2V8Compress14 0x484d_4244_5632_0001
        (bindingKey packed) (bindingRight packed which) := by
  have trace := current_hash_call_state accepted (call := 107 + which.val) (by omega)
  rw [current_bound_initial_state accepted which] at trace
  rw [← trace]
  unfold Poseidon2V8SemanticSpecification.poseidon2V8Compress14
  apply congrArg (fun state => (Poseidon2Width16Kernel.permutation state).take 7)
  apply List.map_congr_left
  intro lane member
  have laneBound : lane < 16 := List.mem_range.mp member
  fin_cases which <;> interval_cases lane <;>
    simp [bindingKey, bindingRight,
      SmzaRp05AccumulatorHashBridge.packedFinalState,
      V8Smz9SemanticDecoder.packedWord,
      Poseidon2V8SemanticSpecification.digestWords,
      Poseidon2V8SemanticSpecification.poseidon2V8SuiteMarker,
      List.getD_eq_getElem?_getD]

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureBoundFrame
