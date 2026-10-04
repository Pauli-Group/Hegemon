import SmzaRp05NullifierSourceBase
import SmzaRp05Components
import SmzaRp05LocalCertificate
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Minimal extraction of the generated current-RP05 public-copy
certificate, without importing the aggregate nullifier source. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPublicCertificate

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierSource
open _root_.HegemonCrypto.SmallWood.SmzaRp05Components
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 4000000

def publicAttemptData : Array CsrExecutableAttempt := #[
  { globalIndex := 18319, family := 22, localIndex := 0, emission := 1, terms := [(28773, 4)], targetRoot := 263 },
  { globalIndex := 18320, family := 22, localIndex := 1, emission := 1, terms := [(28837, 4)], targetRoot := 264 },
  { globalIndex := 18321, family := 22, localIndex := 2, emission := 1, terms := [(28901, 4)], targetRoot := 265 },
  { globalIndex := 18322, family := 22, localIndex := 3, emission := 1, terms := [(28965, 4)], targetRoot := 266 },
  { globalIndex := 18323, family := 22, localIndex := 4, emission := 1, terms := [(29029, 4)], targetRoot := 267 },
  { globalIndex := 18324, family := 22, localIndex := 5, emission := 1, terms := [(29093, 4)], targetRoot := 268 },
  { globalIndex := 18325, family := 22, localIndex := 6, emission := 1, terms := [(29157, 4)], targetRoot := 269 },
  { globalIndex := 18326, family := 22, localIndex := 7, emission := 1, terms := [(40394, 5)], targetRoot := 278 },
  { globalIndex := 18327, family := 22, localIndex := 8, emission := 1, terms := [(40458, 5)], targetRoot := 279 },
  { globalIndex := 18328, family := 22, localIndex := 9, emission := 1, terms := [(40522, 5)], targetRoot := 280 },
  { globalIndex := 18329, family := 22, localIndex := 10, emission := 1, terms := [(40586, 5)], targetRoot := 281 },
  { globalIndex := 18330, family := 22, localIndex := 11, emission := 1, terms := [(40650, 5)], targetRoot := 282 },
  { globalIndex := 18331, family := 22, localIndex := 12, emission := 1, terms := [(40714, 5)], targetRoot := 283 },
  { globalIndex := 18332, family := 22, localIndex := 13, emission := 1, terms := [(40778, 5)], targetRoot := 284 }
]

private def emptyAttempt : CsrExecutableAttempt :=
  { globalIndex := 0, family := 0, localIndex := 0, emission := 0,
    terms := [], targetRoot := 0 }

def publicAttempt (cell : PublicCell) : CsrExecutableAttempt :=
  (publicAttemptData[cell.1.val * 7 + cell.2.val]?).getD emptyAttempt

private theorem public_target_mul_found (cell : PublicCell) :
    program.csrExpressions[(publicAttempt cell).targetRoot]? =
      some (.mul (4 + cell.1.val) (8 + cell.1.val * 7 + cell.2.val)) := by
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;> decide

private theorem public_active_found (input : Fin 2) :
    program.csrExpressions[(4 + input.val)]? = some (.publicWord input.val) := by
  fin_cases input <;> decide

private theorem public_target_found (cell : PublicCell) :
    program.csrExpressions[(8 + cell.1.val * 7 + cell.2.val)]? =
      some (.publicWord (4 + cell.1.val * 7 + cell.2.val)) := by
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;> decide

private theorem public_left_before_target (cell : PublicCell) :
    4 + cell.1.val < (publicAttempt cell).targetRoot := by
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;> decide

private theorem public_right_before_target (cell : PublicCell) :
    8 + cell.1.val * 7 + cell.2.val < (publicAttempt cell).targetRoot := by
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;> decide

private theorem public_attempt_chunk_member (cell : PublicCell) :
    publicAttempt cell ∈ exactCsrAttemptsChunk0572 := by
  rcases cell with ⟨input, limb⟩
  fin_cases input <;> fin_cases limb <;>
    simp [publicAttempt, publicAttemptData, emptyAttempt] <;> decide

private theorem public_attempt_member (cell : PublicCell) :
    publicAttempt cell ∈ program.csrAttempts := by
  change publicAttempt cell ∈ exactCsrAttempts
  unfold exactCsrAttempts
  apply List.mem_flatten_of_mem (l := exactCsrAttemptsChunk0572)
  · exact List.getElem_mem (n := 572) (by decide)
  · exact public_attempt_chunk_member cell

theorem generated_current_public_target_realizes (cell : PublicCell) :
    Realizes program.csrExpressions (publicAttempt cell).targetRoot
      (.mul (.publicInput cell.1.val)
        (.publicInput (4 + cell.1.val * 7 + cell.2.val))) := by
  exact Realizes.mul (public_target_mul_found cell)
    (public_left_before_target cell) (public_right_before_target cell)
    (Realizes.publicInput (public_active_found cell.1))
    (Realizes.publicInput (public_target_found cell))

def publicCertificate : PublicCertificate program :=
  { canonical := by apply (checkExpressionProgram_eq_true _ _).mp; decide
    activeNode := fun input => 4 + input.val
    targetNode := fun cell => (publicAttempt cell).targetRoot
    activeRealizes := by intro input; fin_cases input <;> exact Realizes.publicInput (by decide)
    targetRealizes := generated_current_public_target_realizes
    attempt := publicAttempt
    member := public_attempt_member
    attemptTerms := by intro cell; rcases cell with ⟨input, limb⟩; fin_cases input <;> fin_cases limb <;> rfl
    attemptTarget := by intro cell; rfl }

end HegemonCrypto.SmallWood.SmzaRp05CurrentPublicCertificate
