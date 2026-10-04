import SmzaRp05NullifierSourceBase
import SmzaRp05Components
import SmzaRp05LocalCertificate

/-! Minimal extraction of the current RP05 64-root position-boolean
certificate, without importing the aggregate nullifier source. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDirectionCertificate

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierSource
open _root_.HegemonCrypto.SmallWood.SmzaRp05Components
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement (inputDirectionRow)

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 4000000

def directionRoot (input : Fin 2) (bit : Fin 32) : Nat :=
  if input.val = 0 then 841 + 2 * bit.val else 918 + 2 * bit.val

private theorem direction_members (input : Fin 2) (bit : Fin 32) :
    directionRoot input bit ∈ program.nonlinearExecutable.roots := by
  fin_cases input <;> fin_cases bit <;> decide

private def directionLeftNode (input : Fin 2) (bit : Fin 32) : Nat :=
  if input.val = 0 then 126 + bit.val else 160 + bit.val

private theorem direction_mul_found (input : Fin 2) (bit : Fin 32) :
    program.nonlinearExecutable.expressions[directionRoot input bit]? =
      some (.mul (directionLeftNode input bit) (directionRoot input bit - 1)) := by
  fin_cases input <;> fin_cases bit <;> decide

private theorem direction_sub_found (input : Fin 2) (bit : Fin 32) :
    program.nonlinearExecutable.expressions[directionRoot input bit - 1]? =
      some (.sub (directionLeftNode input bit) 1) := by
  fin_cases input <;> fin_cases bit <;> decide

private theorem direction_witness_found (input : Fin 2) (bit : Fin 32) :
    program.nonlinearExecutable.expressions[directionLeftNode input bit]? =
      some (.witnessRow (inputDirectionRow input.val bit.val)) := by
  fin_cases input <;> fin_cases bit <;> decide

private theorem direction_one_found :
    program.nonlinearExecutable.expressions[1]? = some (.constant 1) := by
  decide

private theorem direction_left_before_root (input : Fin 2) (bit : Fin 32) :
    directionLeftNode input bit < directionRoot input bit := by
  fin_cases input <;> simp [directionLeftNode, directionRoot] <;> omega

private theorem direction_left_before_sub (input : Fin 2) (bit : Fin 32) :
    directionLeftNode input bit < directionRoot input bit - 1 := by
  fin_cases input <;> simp [directionLeftNode, directionRoot] <;> omega

private theorem direction_one_before_sub (input : Fin 2) (bit : Fin 32) :
    1 < directionRoot input bit - 1 := by
  fin_cases input <;> simp [directionRoot] <;> omega

private theorem direction_sub_before_root (input : Fin 2) (bit : Fin 32) :
    directionRoot input bit - 1 < directionRoot input bit := by
  fin_cases input <;> simp [directionRoot]

private theorem direction_realizes (input : Fin 2) (bit : Fin 32) :
    Realizes program.nonlinearExecutable.expressions (directionRoot input bit)
      (.mul (.witness (inputDirectionRow input.val bit.val))
        (.sub (.witness (inputDirectionRow input.val bit.val)) (.constant 1))) := by
  refine Realizes.mul (direction_mul_found input bit)
      (direction_left_before_root input bit) (direction_sub_before_root input bit)
      (Realizes.witness (direction_witness_found input bit))
      (Realizes.sub (direction_sub_found input bit)
        (direction_left_before_sub input bit) (direction_one_before_sub input bit)
        (Realizes.witness (direction_witness_found input bit))
        (Realizes.constant direction_one_found))

def directionCertificate : DirectionCertificate program :=
  { canonical := SmzaRp05LocalCertificate.certificate.canonical
    root := directionRoot
    member := direction_members
    realizes := direction_realizes }

end HegemonCrypto.SmallWood.SmzaRp05CurrentDirectionCertificate
