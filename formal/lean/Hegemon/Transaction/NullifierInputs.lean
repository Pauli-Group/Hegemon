import Hegemon.Bytes
import Hegemon.Transaction.NoteCommitmentInputs

namespace Hegemon
namespace Transaction
namespace NullifierInputs

open Hegemon.Transaction.NoteCommitmentInputs

def nullifierDomainTag : Nat := 2

def nullifierInputs
    (prfKey position : Nat)
    (rho : List Byte) : List Nat :=
  [prfKey, position] ++ bytes32ToFelts rho

theorem nullifier_domain_tag_is_two :
    nullifierDomainTag = 2 := by
  rfl

theorem nullifier_inputs_have_six_limbs
    (prfKey position : Nat)
    (rho : List Byte) :
    (nullifierInputs prfKey position rho).length = 6 := by
  simp [nullifierInputs, bytes32ToFelts]

theorem nullifier_inputs_start_with_prf_and_position
    (prfKey position : Nat)
    (rho : List Byte) :
    (nullifierInputs prfKey position rho).take 2 = [prfKey, position] := by
  simp [nullifierInputs, bytes32ToFelts]

theorem nullifier_inputs_absorb_rho_after_position
    (prfKey position : Nat)
    (rho : List Byte) :
    (nullifierInputs prfKey position rho).drop 2 = bytes32ToFelts rho := by
  simp [nullifierInputs, bytes32ToFelts]

theorem nullifier_inputs_one_absorb_block
    (prfKey position : Nat)
    (rho : List Byte) :
    (nullifierInputs prfKey position rho).length <= 6 := by
  simp [nullifierInputs, bytes32ToFelts]

end NullifierInputs
end Transaction
end Hegemon
