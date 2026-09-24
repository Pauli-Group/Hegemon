import HegemonCrypto.SmallWoodV8Smz9AuthorizationRoleNonzero

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def signerPairIndexLookup (left right : Nat) : Nat :=
  if left = 0 then right - 1
  else if left = 1 then right + 3
  else if left = 2 then right + 6
  else if left = 3 then right + 8
  else 14

def signerPairActiveExpressionLookup (left right : Nat) :=
  if right = 5 then
    Hegemon.Transaction.Poseidon2V8RelationProgram.FieldExpression.mul
      (signerSuffixNode right) (signerSuffixNode left)
  else
    Hegemon.Transaction.Poseidon2V8RelationProgram.FieldExpression.mul
      (signerSuffixNode left) (signerSuffixNode right)

theorem signer_pair_active_exact {left right : Nat} (ordered : left < right)
    (leftBound : left < 6) (rightBound : right < 6) :
    exactNonlinearExpressions[1853 + 9 * signerPairIndexLookup left right]? =
      some (signerPairActiveExpressionLookup left right) := by
  interval_cases left <;> interval_cases right <;> decide

end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
