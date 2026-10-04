import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairActiveLookup

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem signer_pair_root_exact {left right : Nat} (ordered : left < right)
    (leftBound : left < 6) (rightBound : right < 6) :
    exactNonlinearExpressions[1858 + 9 * signerPairIndexLookup left right]? =
      some (.mul (1855 + 9 * signerPairIndexLookup left right)
        (1857 + 9 * signerPairIndexLookup left right)) := by
  interval_cases left <;> interval_cases right <;> decide

end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
