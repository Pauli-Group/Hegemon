import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerPairActiveLookup

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem signer_pair_root_member {left right : Nat} (ordered : left < right)
    (leftBound : left < 6) (rightBound : right < 6) :
    1858 + 9 * signerPairIndexLookup left right ∈ exactNonlinearRoots := by
  interval_cases left <;> interval_cases right <;> decide

end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
