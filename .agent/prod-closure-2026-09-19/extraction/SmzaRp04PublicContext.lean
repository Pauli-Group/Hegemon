import SmzaRp04ProgramPiop
import SmzaRp04PackedAcceptance
namespace HegemonCrypto.SmallWood.SmzaRp04PublicContext
open SmzaRp04ProgramPiop
open scoped BigOperators
noncomputable section
export V8Smz9CurrentPublicContext (PackedIndex packedFieldValues packingValues)
export SmzaRp04PackedAcceptance (publicExpressionValues rawCoefficient rowTarget rowEmpty
  rowEmitted normalizedCoefficient retainedAttempts)
def batchingWidth (publicValues : List Nat) : Nat := max 773 (retainedAttempts publicValues).length
def publicParameters (publicValues : List Nat) (gamma : Fin 5 → Nat → Goldilocks) :
    CurrentPublicParameters where
  publicValues := publicValues
  nonlinearGamma := fun polynomial root => gamma polynomial root.val
  linearWeights := fun polynomial row lane =>
    ∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * normalizedCoefficient publicValues
        (retainedAttempts publicValues)[index.val] (finProdFinEquiv (row, lane))
  linearTargets := fun polynomial =>
    ∑ index : Fin (retainedAttempts publicValues).length,
      gamma polynomial index.val * rowTarget publicValues (retainedAttempts publicValues)[index.val]


end
end HegemonCrypto.SmallWood.SmzaRp04PublicContext
