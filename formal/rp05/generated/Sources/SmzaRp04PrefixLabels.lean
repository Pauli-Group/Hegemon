import SmzaRp04RoleBadCells
import SmzaRp04McaRoleCells

/-! Pure chronological labels. Separating these definitions from the raw
sampler probability proof lets transcript readback use precisely the same
labels without depending on an unfinished sampler specialization. -/
namespace HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells

open SmzaRp04RoleBadCells SmzaRp04McaRoleCells
open SmzaRp04PublicContext SmzaRp04ChronologicalAlgebra
open SmzaRp04ActualProgram
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open scoped Classical

noncomputable section
set_option autoImplicit false

/-- Every field is fixed before its selected role output is sampled. -/
structure PrefixLabels (publicWords : List Nat) where
  decsMatrix : Option CommittedOracle
  piopMatrix : Option (PiopMatrixPrefixKey publicWords)
  piopOpening : Option (PiopOpeningLabel publicWords)
  smallSupport : Option SmallSupportLabel
  lvcs : Option DecsSamplePrefixKey

def matrixPrefix (publicWords : List Nat) (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients) :
    Option (PiopMatrixPrefixKey publicWords) :=
  match recoverSource oracle response coefficients with
  | none => none
  | some source =>
      if _invalid : ¬ PiopExtraction.FullySatisfied
          (recoveredCandidate publicWords source.data).system then
        some ⟨recoveredCandidate publicWords source.data⟩
      else none

def openingPrefix (publicWords : List Nat) (oracle : CommittedOracle)
    (response : ResponseStrategy) (coefficients : Coefficients)
    (matrix : Matrix (batchingWidth publicWords)) (claimed : ClaimedTranscript) :
    Option (PiopOpeningLabel publicWords) :=
  (recoverSource oracle response coefficients).map fun source =>
    ⟨recoveredCandidate publicWords source.data, matrix, claimed⟩

def supportPrefix (oracle : CommittedOracle) (response : ResponseStrategy)
    (coefficients : Coefficients) : Option SmallSupportLabel :=
  if small : (agreementSupport oracle response coefficients).card < 65536 then
    some ⟨agreementSupport oracle response coefficients, small⟩
  else none

def lvcsPrefix (publicWords : List Nat) (oracle : CommittedOracle)
    (response : ResponseStrategy) (strategy : Strategy publicWords)
    (coefficients : Coefficients) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) : Option DecsSamplePrefixKey :=
  match recoverSource oracle response coefficients with
  | none => none
  | some source => some
      { rows := source.data
        points := baseOpeningPoints opening.1
        claimedCoefficients :=
          (strategy.afterOpening coefficients matrix opening).claimedCoefficients }

def labelsAt (publicWords : List Nat) (oracle : CommittedOracle)
    (response : ResponseStrategy) (strategy : Strategy publicWords)
    (coefficients : Coefficients) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) : PrefixLabels publicWords where
  decsMatrix := some oracle
  piopMatrix := matrixPrefix publicWords oracle response coefficients
  piopOpening := openingPrefix publicWords oracle response coefficients matrix
    (strategy.piopResponse coefficients matrix)
  smallSupport := supportPrefix oracle response coefficients
  lvcs := lvcsPrefix publicWords oracle response strategy coefficients matrix opening

end
end HegemonCrypto.SmallWood.SmzaRp04CompleteRawRoleCells
