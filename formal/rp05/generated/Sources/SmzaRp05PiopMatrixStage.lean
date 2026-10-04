import SmzaRp05PcsHashFppMiddle
import SmzaRp05ExecutableReconstruction

/-!
# PIOP batching matrix from the computed PCS hash

COMPILED DEVELOPMENT PROJECTION. Rust `derive_gamma_prime` requests five rows of
`max(nonlinearConstraints, linearConstraints)` canonical field words from the
PIoP-coefficient role seeded by `hash_fpp`. This stage samples exactly that
matrix from the digest produced by the preceding PCS/LVCS/DECS program. It
does not accept a matrix or digest as a separate proof field.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PiopMatrixStage

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8Smz9PiopSoundness
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

def matrixFromWords (width : Nat) (words : List FieldWord) : Matrix width :=
  fun row column =>
    (words.getD (row.val * width + column.val)
      SmzaRp05ExecutableChallengeStage.zeroWord).val

/-- The pending state is retained if capped field sampling is exhausted; the
final PIOP gate, not a supplied certificate, must reject that state. -/
def matrixProgram (width : Nat) (pending : Bool) (hashFpp : RawDigest) :
    Program (Matrix width × Bool) :=
  (SmzaRp05ExecutableChallengeStage.fieldXof
    SmallWoodTranscript.piopCoefficientDomain (5 * width) hashFpp).bind
      fun sampled =>
        .done (some (matrixFromWords width
          (SmzaRp05ExecutableChallengeStage.returnedWords (5 * width) sampled),
          SmzaRp05ExecutableChallengeStage.pendingFailure pending sampled))

end HegemonCrypto.SmallWood.SmzaRp05PiopMatrixStage
