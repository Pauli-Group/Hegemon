import HegemonCrypto.SmallWoodV8Smz9PiopReconstruction

/-! A projection of the abstract six-opening reconstruction.  Keeping the
trace and target abstract prevents a concrete RP05 verifier trace from being
unfolded merely to select the nonlinear component. -/

namespace HegemonCrypto.SmallWood.SmzaRp05AbstractReconstructionProjection

open V8Smz9PiopReconstruction
open V8Smz9PiopSoundness
open Polynomial

theorem reconstructed_nonlinear_evaluation
    (opening : Opening) (high : ProofHighs) (trace : EvaluationTrace)
    (target : Fin 5 → Goldilocks) (row : Fin 5) (coordinate : Fin 6) :
    ((reconstructedTranscript opening high trace target).nonlinear row).eval
        (points opening coordinate) = trace.nonlinear row coordinate := by
  simpa only [reconstructedTranscript] using
    (restored_nonlinear_evaluation opening (high.nonlinear row)
      (trace.nonlinear row) coordinate)

end HegemonCrypto.SmallWood.SmzaRp05AbstractReconstructionProjection
