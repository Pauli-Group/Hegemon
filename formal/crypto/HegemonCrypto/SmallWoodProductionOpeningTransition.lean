import HegemonCrypto.SmallWoodProductionPiopTransition

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact production PIOP opening transition

This final algebraic step combines the exact challenge-transition witness with the separately
proved nonlinear and sparse-linear ordered-opening bounds.
-/

namespace HegemonCrypto.SmallWood.ProductionOpeningTransition

open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionPiopTransition
open HegemonCrypto.SmallWood.RoundByRound
open Hegemon.Transaction.SmallWoodNoGrindingSoundness

noncomputable section

/--
Outside the exact affine batching event, every claimed production PIOP message passes all ordered
opening checks with probability at most the active `epsilon3` term.
-/
theorem production_piop_opening_probability_le_of_affine_challenge_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (message : PiopPolynomialMessage)
    (claimedTarget : ClaimedLinearTarget statement challenge message)
    (challengeFailure :
      ¬ PiopAffineChallengePasses
        statement oracle active (productionLinearMaskSum oracle) challenge) :
    uniformEventProbability
        (ProductionPiopOpeningPasses
          statement oracle challenge message) ≤
      (epsilon3Numerator : Rat) / epsilon3Denominator := by
  obtain ⟨repetition, nonlinearFailure | linearFailure⟩ :=
    piop_affine_challenge_failure_yields_production_batch_failure
      statement oracle active challenge challengeFailure
  · obtain ⟨lane, laneBound, batchFailure⟩ := nonlinearFailure
    exact production_piop_opening_probability_le_of_nonlinear_batch_failure
      statement oracle active challenge message repetition lane laneBound batchFailure
  · have normalizedLinearFailure :
        HegemonCrypto.SmallWood.Interactive.nodeSum
            (Finset.range packingFactor)
            packingNodePoint
            (productionLinearBatch statement oracle challenge repetition) +
              productionLinearMaskSum oracle repetition ≠
          productionLinearBatchTarget statement challenge repetition := by
      simpa [active.2.1] using linearFailure
    exact production_piop_opening_probability_le_of_linear_affine_failure
      statement oracle challenge message claimedTarget repetition normalizedLinearFailure

end

end HegemonCrypto.SmallWood.ProductionOpeningTransition
