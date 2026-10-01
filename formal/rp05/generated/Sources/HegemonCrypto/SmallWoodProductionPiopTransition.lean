import HegemonCrypto.SmallWoodProductionRoundByRound

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Exact production PIOP verifier transition

This module keeps the generated production constraint certificate abstract while connecting the
semantic affine batching event to the exact Rust nonlinear, sparse-linear, and opening equations.
-/

namespace HegemonCrypto.SmallWood.ProductionPiopTransition

open Polynomial
open scoped BigOperators
open HegemonCrypto.SmallWood.Interactive
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.PiopExtraction
open HegemonCrypto.SmallWood.ProductionPiop
open HegemonCrypto.SmallWood.ProductionRoundByRound
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

/--
If the semantic affine challenge event fails, one exact Rust verifier equation is already exposed
as nonzero: either a nonlinear packing-lane batch or the sparse-linear affine target equation.
-/
theorem piop_affine_challenge_failure_yields_production_batch_failure
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (challenge : PiopBatchingChallenge statement)
    (challengeFailure :
      ¬ PiopAffineChallengePasses
        statement oracle active (productionLinearMaskSum oracle) challenge) :
    ∃ repetition : Fin rho,
      (∃ lane : Nat,
        lane < statement.lppcPackingFactor ∧
          (productionNonlinearBatch
            statement oracle challenge repetition).eval
              (packingNodePoint lane) ≠ 0) ∨
        nodeSum
            (Finset.range statement.lppcPackingFactor)
            packingNodePoint
            (productionLinearBatch statement oracle challenge repetition) +
              productionLinearMaskSum oracle repetition ≠
          productionLinearBatchTarget statement challenge repetition := by
  have notAccepted :
      ¬ AffineBatchAccepts
        (extractedPaddedSystem statement oracle active)
        (productionLinearMaskSum oracle)
        (piopChallengeToGoldilocks statement challenge) := by
    simpa [PiopAffineChallengePasses, affineBatchFailureSet]
      using challengeFailure
  unfold AffineBatchAccepts at notAccepted
  push Not at notAccepted
  obtain ⟨repetition, rowFailure⟩ := notAccepted
  refine ⟨repetition, ?_⟩
  by_cases nonlinearPasses :
      ∀ node ∈ (extractedPaddedSystem statement oracle active).nodes,
        (nonlinearBatch
          (extractedPaddedSystem statement oracle active)
          ((piopChallengeToGoldilocks statement challenge) repetition)).eval
            ((extractedPaddedSystem statement oracle active).point node) = 0
  · right
    have linearFailure := rowFailure nonlinearPasses
    have semanticFailure :
        nodeSum
            (Finset.range statement.lppcPackingFactor)
            packingNodePoint
            (linearBatch
              (extractedPaddedSystem statement oracle active)
              ((piopChallengeToGoldilocks statement challenge) repetition)) +
              productionLinearMaskSum oracle repetition ≠
          Finset.univ.sum (fun linear =>
            piopChallengeToGoldilocks statement challenge repetition linear *
              (extractedPaddedSystem
                statement oracle active).linearTarget linear) := by
      simpa [extractedPaddedSystem, paddedProductionSystem,
        extractedProductionOracles] using linearFailure
    rw [extracted_padded_linear_batch_node_sum_eq_production
        statement oracle active challenge repetition,
      extracted_padded_linear_target_batch_eq_production
        statement oracle active challenge repetition] at semanticFailure
    exact semanticFailure
  · left
    push Not at nonlinearPasses
    obtain ⟨lane, laneMembership, semanticFailure⟩ := nonlinearPasses
    have laneBound : lane < statement.lppcPackingFactor := by
      simpa [extractedPaddedSystem, paddedProductionSystem,
        extractedProductionOracles] using laneMembership
    refine ⟨lane, laneBound, ?_⟩
    have normalizedFailure :
        (nonlinearBatch
          (extractedPaddedSystem statement oracle active)
          ((piopChallengeToGoldilocks statement challenge) repetition)).eval
            (packingNodePoint lane) ≠ 0 := by
      simpa [extractedPaddedSystem, paddedProductionSystem,
        extractedProductionOracles] using semanticFailure
    rw [extracted_padded_nonlinear_batch_eval_eq_production
      statement oracle active challenge repetition lane laneBound] at normalizedFailure
    exact normalizedFailure

end

end HegemonCrypto.SmallWood.ProductionPiopTransition
