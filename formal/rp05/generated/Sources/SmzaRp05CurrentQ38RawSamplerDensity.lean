import SmzaRp05CurrentQ38DetectionProbability
import SmzaRp04RawRoleSampling

/-!
# Current-map q38 density through the source raw sampler

The current RP05 discrepancy event has a uniform 38-subset bound. The
source's 50-word, first-38-distinct sampler has equal successful fibers, so
its bad-and-success mass is bounded by that same uniform-subset probability.
Restriction from a uniform complete vector output to the source-selected
coordinates preserves the bound. This is a finite uniform-output statement;
it does not identify an adaptive physical read's Born law.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentQ38RawSamplerDensity

open SmzaRp04RawRoleSampling
open SmzaRp05CurrentQ38DetectionProbability
open SmzaQ38McaSourceBinding
open SmzaQ38Recovery
open SmzaRp04ChronologicalAlgebra
open V8Smz9RobustQueryMismatch
open V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle
open V8Smz9McaRecovery
open HegemonCrypto.CmsClassicalDatabase
open V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1500000

attribute [local irreducible] querySampleFintype

noncomputable local instance currentDensityQueryNonempty : Nonempty Query := by
  classical
  let embedding : Fin 38 ↪ SmzaQ38McaSourceBinding.Position :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right equal
        apply Fin.ext
        exact congrArg
          (fun position : SmzaQ38McaSourceBinding.Position => position.val) equal }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

/-- The actual capped raw q38 sampler's successful output lies in the
current-map twelve-discrepancy bad event with probability at most the current
q38 root-count loss. Rejected streams remain in the denominator. -/
theorem raw_current_lvcs_bad_query_probability_le
    (rows : SmzaQ38Recovery.RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405) :
    outputEventProbability
      (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
        ∃ query, rawDecsSampleOutput raw = some query ∧
          query ∈ currentLvcsBadQueryEvent rows points claimed) ≤
      SmzaRp04ChronologicalAlgebra.q38LvcsLoss := by
  let bad := currentLvcsBadQueryEvent rows points claimed
  have decoderFiberEqual : ∀ left right : Query,
      Fintype.card (SuccessfulFiber q38Decoder left) =
        Fintype.card (SuccessfulFiber q38Decoder right) := by
    intro left right
    exact q38_decoder_fibers_equal left right
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap q38CandidateCount) q38CandidateCount q38Decoder
    decoderFiberEqual bad
  calc
    outputEventProbability
        (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
          ∃ query, rawDecsSampleOutput raw = some query ∧ query ∈ bad) ≤
        FiniteEvents.probability bad := by
      simpa only [rawDecsSampleOutput] using sampled
    _ ≤ SmzaRp04ChronologicalAlgebra.q38LvcsLoss := by
      dsimp [bad]
      exact current_lvcs_bad_query_probability_le rows points claimed
        rowsDegree claimedDegree

/-- Selected coordinates of a uniform full vector output induce the source
raw q38 sampler. The current-map bad-and-success event inherits the raw
sampler bound for every injective coordinate selection. -/
theorem current_decs_sample_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (rows : SmzaQ38Recovery.RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (rowsDegree : ∀ row, (rows row).natDegree ≤ 405)
    (claimedDegree : ∀ combination, (claimed combination).natDegree ≤ 405) :
    outputEventProbability
      (fun vector : VectorOutput Counter =>
        ∃ query, actualDecsSampleOutput select vector = some query ∧
          query ∈ currentLvcsBadQueryEvent rows points claimed) ≤
      SmzaRp04ChronologicalAlgebra.q38LvcsLoss := by
  change outputEventProbability
      (fun vector : VectorOutput Counter =>
        (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
          ∃ query, rawDecsSampleOutput raw = some query ∧
            query ∈ currentLvcsBadQueryEvent rows points claimed)
          (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ query, rawDecsSampleOutput raw = some query ∧
      query ∈ currentLvcsBadQueryEvent rows points claimed)]
  exact raw_current_lvcs_bad_query_probability_le rows points claimed
    rowsDegree claimedDegree

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentQ38RawSamplerDensity
