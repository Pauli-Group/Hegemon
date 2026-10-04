import SmzaRp04RawRoleSampling
import SmzaRp04McaRoleCells

/-! The two MCA contributions on actual capped raw challenge vectors.
These are success-and-bad events: no conditioning on successful parsing and
no exactly-uniform total map from binary blocks into Goldilocks is assumed. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawMcaSampling

open scoped Classical
open HegemonCrypto.CmsClassicalDatabase
open SmzaQ38OracleExtraction SmzaQ38McaSourceBinding
open SmzaRp04RoleBadCells SmzaRp04RawRoleSampling SmzaRp04McaRoleCells
open V8Smz9CappedRawSampler V8Smz9CoherentVectorMerkle
open V8Smz9RawCounterCompiler V8Smz9RuntimeFieldLayout
open V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution
open V8Smz9CoherentMerkleInstrument V8Smz9AdaptiveFiniteAccounting
open V8Smz9PiopSoundness

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option exponentiation.threshold 1024

noncomputable local instance facadeQueryNonempty : Nonempty Query := by
  let embedding : Fin 38 ↪ SmzaQ38McaSourceBinding.Position :=
    { toFun := fun index => ⟨index.val, index.isLt.trans (by decide)⟩
      inj' := by
        intro left right equal
        apply Fin.ext
        exact congrArg
          (fun position : SmzaQ38McaSourceBinding.Position => position.val) equal }
  exact ⟨⟨Finset.univ.map embedding, by simp⟩⟩

def decsMatrixFieldEquiv :
    FieldOutput sourceFieldSize (140 * 5) ≃ Coefficients :=
  (Equiv.piCongrRight fun _ => idealFieldCoinEquivGoldilocks).trans
    (matrixEquiv 140 5 Goldilocks)

def rawDecsMatrixOutput
    (raw : Fin (digestCallCap (140 * 5)) → RawByteBlock) : Option Coefficients :=
  (rawFieldSample (digestCallCap (140 * 5)) (140 * 5) raw).bind
    (totalEquivDecoder decsMatrixFieldEquiv)

def actualDecsMatrixOutput {Counter : Type*}
    (select : Fin (digestCallCap (140 * 5)) ↪ Counter)
    (vector : VectorOutput Counter) : Option Coefficients :=
  rawDecsMatrixOutput (selectedRawBlocks select vector)

theorem raw_matrix_bad_and_success_le (oracle : CommittedOracle) :
    outputEventProbability
      (fun raw : Fin (digestCallCap (5 * 140)) → RawByteBlock =>
        ∃ output, rawDecsMatrixOutput raw = some output ∧
          matrixBad oracle output) ≤ matrixLoss := by
  let bad : Finset Coefficients := Finset.univ.filter (matrixBad oracle)
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap (5 * 140)) (5 * 140)
    (totalEquivDecoder decsMatrixFieldEquiv)
    (total_equiv_decoder_fibers_equal decsMatrixFieldEquiv) bad
  have event : (fun raw : Fin (digestCallCap (5 * 140)) → RawByteBlock =>
      ∃ output, rawDecsMatrixOutput raw = some output ∧ output ∈ bad) =
    (fun raw => ∃ output, rawDecsMatrixOutput raw = some output ∧
      matrixBad oracle output) := by
    funext raw
    simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
  change outputEventProbability _ ≤ _
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      rw [← event]
      exact sampled
    _ = outputEventProbability (matrixBad oracle) := by
      calc
        _ = outputEventProbability (fun output => output ∈ bad) :=
          (output_event_probability_membership bad).symm
        _ = outputEventProbability (matrixBad oracle) := by
          apply congrArg outputEventProbability
          funext output
          apply propext
          simp [bad]
    _ ≤ matrixLoss := matrix_bad_output_density oracle

theorem raw_small_support_bad_and_success_le (label : SmallSupportLabel) :
    outputEventProbability
      (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
        ∃ output, rawDecsSampleOutput raw = some output ∧
          smallSupportBad label output) ≤ smallSupportLoss := by
  let bad : Finset Query := Finset.univ.filter (smallSupportBad label)
  have sampled := raw_field_then_partial_decoder_bad_le
    (digestCallCap q38CandidateCount) q38CandidateCount q38Decoder
    (fun left right => q38_decoder_fibers_equal left right) bad
  have event : (fun raw : Fin (digestCallCap q38CandidateCount) → RawByteBlock =>
      ∃ output, rawDecsSampleOutput raw = some output ∧ output ∈ bad) =
    (fun raw => ∃ output, rawDecsSampleOutput raw = some output ∧
      smallSupportBad label output) := by
    funext raw
    simp only [bad, Finset.mem_filter, Finset.mem_univ, true_and]
  calc
    _ ≤ V8Smz9RobustQueryMismatch.FiniteEvents.probability bad := by
      rw [← event]
      exact sampled
    _ = outputEventProbability (smallSupportBad label) := by
      calc
        _ = outputEventProbability (fun output => output ∈ bad) :=
          (output_event_probability_membership bad).symm
        _ = outputEventProbability (smallSupportBad label) := by
          apply congrArg outputEventProbability
          funext output
          apply propext
          simp [bad]
    _ ≤ smallSupportLoss := small_support_output_density label

theorem actual_matrix_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap (5 * 140)) ↪ Counter)
    (oracle : CommittedOracle) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualDecsMatrixOutput select vector = some output ∧
        matrixBad oracle output) ≤ matrixLoss := by
  change outputEventProbability (fun vector =>
    (fun raw => ∃ output, rawDecsMatrixOutput raw = some output ∧
      matrixBad oracle output) (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawDecsMatrixOutput raw = some output ∧
      matrixBad oracle output)]
  exact raw_matrix_bad_and_success_le oracle

theorem actual_small_support_bad_and_success_le
    {Counter : Type*} [Fintype Counter] [DecidableEq Counter]
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (label : SmallSupportLabel) :
    outputEventProbability (fun vector : VectorOutput Counter =>
      ∃ output, actualDecsSampleOutput select vector = some output ∧
        smallSupportBad label output) ≤ smallSupportLoss := by
  change outputEventProbability (fun vector =>
    (fun raw => ∃ output, rawDecsSampleOutput raw = some output ∧
      smallSupportBad label output) (selectedRawBlocks select vector)) ≤ _
  rw [selected_raw_blocks_event_probability select
    (fun raw => ∃ output, rawDecsSampleOutput raw = some output ∧
      smallSupportBad label output)]
  exact raw_small_support_bad_and_success_le label

/-- Four-role loss ledger including both MCA events. The older three-cell
algebra ledger deliberately did not include these contributions. -/
def completeRoleLoss : SmzaChallengeStageTargets.Role → Rat
  | .decsMatrix => matrixLoss
  | .piopMatrix => roleLoss .piopMatrix
  | .piopOpening => roleLoss .piopOpening
  | .decsSample => smallSupportLoss + roleLoss .decsSample

end
end HegemonCrypto.SmallWood.SmzaRp04RawMcaSampling
