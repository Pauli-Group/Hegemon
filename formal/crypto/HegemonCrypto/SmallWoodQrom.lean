import HegemonCrypto.SmallWoodRom

/-!
# SmallWood standard-QROM transfer boundary

This module checks the exact point at which the deployed SmallWood Fiat-Shamir transcript meets,
or fails to meet, the multi-round measure-and-reprogram theorem of Don, Fehr, and Majenz
(`ePrint 2020/282`, Corollary 13).

The deployed protocol has four public-coin challenge stages, corresponding to DECS degree
enforcement, PIOP batching, PIOP evaluation, and DECS opening sampling.  The generic theorem
therefore has numerator `4! = 24` and denominator `(2q + 5)^8`.  Its duplicate-free-input
hypothesis is not automatic for the deployed transcript: the two digest-only inputs have the same
shape, as do the two nonce-and-digest inputs.  The checked counterexample below prevents this
package from silently treating the current untagged wire as a direct theorem instantiation.

The round-tagged construction is a protocol repair target, not the deployed transcript.  Applying
it would change challenge bytes and requires an explicit versioned migration.
-/

namespace HegemonCrypto.SmallWood.Qrom

open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Rom
open Hegemon.Transaction.SmallWoodNoGrindingSoundness

/-- The four interactive public-coin stages underlying the deployed non-interactive argument. -/
inductive ChallengeRound where
  | decsDegreeEnforcement
  | piopBatching
  | piopEvaluation
  | decsOpeningSampling
deriving DecidableEq, Repr

def allChallengeRounds : List ChallengeRound :=
  [ .decsDegreeEnforcement,
    .piopBatching,
    .piopEvaluation,
    .decsOpeningSampling ]

def activeFiatShamirRoundCount : Nat := allChallengeRounds.length

theorem active_fiat_shamir_round_count :
    activeFiatShamirRoundCount = 4 := by
  rfl

/-- Exact inputs to the four challenge-producing XOF calls after transcript hashes are computed. -/
structure ChallengeInputs where
  decsCommitmentDigest : List Word
  piopCommitmentDigest : List Word
  piopOpeningNonce : Word
  piopTranscriptDigest : List Word
  decsOpeningNonce : Word
  decsTranscriptDigest : List Word
deriving DecidableEq, Repr

/-- Runtime shape contract: every stored digest is the four-word deployed digest. -/
def ChallengeInputs.WellFormed (inputs : ChallengeInputs) : Prop :=
  inputs.decsCommitmentDigest.length = digestWordCount
    ∧ inputs.piopCommitmentDigest.length = digestWordCount
    ∧ inputs.piopTranscriptDigest.length = digestWordCount
    ∧ inputs.decsTranscriptDigest.length = digestWordCount

def ChallengeInputs.words (inputs : ChallengeInputs) : List (List Word) :=
  [ inputs.decsCommitmentDigest,
    inputs.piopCommitmentDigest,
    inputs.piopOpeningNonce :: inputs.piopTranscriptDigest,
    inputs.decsOpeningNonce :: inputs.decsTranscriptDigest ]

/-- The deployed challenge inputs have exact word lengths `4, 4, 5, 5`. -/
theorem well_formed_challenge_input_lengths
    (inputs : ChallengeInputs)
    (wellFormed : inputs.WellFormed) :
    (inputs.words.map List.length) = [4, 4, 5, 5] := by
  rcases wellFormed with ⟨decsCommitment, piopCommitment, piopTranscript, decsTranscript⟩
  simp [ChallengeInputs.words, digestWordCount, decsCommitment, piopCommitment,
    piopTranscript, decsTranscript]

/-- Active XOF output-prefix lengths used by the four challenge stages. -/
def activeChallengeOutputWordCounts : List Nat := [3, 16, 3, 6]

theorem active_challenge_output_word_counts_are_nonzero :
    ∀ count ∈ activeChallengeOutputWordCounts, 0 < count := by
  decide

/-- Direct DFMS applicability requires every challenge-reprogramming input to be distinct. -/
def DeployedChallengeInputsAreDuplicateFree : Prop :=
  ∀ inputs : ChallengeInputs, inputs.WellFormed → inputs.words.Nodup

private def repeatedDigest : List Word :=
  List.replicate digestWordCount 0

private def collidedChallengeInputs : ChallengeInputs :=
  { decsCommitmentDigest := repeatedDigest,
    piopCommitmentDigest := repeatedDigest,
    piopOpeningNonce := 0,
    piopTranscriptDigest := repeatedDigest,
    decsOpeningNonce := 0,
    decsTranscriptDigest := repeatedDigest }

private theorem collided_challenge_inputs_well_formed :
    collidedChallengeInputs.WellFormed := by
  simp [ChallengeInputs.WellFormed, collidedChallengeInputs, repeatedDigest,
    digestWordCount]

private theorem collided_challenge_inputs_are_not_duplicate_free :
    ¬collidedChallengeInputs.words.Nodup := by
  simp [ChallengeInputs.words, collidedChallengeInputs]

/--
The deployed untagged format does not provide the theorem's deterministic duplicate-free
hypothesis.  This is a format mismatch, not a claim that an honest transcript actually collides.
-/
theorem deployed_challenge_inputs_are_not_unconditionally_duplicate_free :
    ¬DeployedChallengeInputsAreDuplicateFree := by
  intro claimed
  exact collided_challenge_inputs_are_not_duplicate_free
    (claimed collidedChallengeInputs collided_challenge_inputs_well_formed)

/-- A one-word role tag for the protocol repair target. -/
def ChallengeRound.tag : ChallengeRound → Word
  | .decsDegreeEnforcement => 0
  | .piopBatching => 1
  | .piopEvaluation => 2
  | .decsOpeningSampling => 3

def taggedChallengeInput (round : ChallengeRound) (payload : List Word) : List Word :=
  round.tag :: payload

def ChallengeInputs.taggedWords (inputs : ChallengeInputs) : List (List Word) :=
  [ taggedChallengeInput .decsDegreeEnforcement inputs.decsCommitmentDigest,
    taggedChallengeInput .piopBatching inputs.piopCommitmentDigest,
    taggedChallengeInput .piopEvaluation
      (inputs.piopOpeningNonce :: inputs.piopTranscriptDigest),
    taggedChallengeInput .decsOpeningSampling
      (inputs.decsOpeningNonce :: inputs.decsTranscriptDigest) ]

/-- Explicit round tags make all four challenge inputs distinct for every payload. -/
theorem tagged_challenge_inputs_are_duplicate_free (inputs : ChallengeInputs) :
    inputs.taggedWords.Nodup := by
  simp [ChallengeInputs.taggedWords, taggedChallengeInput, ChallengeRound.tag]

/--
Requirements that must be discharged before Corollary 13 can be instantiated for the production
argument.  The common finite challenge range and quantum interactive PoK fields are explicit
because neither follows from classical straight-line extraction.
-/
structure MeasureAndReprogramInstantiation
    (CommonFiniteChallengeRange
      InteractiveQuantumProofOfKnowledge
      EveryQuantumOracleQueryCounted : Prop) : Prop where
  duplicateFreeInputs : DeployedChallengeInputsAreDuplicateFree
  commonFiniteChallengeRange : CommonFiniteChallengeRange
  interactiveQuantumProofOfKnowledge : InteractiveQuantumProofOfKnowledge
  everyQuantumOracleQueryCounted : EveryQuantumOracleQueryCounted

/-- The current untagged transcript cannot directly instantiate the cited generic theorem. -/
theorem no_direct_measure_and_reprogram_instantiation :
    ∀ commonFiniteChallengeRange interactiveQuantumProofOfKnowledge
        everyQuantumOracleQueryCounted,
      ¬MeasureAndReprogramInstantiation commonFiniteChallengeRange
        interactiveQuantumProofOfKnowledge everyQuantumOracleQueryCounted := by
  intro commonFiniteChallengeRange interactiveQuantumProofOfKnowledge
    everyQuantumOracleQueryCounted instantiation
  exact deployed_challenge_inputs_are_not_unconditionally_duplicate_free
    instantiation.duplicateFreeInputs

section ExactTransferLoss

/-- Exact denominator `(2q + n + 1)^(2n)` at the active `n = 4`. -/
def activeTransferDenominator (queries : Nat) : Nat :=
  (2 * queries + activeFiatShamirRoundCount + 1) ^
    (2 * activeFiatShamirRoundCount)

/-- Exact numerator `n!` at the active `n = 4`. -/
def activeTransferNumerator : Nat :=
  Nat.factorial activeFiatShamirRoundCount

theorem active_transfer_numerator_is_24 : activeTransferNumerator = 24 := by
  decide

theorem active_transfer_denominator_exact (queries : Nat) :
    activeTransferDenominator queries = (2 * queries + 5) ^ 8 := by
  simp [activeTransferDenominator, activeFiatShamirRoundCount, allChallengeRounds]

/--
Optimistic generic-QROM bound: only the four-term interactive algebraic error multiplied by the
published transfer loss.  This deliberately omits the theorem's additive challenge-space term,
hash collisions, transcript-mismatch loss, and executable-refinement loss, so failure here is a
strong parameter no-go for this proof route.
-/
def optimisticQromLoss (queries : Nat) : ℚ :=
  ((activeTransferDenominator queries : Nat) : ℚ) /
      activeTransferNumerator *
    ((aggregateErrorNumerator : Nat) : ℚ) / aggregateErrorDenominator

def optimisticQromLossNumerator (queries : Nat) : Nat :=
  activeTransferDenominator queries * aggregateErrorNumerator

def optimisticQromLossDenominator : Nat :=
  activeTransferNumerator * aggregateErrorDenominator

def supportsOptimisticQromBits (bits queries : Nat) : Prop :=
  2 ^ bits * optimisticQromLossNumerator queries ≤ optimisticQromLossDenominator

/-- The symbolic optimistic loss is exactly the checked natural common fraction. -/
theorem optimistic_qrom_loss_eq_common_fraction (queries : Nat) :
    optimisticQromLoss queries =
      (optimisticQromLossNumerator queries : ℚ) /
        optimisticQromLossDenominator := by
  have transferNumeratorPositive : 0 < activeTransferNumerator := by
    rw [active_transfer_numerator_is_24]
    decide
  have aggregateDenominatorPositive : 0 < aggregateErrorDenominator := by decide
  have transferNumeratorNonzero : (activeTransferNumerator : ℚ) ≠ 0 := by
    exact_mod_cast transferNumeratorPositive.ne'
  have aggregateDenominatorNonzero : (aggregateErrorDenominator : ℚ) ≠ 0 := by
    exact_mod_cast aggregateDenominatorPositive.ne'
  unfold optimisticQromLoss optimisticQromLossNumerator optimisticQromLossDenominator
  push_cast
  field_simp

/-- Bit-floor checks are equivalent to the corresponding rational probability inequality. -/
theorem supports_optimistic_qrom_bits_iff (bits queries : Nat) :
    supportsOptimisticQromBits bits queries ↔
      optimisticQromLoss queries ≤ (1 : ℚ) / 2 ^ bits := by
  rw [optimistic_qrom_loss_eq_common_fraction]
  unfold supportsOptimisticQromBits
  have denominatorPositive : 0 < optimisticQromLossDenominator := by
    unfold optimisticQromLossDenominator
    exact Nat.mul_pos (by rw [active_transfer_numerator_is_24]; decide) (by decide)
  have scalePositive : 0 < 2 ^ bits := by positivity
  rw [div_le_div_iff₀ (by exact_mod_cast denominatorPositive)
    (by exact_mod_cast scalePositive)]
  norm_cast
  simp [Nat.mul_comm]

theorem active_transfer_denominator_mono
    {smaller larger : Nat}
    (queryBound : smaller ≤ larger) :
    activeTransferDenominator smaller ≤ activeTransferDenominator larger := by
  rw [active_transfer_denominator_exact, active_transfer_denominator_exact]
  exact Nat.pow_le_pow_left
    (Nat.add_le_add_right (Nat.mul_le_mul_left 2 queryBound) 5) 8

theorem optimistic_qrom_loss_numerator_mono
    {smaller larger : Nat}
    (queryBound : smaller ≤ larger) :
    optimisticQromLossNumerator smaller ≤ optimisticQromLossNumerator larger := by
  exact Nat.mul_le_mul_right aggregateErrorNumerator
    (active_transfer_denominator_mono queryBound)

/-- Even at one quantum query, the optimistic generic transfer retains a checked 110-bit floor. -/
theorem optimistic_qrom_one_query_supports_110_bits :
    supportsOptimisticQromBits 110 1 := by
  unfold supportsOptimisticQromBits optimisticQromLossNumerator
    optimisticQromLossDenominator activeTransferNumerator activeTransferDenominator
    activeFiatShamirRoundCount allChallengeRounds
  decide

/-- The same already-optimistic one-query bound does not retain 111 bits. -/
theorem optimistic_qrom_one_query_does_not_support_111_bits :
    ¬supportsOptimisticQromBits 111 1 := by
  unfold supportsOptimisticQromBits optimisticQromLossNumerator
    optimisticQromLossDenominator activeTransferNumerator activeTransferDenominator
    activeFiatShamirRoundCount allChallengeRounds
  decide

/-- In particular, the active parameters cannot certify 128 bits through this generic route. -/
theorem optimistic_qrom_one_query_does_not_support_128_bits :
    ¬supportsOptimisticQromBits 128 1 := by
  unfold supportsOptimisticQromBits optimisticQromLossNumerator
    optimisticQromLossDenominator activeTransferNumerator activeTransferDenominator
    activeFiatShamirRoundCount allChallengeRounds
  decide

/-- No positive quantum-query budget recovers the missing 128-bit margin. -/
theorem optimistic_qrom_positive_queries_do_not_support_128_bits
    {queries : Nat}
    (positiveQueries : 1 ≤ queries) :
    ¬supportsOptimisticQromBits 128 queries := by
  intro claimed
  apply optimistic_qrom_one_query_does_not_support_128_bits
  unfold supportsOptimisticQromBits at claimed ⊢
  exact (Nat.mul_le_mul_left (2 ^ 128)
    (optimistic_qrom_loss_numerator_mono positiveQueries)).trans claimed

end ExactTransferLoss

end HegemonCrypto.SmallWood.Qrom
