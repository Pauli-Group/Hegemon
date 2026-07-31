import HegemonCrypto.SmallWoodRom

set_option maxRecDepth 100000
set_option exponentiation.threshold 512

/-!
# SmallWood V4 QROM transcript boundary

Circuit V4 uses four distinct SHA-512 domains for the four challenge-producing oracle calls.
Consequently the deterministic duplicate-free-input precondition that failed for historical
untagged transcripts now holds by byte syntax.  This file proves that format fact and records the
generic measure-and-reprogram loss without treating that generic route as the selected production
reduction.  A "challenge call" below is one logical field-XOF request.  It is not one SHA-512
digest invocation: a variable-output request can require several counter-mode digests, and
canonical nonce search can issue several logical requests.  The production route is the tighter
round-by-round BCS reduction in `SmallWoodBcsQrom`.
-/

namespace HegemonCrypto.SmallWood.Qrom

open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Rom
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open Hegemon.Transaction.SmallWoodTranscriptBinding

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

/-- Digest payloads used by the four challenge stages. -/
structure ChallengeInputs where
  decsCommitmentDigest : List Word
  piopCommitmentDigest : List Word
  piopOpeningNonce : Word
  piopTranscriptDigest : List Word
  decsTranscriptDigest : List Word
deriving DecidableEq, Repr

def ChallengeInputs.WellFormed (inputs : ChallengeInputs) : Prop :=
  inputs.decsCommitmentDigest.length = digestWordCount
    ∧ inputs.piopCommitmentDigest.length = digestWordCount
    ∧ inputs.piopTranscriptDigest.length = digestWordCount
    ∧ inputs.decsTranscriptDigest.length = digestWordCount

def ChallengeInputs.words (inputs : ChallengeInputs) : List (List Word) :=
  [ inputs.decsCommitmentDigest,
    inputs.piopCommitmentDigest,
    inputs.piopOpeningNonce :: inputs.piopTranscriptDigest,
    inputs.decsTranscriptDigest ]

theorem well_formed_challenge_input_lengths
    (inputs : ChallengeInputs)
    (wellFormed : inputs.WellFormed) :
    (inputs.words.map List.length) = [8, 8, 9, 8] := by
  rcases wellFormed with ⟨decsCommitment, piopCommitment, piopTranscript, decsTranscript⟩
  simp [ChallengeInputs.words, digestWordCount, decsCommitment, piopCommitment,
    piopTranscript, decsTranscript]

/--
Selected byte preimages for the four accepted challenge families.  These are the accepted
Fiat--Shamir edges, not the complete verifier hash-query trace: canonical nonce search also queries
all preceding candidate nonces and the native verifier currently recomputes the selected PIOP
opening once.
-/
def deployedChallengePreimages
    (oracle : Oracle)
    (transcript : Transcript) : List (List CanonicalBytes.Byte) :=
  [ firstChallengePreimage oracle transcript,
    secondChallengePreimage oracle transcript,
    thirdChallengePreimage oracle transcript,
    fourthChallengePreimage oracle transcript ]

def DeployedChallengeInputsAreDuplicateFree : Prop :=
  ∀ oracle transcript,
    (deployedChallengePreimages oracle transcript).Nodup

theorem deployed_challenge_inputs_are_duplicate_free :
    DeployedChallengeInputsAreDuplicateFree := by
  intro oracle transcript
  exact active_challenge_preimages_are_pairwise_distinct oracle transcript

/--
The active uniform DECS batching matrix has one field word for every repetition and committed
LVCS row.
-/
def activeDecsCoefficientWordCount : Nat :=
  HegemonCrypto.SmallWoodTranscript.activeDecsCoefficientWordCount

theorem active_decs_coefficient_word_count_is_690 :
    activeDecsCoefficientWordCount = 690 := by
  decide

/--
Active accepted-challenge output-prefix lengths: the uniform DECS matrix, the full uniform PIOP
matrix, one selected PIOP-opening candidate, and the fixed DECS candidate pool. The last 50 words
are deterministically filtered to the first 23 distinct indices.

Canonical PIOP nonce selection may evaluate up to 16 distinct five-word candidates.  That retry
trace is accounted separately below instead of being hidden in this accepted-edge shape.
-/
def activeChallengeOutputWordCounts : List Nat :=
  [activeDecsCoefficientWordCount,
    HegemonCrypto.SmallWoodTranscript.activePiopCoefficientWordCount,
    activeProfile.nbOpenedEvals,
    HegemonCrypto.SmallWoodTranscript.activeDecsFixedCandidateCount]

theorem active_challenge_output_word_counts_are_nonzero :
    ∀ count ∈ activeChallengeOutputWordCounts, 0 < count := by
  decide

/--
Minimum number of 512-bit SHA-512 counter-mode digest calls required to obtain a requested number
of 64-bit field words.  Goldilocks rejection sampling can only increase this count.
-/
def minimumSha512DigestCalls (outputWords : Nat) : Nat :=
  (outputWords + digestWordCount - 1) / digestWordCount

def activeChallengeMinimumSha512DigestCalls : List Nat :=
  activeChallengeOutputWordCounts.map minimumSha512DigestCalls

theorem active_challenge_minimum_sha512_digest_calls :
    activeChallengeMinimumSha512DigestCalls = [87, 11464, 1, 7] := by
  decide

theorem active_challenge_minimum_sha512_digest_call_total :
    activeChallengeMinimumSha512DigestCalls.sum = 11559 := by
  decide

/--
The verifier may test all 16 canonical PIOP nonces.  Each candidate asks for five field words and
therefore needs at least one SHA-512 block before rejection sampling.
-/
def activePiopNonceMaximumMinimumSha512DigestCalls : Nat :=
  piopNonceTrialBound *
    minimumSha512DigestCalls activeProfile.nbOpenedEvals

theorem active_piop_nonce_maximum_minimum_sha512_digest_calls :
    activePiopNonceMaximumMinimumSha512DigestCalls = 16 := by
  decide

/--
Minimum physical SHA-512 calls over the complete accepted challenge trace in the worst canonical
nonce case.  Rejection sampling can only increase this value.
-/
def activeChallengeWorstCaseMinimumSha512DigestCallTotal : Nat :=
  minimumSha512DigestCalls activeDecsCoefficientWordCount +
    minimumSha512DigestCalls
      HegemonCrypto.SmallWoodTranscript.activePiopCoefficientWordCount +
    activePiopNonceMaximumMinimumSha512DigestCalls +
    minimumSha512DigestCalls
      HegemonCrypto.SmallWoodTranscript.activeDecsFixedCandidateCount

theorem active_challenge_worst_case_minimum_sha512_digest_call_total :
    activeChallengeWorstCaseMinimumSha512DigestCallTotal = 11574 := by
  decide

/--
Remaining hypotheses for the generic multi-round measure-and-reprogram theorem.  Unlike the
historical format, V4 discharges `duplicateFreeInputs` directly.
-/
structure MeasureAndReprogramInstantiation
    (CommonFiniteChallengeRange
      InteractiveQuantumProofOfKnowledge
      EveryQuantumOracleQueryCounted : Prop) : Prop where
  duplicateFreeInputs : DeployedChallengeInputsAreDuplicateFree
  commonFiniteChallengeRange : CommonFiniteChallengeRange
  interactiveQuantumProofOfKnowledge : InteractiveQuantumProofOfKnowledge
  everyQuantumOracleQueryCounted : EveryQuantumOracleQueryCounted

theorem formatCompleteMeasureAndReprogramInstantiation
    {CommonFiniteChallengeRange
      InteractiveQuantumProofOfKnowledge
      EveryQuantumOracleQueryCounted : Prop}
    (commonFiniteChallengeRange : CommonFiniteChallengeRange)
    (interactiveQuantumProofOfKnowledge : InteractiveQuantumProofOfKnowledge)
    (everyQuantumOracleQueryCounted : EveryQuantumOracleQueryCounted) :
    MeasureAndReprogramInstantiation CommonFiniteChallengeRange
      InteractiveQuantumProofOfKnowledge EveryQuantumOracleQueryCounted :=
  { duplicateFreeInputs := deployed_challenge_inputs_are_duplicate_free,
    commonFiniteChallengeRange,
    interactiveQuantumProofOfKnowledge,
    everyQuantumOracleQueryCounted }

section ExactGenericTransferLoss

def activeTransferDenominator (queries : Nat) : Nat :=
  (2 * queries + activeFiatShamirRoundCount + 1) ^
    (2 * activeFiatShamirRoundCount)

def activeTransferNumerator : Nat :=
  Nat.factorial activeFiatShamirRoundCount

theorem active_transfer_numerator_is_24 : activeTransferNumerator = 24 := by
  decide

theorem active_transfer_denominator_exact (queries : Nat) :
    activeTransferDenominator queries = (2 * queries + 5) ^ 8 := by
  simp [activeTransferDenominator, activeFiatShamirRoundCount, allChallengeRounds]

/--
Generic four-round transfer applied only to the active interactive algebraic term.  Hash
collisions, concrete theorem constants, transcript refinement, and executable refinement are
separate terms.
-/
def optimisticGenericQromLoss (queries : Nat) : Rat :=
  ((activeTransferDenominator queries : Nat) : Rat) /
      activeTransferNumerator *
    ((aggregateErrorNumerator : Nat) : Rat) / aggregateErrorDenominator

def optimisticGenericQromLossNumerator (queries : Nat) : Nat :=
  activeTransferDenominator queries * aggregateErrorNumerator

def optimisticGenericQromLossDenominator : Nat :=
  activeTransferNumerator * aggregateErrorDenominator

def supportsOptimisticGenericQromBits (bits queries : Nat) : Prop :=
  2 ^ bits * optimisticGenericQromLossNumerator queries ≤
    optimisticGenericQromLossDenominator

theorem active_transfer_denominator_mono
    {smaller larger : Nat}
    (queryBound : smaller ≤ larger) :
    activeTransferDenominator smaller ≤ activeTransferDenominator larger := by
  rw [active_transfer_denominator_exact, active_transfer_denominator_exact]
  exact Nat.pow_le_pow_left
    (Nat.add_le_add_right (Nat.mul_le_mul_left 2 queryBound) 5) 8

theorem optimistic_generic_qrom_loss_numerator_mono
    {smaller larger : Nat}
    (queryBound : smaller ≤ larger) :
    optimisticGenericQromLossNumerator smaller ≤
      optimisticGenericQromLossNumerator larger := by
  exact Nat.mul_le_mul_right aggregateErrorNumerator
    (active_transfer_denominator_mono queryBound)

end ExactGenericTransferLoss

end HegemonCrypto.SmallWood.Qrom
