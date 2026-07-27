import HegemonCrypto.SmallWoodQrom
import Mathlib.Tactic.FieldSimp

/-!
# SmallWood BCS/QROM instantiation boundary

This module applies the security-accounting method used by mature STARK implementations: every
loss has a stable label, a proof status, and an exact contribution to one sum.  It then maps the
deployed SmallWood PACS-PIOP plus DECS/LVCS transcript to the round-by-round BCS theorem shape of
Chiesa, Manohar, and Spooner (TCC 2019).

The cited QROM theorem gives asymptotic losses `O(t^2 * k + t^3 / 2^kappa)` and an asymptotic query
overhead.  Its hidden constants are therefore inputs to this formal target, not invented numeric
facts.  The active-parameter calculations below use unit constants only as an explicitly
optimistic diagnostic.  They are not a production security theorem.

The exact transcript map closes.  Direct adaptive BCS applicability does not: the deployed first
DECS verifier challenge is independent of the statement, and the package still lacks a
round-by-round knowledge extractor and concrete theorem constants.  Those failures stay visible
as typed hypotheses and assurance obligations.
-/

namespace HegemonCrypto.SmallWood.BcsQrom

open scoped BigOperators
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.SmallWood.Qrom
open HegemonCrypto.SmallWood.Extraction
open HegemonCrypto.SmallWood.Interactive
open Hegemon.Transaction.SmallWoodNoGrindingSoundness

section DeployedTranscript

/-- The oracle returns exactly the requested number of field words. -/
def LengthRespectingOracle (oracle : Oracle) : Prop :=
  ∀ input outputWords, (oracle input outputWords).length = outputWords

/-- Exact four challenge inputs reconstructed from one deployed transcript. -/
def deployedChallengeInputs
    (oracle : Oracle)
    (transcript : Transcript)
    (decsOpeningNonce : Word) : ChallengeInputs :=
  { decsCommitmentDigest := merkleRootDigest oracle transcript.commitment,
    piopCommitmentDigest :=
      hashFpp oracle transcript.commitment transcript.statementBindingWords,
    piopOpeningNonce := transcript.openingNonce,
    piopTranscriptDigest := transcript.piopHash oracle,
    decsOpeningNonce := decsOpeningNonce,
    decsTranscriptDigest := transcript.decsHash oracle }

/-- A length-respecting random oracle gives the exact deployed digest shape. -/
theorem deployed_challenge_inputs_well_formed
    (oracle : Oracle)
    (lengthRespecting : LengthRespectingOracle oracle)
    (transcript : Transcript)
    (decsOpeningNonce : Word) :
    (deployedChallengeInputs oracle transcript decsOpeningNonce).WellFormed := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact lengthRespecting _ digestWordCount
  · exact lengthRespecting _ digestWordCount
  · exact lengthRespecting _ digestWordCount
  · exact lengthRespecting _ digestWordCount

/-- The reconstructed BCS view has challenge-input lengths `4, 4, 5, 5`. -/
theorem deployed_bcs_challenge_input_lengths
    (oracle : Oracle)
    (lengthRespecting : LengthRespectingOracle oracle)
    (transcript : Transcript)
    (decsOpeningNonce : Word) :
    ((deployedChallengeInputs oracle transcript decsOpeningNonce).words.map List.length) =
      [4, 4, 5, 5] := by
  exact well_formed_challenge_input_lengths _
    (deployed_challenge_inputs_well_formed oracle lengthRespecting transcript decsOpeningNonce)

/-- Number of rows in the committed DECS evaluation oracle. -/
def activeCommittedOracleLength : Nat := 32768

/-- Number of DECS leaves opened by the active no-grinding profile. -/
def activeBcsQueryCount : Nat := activeParameters.decsOpenedEvaluations

/-- Binary Merkle depth for the active committed evaluation oracle. -/
def activeMerkleDepth : Nat := 15

theorem active_committed_oracle_length_is_binary_depth :
    activeCommittedOracleLength = 2 ^ activeMerkleDepth := by
  decide

theorem active_bcs_query_count_is_24 : activeBcsQueryCount = 24 := by
  rfl

theorem active_merkle_depth_is_15 : activeMerkleDepth = 15 := by
  rfl

/-- Raw `q * log_2(ell)` unit used by the published asymptotic extractor-query overhead. -/
def activeQueryDepthProduct : Nat := activeBcsQueryCount * activeMerkleDepth

theorem active_query_depth_product_is_360 : activeQueryDepthProduct = 360 := by
  decide

/-- The first DECS verifier challenge hashes only the commitment digest. -/
def firstDecsChallengeInput
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (_statementBindingWords : List Word) : List Word :=
  merkleRootDigest oracle commitment

/-- The deployed first challenge is unchanged when the statement changes. -/
theorem deployed_first_decs_challenge_is_statement_independent
    (oracle : Oracle)
    (commitment : CommitmentRound)
    (leftStatement rightStatement : List Word) :
    firstDecsChallengeInput oracle commitment leftStatement =
      firstDecsChallengeInput oracle commitment rightStatement := by
  rfl

/-- Adaptive BCS needs the first challenge query to bind the selected instance. -/
def AdaptiveFirstChallengeInstanceBinding : Prop :=
  ∀ oracle commitment leftStatement rightStatement,
    firstDecsChallengeInput oracle commitment leftStatement =
        firstDecsChallengeInput oracle commitment rightStatement →
      leftStatement = rightStatement

private def zeroOracle : Oracle :=
  fun _ outputWords => List.replicate outputWords 0

private def emptyCommitment : CommitmentRound :=
  { saltWords := [], merkleRootWords := [], decPolynomials := [] }

/-- The deployed transcript cannot directly meet adaptive first-round instance binding. -/
theorem deployed_first_challenge_does_not_bind_adaptive_statement :
    ¬AdaptiveFirstChallengeInstanceBinding := by
  intro claimed
  have impossible := claimed zeroOracle emptyCommitment ([] : List Word) [0]
    (deployed_first_decs_challenge_is_statement_independent
      zeroOracle emptyCommitment [] [0])
  simp at impossible

/-- Canonical nonce selection makes the PIOP opening challenge prefix-determined. -/
theorem canonical_opening_nonce_is_determined_by_piop_prefix
    {oracle : Oracle}
    {parameters : Parameters}
    {packingPoints piopHash : List Word}
    {left right : Word}
    (leftCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash left)
    (rightCanonical :
      CanonicalOpeningNonce oracle parameters packingPoints piopHash right) :
    left = right := by
  exact canonical_opening_nonce_unique leftCanonical rightCanonical

end DeployedTranscript

section RoundByRoundKnowledge

/-!
`RoundByRoundKnowledgeTarget` is the Hegemon specialization of the CMS RBR knowledge condition.
At a verifier-turn prefix whose state is still false, crossing the knowledge-error threshold must
yield an exact witness for the production relation.  Defining the interface is not evidence that
the deployed DECS/LVCS protocol inhabits it.
-/

structure RoundByRoundKnowledgeTarget (Prefix : Type*) where
  knowledgeError : Rat
  state : Prefix -> Bool
  verifierTurn : Prefix -> Prop
  statement : Prefix -> Statement
  initialPrefix : Statement -> Prefix
  proverExtension : Prefix -> Prefix -> Prop
  terminal : Prefix -> Prop
  accepts : Prefix -> Bool
  nextGoodProbability : Prefix -> Rat
  extract : Prefix -> Option Witness
  knowledgeError_nonnegative : 0 ≤ knowledgeError
  invalidInitialStateIsDoomed : ∀ selectedStatement,
    (¬∃ witness, (selectedStatement, witness) ∈ Relation) ->
      state (initialPrefix selectedStatement) = false
  doomedStateSurvivesProverMessage : ∀ before after,
    proverExtension before after ->
    state before = false ->
      state after = false
  doomedTerminalTranscriptRejects : ∀ transcriptPrefix,
    terminal transcriptPrefix ->
    state transcriptPrefix = false ->
      accepts transcriptPrefix = false
  nextGoodProbability_nonnegative : ∀ transcriptPrefix,
    0 ≤ nextGoodProbability transcriptPrefix
  nextGoodProbability_at_most_one : ∀ transcriptPrefix,
    nextGoodProbability transcriptPrefix ≤ 1
  extractAboveError : ∀ transcriptPrefix,
    verifierTurn transcriptPrefix →
    state transcriptPrefix = false →
    knowledgeError < nextGoodProbability transcriptPrefix →
      ∃ witness,
        extract transcriptPrefix = some witness ∧
          (statement transcriptPrefix, witness) ∈ Relation

/-- The RBR target extracts the exact production relation, not a surrogate acceptance bit. -/
theorem RoundByRoundKnowledgeTarget.extracts_exact_relation
    {Prefix : Type*}
    (target : RoundByRoundKnowledgeTarget Prefix)
    (transcriptPrefix : Prefix)
    (verifierTurn : target.verifierTurn transcriptPrefix)
    (doomed : target.state transcriptPrefix = false)
    (aboveError : target.knowledgeError < target.nextGoodProbability transcriptPrefix) :
    ∃ witness,
      target.extract transcriptPrefix = some witness ∧
        (target.statement transcriptPrefix, witness) ∈ Relation := by
  exact target.extractAboveError transcriptPrefix verifierTurn doomed aboveError

/-- Hypotheses needed for a direct adaptive BCS/QROM production instantiation. -/
structure DirectAdaptiveInstantiation
    (Prefix : Type*)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop) : Prop where
  firstChallengeBindsStatement : AdaptiveFirstChallengeInstanceBinding
  roundByRoundKnowledge : Nonempty (RoundByRoundKnowledgeTarget Prefix)
  commitmentBindingReduction : CommitmentBinding
  concreteCmsTransfer : ConcreteCmsTransfer
  nativeVerifierRefinement : NativeVerifierRefinement

/-- Fixed-statement BCS target after removing only the adaptive first-instance requirement. -/
structure FixedStatementInstantiation
    (Prefix : Type*)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop) : Prop where
  roundByRoundKnowledge : Nonempty (RoundByRoundKnowledgeTarget Prefix)
  commitmentBindingReduction : CommitmentBinding
  concreteCmsTransfer : ConcreteCmsTransfer
  nativeVerifierRefinement : NativeVerifierRefinement

/-- No direct adaptive instantiation exists for the current first-round transcript. -/
theorem no_direct_adaptive_bcs_qrom_instantiation
    (Prefix : Type*)
    (CommitmentBinding ConcreteCmsTransfer NativeVerifierRefinement : Prop) :
    ¬DirectAdaptiveInstantiation Prefix CommitmentBinding ConcreteCmsTransfer
      NativeVerifierRefinement := by
  intro instantiation
  exact deployed_first_challenge_does_not_bind_adaptive_statement
    instantiation.firstChallengeBindsStatement

end RoundByRoundKnowledge

section SecurityLedger

/-- Stable labels prevent a security report from silently dropping a term. -/
inductive LossLabel where
  | rbrKnowledgeAmplification
  | qromReprogramming
  | commitmentBinding
  | randomOracleInstantiation
  | transcriptCompatibility
  | nativeVerifierRefinement
deriving DecidableEq, Repr

/-- Whether a ledger entry is proved here, a required hypothesis, or only asymptotic in its source. -/
inductive EvidenceStatus where
  | proved
  | hypothesis
  | asymptotic
deriving DecidableEq, Repr

structure LossEntry where
  label : LossLabel
  status : EvidenceStatus
  value : Rat
deriving DecidableEq, Repr

/-- Explicit constants replacing the two hidden constants in the published `O` expression. -/
structure CmsConstants where
  rbrMultiplier : Nat
  oracleMultiplier : Nat
deriving DecidableEq, Repr

/-- External losses not discharged by the ideal-oracle CMS theorem. -/
structure ExternalLosses where
  commitmentBinding : Rat
  randomOracleInstantiation : Rat
  transcriptCompatibility : Rat
  nativeVerifierRefinement : Rat
deriving DecidableEq, Repr

def cmsRbrLoss
    (constants : CmsConstants)
    (queries : Nat)
    (rbrKnowledgeError : Rat) : Rat :=
  (constants.rbrMultiplier * queries ^ 2 : Nat) * rbrKnowledgeError

def cmsOracleLoss
    (constants : CmsConstants)
    (queries oracleBits : Nat) : Rat :=
  (constants.oracleMultiplier * queries ^ 3 : Nat) / (2 ^ oracleBits : Nat)

/-- Complete labeled BCS/QROM accounting surface. -/
def securityLedger
    (constants : CmsConstants)
    (queries oracleBits : Nat)
    (rbrKnowledgeError : Rat)
    (external : ExternalLosses) : List LossEntry :=
  [ { label := .rbrKnowledgeAmplification,
      status := .hypothesis,
      value := cmsRbrLoss constants queries rbrKnowledgeError },
    { label := .qromReprogramming,
      status := .asymptotic,
      value := cmsOracleLoss constants queries oracleBits },
    { label := .commitmentBinding,
      status := .hypothesis,
      value := external.commitmentBinding },
    { label := .randomOracleInstantiation,
      status := .hypothesis,
      value := external.randomOracleInstantiation },
    { label := .transcriptCompatibility,
      status := .hypothesis,
      value := external.transcriptCompatibility },
    { label := .nativeVerifierRefinement,
      status := .hypothesis,
      value := external.nativeVerifierRefinement } ]

def ledgerTotal (entries : List LossEntry) : Rat :=
  (entries.map LossEntry.value).sum

/-- The report contains each named attack surface exactly once and in a fixed order. -/
theorem security_ledger_labels_are_complete
    (constants : CmsConstants)
    (queries oracleBits : Nat)
    (rbrKnowledgeError : Rat)
    (external : ExternalLosses) :
    (securityLedger constants queries oracleBits rbrKnowledgeError external).map
        LossEntry.label =
      [ .rbrKnowledgeAmplification,
        .qromReprogramming,
        .commitmentBinding,
        .randomOracleInstantiation,
        .transcriptCompatibility,
        .nativeVerifierRefinement ] := by
  rfl

/-- The ledger total is exactly the two CMS-shape terms plus every external loss. -/
theorem security_ledger_total_exact
    (constants : CmsConstants)
    (queries oracleBits : Nat)
    (rbrKnowledgeError : Rat)
    (external : ExternalLosses) :
    ledgerTotal (securityLedger constants queries oracleBits rbrKnowledgeError external) =
      cmsRbrLoss constants queries rbrKnowledgeError +
        cmsOracleLoss constants queries oracleBits +
        external.commitmentBinding +
        external.randomOracleInstantiation +
        external.transcriptCompatibility +
        external.nativeVerifierRefinement := by
  simp [ledgerTotal, securityLedger]
  ring

/-- The source theorem provides an asymptotic term, not a reviewed concrete multiplier. -/
def publishedCmsQromStatus : EvidenceStatus := .asymptotic

theorem published_cms_qrom_bound_is_not_a_concrete_proof_entry :
    publishedCmsQromStatus ≠ .proved := by
  decide

end SecurityLedger

section ConcreteDiagnostics

/-- Unit constants are an optimistic diagnostic, not constants claimed by the CMS theorem. -/
def unitCmsConstants : CmsConstants :=
  { rbrMultiplier := 1, oracleMultiplier := 1 }

/-- Unit-constant CMS shape using the exact active four-layer algebraic error as an optimistic RBR error. -/
def activeUnitBcsLoss (queries : Nat) : Rat :=
  (queries ^ 2 : Nat) *
      ((aggregateErrorNumerator : Rat) / aggregateErrorDenominator) +
    (queries ^ 3 : Nat) / (2 ^ 256 : Nat)

def activeUnitBcsLossNumerator (queries : Nat) : Nat :=
  queries ^ 2 * aggregateErrorNumerator * 2 ^ 256 +
    queries ^ 3 * aggregateErrorDenominator

def activeUnitBcsLossDenominator : Nat :=
  aggregateErrorDenominator * 2 ^ 256

def supportsActiveUnitBcsBits (bits queries : Nat) : Prop :=
  2 ^ bits * activeUnitBcsLossNumerator queries <= activeUnitBcsLossDenominator

/-- The symbolic optimistic loss equals its exact natural common fraction. -/
theorem active_unit_bcs_loss_eq_common_fraction (queries : Nat) :
    activeUnitBcsLoss queries =
      (activeUnitBcsLossNumerator queries : Rat) / activeUnitBcsLossDenominator := by
  have aggregatePositive : 0 < aggregateErrorDenominator := by decide
  have oraclePositive : 0 < (2 ^ 256 : Nat) := by positivity
  have aggregateNonzero : (aggregateErrorDenominator : Rat) ≠ 0 := by
    exact_mod_cast aggregatePositive.ne'
  have oracleNonzero : ((2 ^ 256 : Nat) : Rat) ≠ 0 := by
    exact_mod_cast oraclePositive.ne'
  unfold activeUnitBcsLoss activeUnitBcsLossNumerator activeUnitBcsLossDenominator
  push_cast
  field_simp

/-- Exact natural checks are equivalent to rational bit-floor inequalities. -/
theorem supports_active_unit_bcs_bits_iff (bits queries : Nat) :
    supportsActiveUnitBcsBits bits queries ↔
      activeUnitBcsLoss queries ≤ (1 : Rat) / 2 ^ bits := by
  rw [active_unit_bcs_loss_eq_common_fraction]
  unfold supportsActiveUnitBcsBits
  have denominatorPositive : 0 < activeUnitBcsLossDenominator := by
    exact Nat.mul_pos (by decide) (by positivity)
  have scalePositive : 0 < 2 ^ bits := by positivity
  rw [div_le_div_iff₀ (by exact_mod_cast denominatorPositive)
    (by exact_mod_cast scalePositive)]
  norm_cast
  simp [Nat.mul_comm]

/-- Even the unit-constant diagnostic clears 128 bits only at the one-query edge. -/
theorem active_unit_bcs_one_query_supports_128_bits :
    supportsActiveUnitBcsBits 128 1 := by
  unfold supportsActiveUnitBcsBits activeUnitBcsLossNumerator activeUnitBcsLossDenominator
  decide

theorem active_unit_bcs_two_queries_do_not_support_128_bits :
    ¬supportsActiveUnitBcsBits 128 2 := by
  unfold supportsActiveUnitBcsBits activeUnitBcsLossNumerator activeUnitBcsLossDenominator
  decide

/-- At `2^32` quantum queries, the optimistic active ledger retains 64 bits. -/
theorem active_unit_bcs_2pow32_queries_support_64_bits :
    supportsActiveUnitBcsBits 64 (2 ^ 32) := by
  unfold supportsActiveUnitBcsBits activeUnitBcsLossNumerator activeUnitBcsLossDenominator
  decide

theorem active_unit_bcs_2pow32_queries_do_not_support_65_bits :
    ¬supportsActiveUnitBcsBits 65 (2 ^ 32) := by
  unfold supportsActiveUnitBcsBits activeUnitBcsLossNumerator activeUnitBcsLossDenominator
  decide

/-!
The following power-of-two model isolates parameter design from the exact active fraction.  It
uses unit theorem constants and zero external losses.  Its first term is `t^2 / 2^b` and its second
is `t^3 / 2^kappa`.
-/

def powerEnvelopeNumerator (queries baseBits oracleBits : Nat) : Nat :=
  queries ^ 2 * 2 ^ oracleBits + queries ^ 3 * 2 ^ baseBits

def powerEnvelopeDenominator (baseBits oracleBits : Nat) : Nat :=
  2 ^ (baseBits + oracleBits)

def supportsPowerEnvelopeBits
    (targetBits queries baseBits oracleBits : Nat) : Prop :=
  2 ^ targetBits * powerEnvelopeNumerator queries baseBits oracleBits <=
    powerEnvelopeDenominator baseBits oracleBits

/-- A 192-bit RBR base margin is insufficient at `t = 2^32`, even with a 256-bit oracle. -/
theorem unit_bcs_2pow32_queries_192_base_bits_do_not_support_128 :
    ¬supportsPowerEnvelopeBits 128 (2 ^ 32) 192 256 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 512 in
    decide

/-- One more RBR bit suffices in the optimistic unit-constant model at `t = 2^32`. -/
theorem unit_bcs_2pow32_queries_193_base_bits_support_128 :
    supportsPowerEnvelopeBits 128 (2 ^ 32) 193 256 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 512 in
    decide

/-- The active 128/256 margins are far below 128 bits at `t = 2^64`. -/
theorem unit_bcs_2pow64_queries_active_margins_do_not_support_128 :
    ¬supportsPowerEnvelopeBits 128 (2 ^ 64) 128 256 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 512 in
    decide

/-- A 256-bit RBR margin is still insufficient when the oracle margin is 321 bits. -/
theorem unit_bcs_2pow64_queries_256_base_321_oracle_bits_do_not_support_128 :
    ¬supportsPowerEnvelopeBits 128 (2 ^ 64) 256 321 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 1024 in
    decide

/-- A 320-bit oracle margin is still insufficient when the RBR margin is 257 bits. -/
theorem unit_bcs_2pow64_queries_257_base_320_oracle_bits_do_not_support_128 :
    ¬supportsPowerEnvelopeBits 128 (2 ^ 64) 257 320 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 1024 in
    decide

/-- Unit constants at `t = 2^64` require at least the checked 257/321 split shown here. -/
theorem unit_bcs_2pow64_queries_257_base_321_oracle_bits_support_128 :
    supportsPowerEnvelopeBits 128 (2 ^ 64) 257 321 := by
  unfold supportsPowerEnvelopeBits powerEnvelopeNumerator powerEnvelopeDenominator
  set_option exponentiation.threshold 1024 in
    set_option maxRecDepth 100000 in
      decide

end ConcreteDiagnostics

end HegemonCrypto.SmallWood.BcsQrom
