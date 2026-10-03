import HegemonCrypto.SmallWoodExtraction
import HegemonCrypto.SmallWoodTranscript
import Mathlib.Tactic.FieldSimp

set_option maxRecDepth 100000
set_option exponentiation.threshold 1024

/-!
# SmallWood classical random-oracle reduction boundary

The revised SmallWood/CAPSS theorem gives a classical-ROM straight-line extraction loss

`Q_RO^2 / 2^(2 lambda) + Q_RO * (epsilon1 + epsilon2 + epsilon3 + epsilon4)`

for the deployed zero-grinding profile.  This module connects that exact expression to the named
Hegemon extraction failures and proves its concrete consequences.  It does not prove the published
per-layer cryptographic estimates or promote the theorem to the QROM.
-/

namespace HegemonCrypto.SmallWood.Rom

open scoped BigOperators
open Hegemon.Transaction.SmallWoodNoGrindingSoundness
open HegemonCrypto.SmallWood.Extraction
open HegemonCrypto.SmallWoodTranscript
open HegemonCrypto.CanonicalBytes

section OracleDomains

/-- Domain used by the active V4 binary Merkle-node hash. -/
def compressionDomain : List Byte := merkleNodeDomain

/-- Exact byte preimage used by the active V4 binary Merkle-node hash. -/
def compressionPreimage (words : List Word) : List Byte :=
  sha512BlockPreimage compressionDomain words 0

theorem deployed_oracle_domains_are_distinct :
    xofDomain ≠ compressionDomain := by
  decide

/-- XOF/challenge inputs cannot alias binary-compression inputs before hashing. -/
theorem xof_and_compression_preimages_are_disjoint
    (xofWords compressionWords : List Word) :
    xofPreimage xofWords ≠ compressionPreimage compressionWords := by
  intro equality
  have prefixEquality := congrArg (List.take 8) equality
  norm_num [xofPreimage, xofDomain, compressionPreimage, compressionDomain,
    sha512BlockPreimage, piopInputDomain, merkleNodeDomain, level5DomainPrefix,
    encodeLE] at prefixEquality
  have firstByteEquality := prefixEquality 0 (by decide)
  norm_num at firstByteEquality

/-- One query to the variable-output XOF restriction. -/
abbrev XofRequest := List Word × Nat

/-- One query to the fixed-output binary compression restriction. -/
abbrev CompressionRequest := List Word

/-- Product form used by the paper's independent-oracle presentation. -/
abbrev IndependentOracles (Output : Type*) :=
  (XofRequest -> Output) × (CompressionRequest -> Output)

/-- Tagged form used to represent both restrictions of one domain-separated oracle. -/
abbrev TaggedOracle (Output : Type*) :=
  Sum XofRequest CompressionRequest -> Output

/-- Splitting a tagged oracle and recombining it loses no oracle behavior. -/
def independentTaggedEquiv (Output : Type*) :
    IndependentOracles Output ≃ TaggedOracle Output where
  toFun pair request :=
    match request with
    | .inl xofRequest => pair.1 xofRequest
    | .inr compressionRequest => pair.2 compressionRequest
  invFun oracle :=
    (fun request => oracle (.inl request), fun request => oracle (.inr request))
  left_inv pair := by
    apply Prod.ext
    · funext request
      rfl
    · funext request
      rfl
  right_inv oracle := by
    funext request
    cases request <;> rfl

theorem tagged_oracle_roundtrip
    {Output : Type*}
    (oracle : TaggedOracle Output) :
    independentTaggedEquiv Output
        ((independentTaggedEquiv Output).symm oracle) = oracle := by
  exact (independentTaggedEquiv Output).apply_symm_apply oracle

end OracleDomains

section ExactLoss

/-- `lambda = 256` in the collision term, matching the active 512-bit SHA-512 output. -/
def activeHashSecurityBits : Nat := 256

/-- Published random-oracle collision term. -/
def hashCollisionLoss (queries : Nat) : ℚ :=
  (queries ^ 2 : Nat) / (2 ^ (2 * activeHashSecurityBits) : Nat)

/-- Published four-term algebraic extraction loss after zero-grinding specialization. -/
def activeAlgebraicLoss (queries : Nat) : ℚ :=
  (queries : ℚ) *
    ((aggregateErrorNumerator : ℚ) / aggregateErrorDenominator)

/-- Exact active classical-ROM straight-line extraction bound. -/
def activeRomLoss (queries : Nat) : ℚ :=
  hashCollisionLoss queries + activeAlgebraicLoss queries

/-- Common numerator for exact natural-number comparison of the ROM bound. -/
def activeRomLossNumerator (queries : Nat) : Nat :=
  queries ^ 2 * aggregateErrorDenominator +
    queries * aggregateErrorNumerator * 2 ^ (2 * activeHashSecurityBits)

/-- Common denominator for exact natural-number comparison of the ROM bound. -/
def activeRomLossDenominator : Nat :=
  2 ^ (2 * activeHashSecurityBits) * aggregateErrorDenominator

/-- Exact bit-floor predicate for the complete classical-ROM expression. -/
def supportsActiveRomBits (bits queries : Nat) : Prop :=
  2 ^ bits * activeRomLossNumerator queries ≤ activeRomLossDenominator

private theorem two_fraction_common_denominator
    (leftNumerator leftDenominator rightNumerator rightDenominator : ℚ)
    (leftNonzero : leftDenominator ≠ 0)
    (rightNonzero : rightDenominator ≠ 0) :
    leftNumerator / leftDenominator + rightNumerator / rightDenominator =
      (leftNumerator * rightDenominator + rightNumerator * leftDenominator) /
        (leftDenominator * rightDenominator) := by
  field_simp

/-- The symbolic published expression equals the exact natural common fraction. -/
theorem active_rom_loss_eq_common_fraction (queries : Nat) :
    activeRomLoss queries =
      (activeRomLossNumerator queries : ℚ) / activeRomLossDenominator := by
  have hashDenominatorPositive : 0 < 2 ^ (2 * activeHashSecurityBits) := by positivity
  have aggregateDenominatorPositive : 0 < aggregateErrorDenominator := by decide
  have hashDenominatorNonzero :
      (2 ^ (2 * activeHashSecurityBits) : ℚ) ≠ 0 := by
    exact_mod_cast hashDenominatorPositive.ne'
  have aggregateDenominatorNonzero : (aggregateErrorDenominator : ℚ) ≠ 0 := by
    exact_mod_cast aggregateDenominatorPositive.ne'
  unfold activeRomLoss hashCollisionLoss activeAlgebraicLoss
  rw [show
    ((activeRomLossNumerator queries : Nat) : ℚ) =
      (queries : ℚ) ^ 2 * aggregateErrorDenominator +
        (queries : ℚ) * aggregateErrorNumerator *
          2 ^ (2 * activeHashSecurityBits) by
      simp [activeRomLossNumerator, Nat.cast_add, Nat.cast_mul, Nat.cast_pow]]
  rw [show
    ((activeRomLossDenominator : Nat) : ℚ) =
      2 ^ (2 * activeHashSecurityBits) * aggregateErrorDenominator by
      simp [activeRomLossDenominator, Nat.cast_mul, Nat.cast_pow]]
  convert two_fraction_common_denominator
      ((queries : ℚ) ^ 2) (2 ^ (2 * activeHashSecurityBits) : Nat)
      ((queries : ℚ) * aggregateErrorNumerator) aggregateErrorDenominator
      hashDenominatorNonzero aggregateDenominatorNonzero using 1
  all_goals simp [Nat.cast_pow, div_eq_mul_inv, mul_comm, mul_left_comm]

/-- Natural bit-floor checks and rational probability inequalities are equivalent. -/
theorem supports_active_rom_bits_iff (bits queries : Nat) :
    supportsActiveRomBits bits queries ↔
      activeRomLoss queries ≤ (1 : ℚ) / 2 ^ bits := by
  rw [active_rom_loss_eq_common_fraction]
  unfold supportsActiveRomBits
  have denominatorPositive : 0 < activeRomLossDenominator := by
    unfold activeRomLossDenominator
    exact Nat.mul_pos (by positivity) (by decide)
  have scalePositive : 0 < 2 ^ bits := by positivity
  rw [div_le_div_iff₀ (by exact_mod_cast denominatorPositive)
    (by exact_mod_cast scalePositive)]
  norm_cast
  simp [Nat.mul_comm]

/-- With one total oracle query, the exact active ROM expression clears 256 bits. -/
theorem active_rom_one_query_supports_256_bits :
    supportsActiveRomBits 256 1 := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  decide

/-- With two total oracle queries, the exact active ROM expression still clears 256 bits. -/
theorem active_rom_two_queries_support_256_bits :
    supportsActiveRomBits 256 2 := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  decide

/-- The exact common numerator is monotone in the total random-oracle query count. -/
theorem active_rom_loss_numerator_mono
    {smaller larger : Nat}
    (queryBound : smaller ≤ larger) :
    activeRomLossNumerator smaller ≤ activeRomLossNumerator larger := by
  have squareBound : smaller ^ 2 ≤ larger ^ 2 :=
    Nat.pow_le_pow_left queryBound 2
  have collisionBound :
      smaller ^ 2 * aggregateErrorDenominator ≤
        larger ^ 2 * aggregateErrorDenominator :=
    Nat.mul_le_mul_right aggregateErrorDenominator squareBound
  have algebraicBound :
      smaller * (aggregateErrorNumerator * 2 ^ (2 * activeHashSecurityBits)) ≤
        larger * (aggregateErrorNumerator * 2 ^ (2 * activeHashSecurityBits)) :=
    Nat.mul_le_mul_right
      (aggregateErrorNumerator * 2 ^ (2 * activeHashSecurityBits)) queryBound
  exact Nat.add_le_add collisionBound (by
    simpa [Nat.mul_assoc] using algebraicBound)

/-- A `2^32` classical-query budget retains a checked 230-bit floor. -/
theorem active_rom_2pow32_queries_support_230_bits :
    supportsActiveRomBits 230 (2 ^ 32) := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  set_option exponentiation.threshold 1024 in
    decide

theorem active_rom_2pow32_queries_do_not_support_231_bits :
    ¬supportsActiveRomBits 231 (2 ^ 32) := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  set_option exponentiation.threshold 1024 in
    decide

/-- A `2^64` classical-query budget retains a checked 198-bit floor. -/
theorem active_rom_2pow64_queries_support_198_bits :
    supportsActiveRomBits 198 (2 ^ 64) := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  set_option exponentiation.threshold 1024 in
    set_option maxRecDepth 100000 in
      decide

theorem active_rom_2pow64_queries_do_not_support_199_bits :
    ¬supportsActiveRomBits 199 (2 ^ 64) := by
  unfold supportsActiveRomBits activeRomLossNumerator activeRomLossDenominator
  set_option exponentiation.threshold 1024 in
    set_option maxRecDepth 100000 in
      decide

/-- Exact published layer loss, with executable refinement kept as an explicit external term. -/
def publishedRomLayerLoss
    (queries : Nat)
    (productionRefinementLoss : ℚ) : FailureLayer -> ℚ
  | .hashOrMerkleBinding => hashCollisionLoss queries
  | .decsDegreeEnforcement => (queries : ℚ) * publishedLayerLoss .decsDegreeEnforcement
  | .piopBatching => (queries : ℚ) * publishedLayerLoss .piopBatching
  | .piopEvaluation => (queries : ℚ) * publishedLayerLoss .piopEvaluation
  | .decsOpeningSampling => (queries : ℚ) * publishedLayerLoss .decsOpeningSampling
  | .productionOracleRefinement => productionRefinementLoss

/-- Summing all named layers yields the published ROM loss plus executable-refinement loss. -/
theorem published_rom_layer_loss_sum_exact
    (queries : Nat)
    (productionRefinementLoss : ℚ) :
    (∑ layer ∈ allFailureLayers,
      publishedRomLayerLoss queries productionRefinementLoss layer) =
        activeRomLoss queries + productionRefinementLoss := by
  calc
    (∑ layer ∈ allFailureLayers,
        publishedRomLayerLoss queries productionRefinementLoss layer) =
        hashCollisionLoss queries +
          (queries : ℚ) *
            (∑ layer ∈ publishedAlgebraicFailureLayers, publishedLayerLoss layer) +
          productionRefinementLoss := by
      simp [allFailureLayers, publishedAlgebraicFailureLayers, publishedRomLayerLoss]
      ring
    _ = hashCollisionLoss queries +
          (queries : ℚ) *
            ((aggregateErrorNumerator : ℚ) / aggregateErrorDenominator) +
          productionRefinementLoss := by
      rw [published_layer_loss_sum_exact]
    _ = activeRomLoss queries + productionRefinementLoss := by
      rfl

end ExactLoss

section AcceptanceComposition

variable {F Proof Commitment DegreeBound Batched Evaluated Opened : Type*}
variable [Field F]

/-- One classical-ROM experiment output relevant to proof acceptance and extraction. -/
structure Outcome (Proof : Type*) where
  statement : Statement
  proof : Proof

/-- Accepted proof for which no exact production-relation witness exists. -/
def acceptanceFailureEvent
    (extractor : LayeredExtractor (F := F) (Proof := Proof)
      (Commitment := Commitment) (DegreeBound := DegreeBound) (Batched := Batched)
      (Evaluated := Evaluated) (Opened := Opened)) : Set (Outcome Proof) :=
  { outcome |
    extractor.verifies outcome.statement outcome.proof = true ∧
      ¬∃ witness, (outcome.statement, witness) ∈ Relation }

/-- Pointwise staged extraction puts every acceptance failure in one named failure event. -/
theorem acceptance_failure_subset_named_failures
    (extractor : LayeredExtractor (F := F) (Proof := Proof)
      (Commitment := Commitment) (DegreeBound := DegreeBound) (Batched := Batched)
      (Evaluated := Evaluated) (Opened := Opened)) :
    acceptanceFailureEvent extractor ⊆
      anyFailureEvent (fun layer outcome =>
        extractor.failure layer outcome.statement outcome.proof) := by
  intro outcome acceptanceFailure
  rcases extractor.accepted_yields_relation_or_named_failure outcome.statement outcome.proof
      acceptanceFailure.1 with
    ⟨witness, relation⟩ | ⟨layer, layerMembership, layerFailure⟩
  · exact False.elim (acceptanceFailure.2 ⟨witness, relation⟩)
  · simp only [anyFailureEvent, failureEvent, Set.mem_iUnion, Set.mem_setOf_eq]
    exact ⟨layer, ⟨layerMembership, layerFailure⟩⟩

/-- Exact conditional classical-ROM knowledge-soundness composition theorem. -/
theorem acceptance_failure_probability_le_active_rom_loss
    (extractor : LayeredExtractor (F := F) (Proof := Proof)
      (Commitment := Commitment) (DegreeBound := DegreeBound) (Batched := Batched)
      (Evaluated := Evaluated) (Opened := Opened))
    (measure : EventProbability (Outcome Proof))
    (queries : Nat)
    (productionRefinementLoss : ℚ)
    (layerBound : ∀ layer ∈ allFailureLayers,
      measure.probability
          (failureEvent (fun selected outcome =>
            extractor.failure selected outcome.statement outcome.proof) layer) ≤
        publishedRomLayerLoss queries productionRefinementLoss layer) :
    measure.probability (acceptanceFailureEvent extractor) ≤
      activeRomLoss queries + productionRefinementLoss := by
  calc
    measure.probability (acceptanceFailureEvent extractor) ≤
        measure.probability
          (anyFailureEvent (fun layer outcome =>
            extractor.failure layer outcome.statement outcome.proof)) :=
      measure.monotone (acceptance_failure_subset_named_failures extractor)
    _ ≤ ∑ layer ∈ allFailureLayers,
        publishedRomLayerLoss queries productionRefinementLoss layer :=
      any_failure_probability_le_sum measure
        (fun layer outcome => extractor.failure layer outcome.statement outcome.proof)
        (publishedRomLayerLoss queries productionRefinementLoss) layerBound
    _ = activeRomLoss queries + productionRefinementLoss :=
      published_rom_layer_loss_sum_exact queries productionRefinementLoss

end AcceptanceComposition

end HegemonCrypto.SmallWood.Rom
