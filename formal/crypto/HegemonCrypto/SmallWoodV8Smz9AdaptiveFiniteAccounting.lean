import HegemonCrypto.SmallWoodHeterogeneousCmsQrom
import HegemonCrypto.SmallWoodV8Smz9LogicalOracle
import HegemonCrypto.SmallWoodV8Smz9QromAccounting
import HegemonCrypto.SmallWoodV8Smz9ZeroKnowledge
import HegemonCrypto.UniformSubsetSampling
import Mathlib.Algebra.MvPolynomial.SchwartzZippel
import Mathlib.Data.Fintype.CardEmbedding
import Mathlib.Data.Nat.Log
import Mathlib.FieldTheory.Finite.Basic

/-!
# Full-admissibility finite-history accounting for V8/SMZ9

The historical SMZ9 arithmetic models the six PIOP openings as a uniform ordered tuple that is
distinct and outside the 64-point packing domain.  The executable Rust nonce selector imposes two
additional predicates: the degree-six linear-correction numerator must be nonzero, and every exact
PCS-unstack block must have full rank.  This file proves the corresponding ideal finite-field
sampling theorem, but does not identify SHA-512-derived executable openings with uniform tuples.

Instead, it records a conservative counting bound.  There are `(p - 64)_6` distinct/outside
ordered tuples.  The correction numerator removes at most `6 * p^5` tuples.  The PCS row factors
are `r^64 - 1`, `r^35 - 1`, and `r^63 - 1`; their Goldilocks root union has 70 values, of which
`1` and `8` are already in the packing domain, so the PCS predicate removes at most
`6 * 68 * p^5` more tuples.  The accepted-tuple denominator is therefore bounded below by
`(p - 64)_6 - 414 * p^5`.  Exhaustion of all sixteen nonce trials is bounded by
`813^16 / p^16`, where `813 = 6 * 64 + choose(6, 2) + 6 + 6 * 68` includes domain hits,
collisions, the degree-six zero event, and every additional PCS root.

The exact canonical public-argument carrier is 128,297 bytes and its complete `PendingAction`
record is 128,522 bytes, so the 64 MiB block-action byte cap admits 522 records before block
overhead.  Consensus independently caps accepted proofs at 512 per block, and only that smaller
consensus count enters the finite-history loss terms below.

The resulting exact integer ledger proves finite arithmetic statements only.  Concrete SHA-512
Fiat-Shamir/QROM, Poseidon2, canonical-byte-to-opening refinement, adaptive whole-view zero
knowledge, one protocol-lifetime global query budget, and independent review remain separate
constructor-free premises.  The 4,096-block interval is not a cryptographic reset.
The fixed-history SHA/CMS diagnostic uses the shared exposure count `E = Q + H` for the modeled
canonical accepted-proof interactions; the Poseidon2 terms continue to use adversarial `Q`.
Consensus does not bound wallet-generated, rejected, orphaned, side-fork, or repeated-verifier
views, so the generic lifetime interface below keeps their total `T` explicit.  The fixed
`2,097,152` specialization is not a deployed upper bound without a separate global exposure
binding.
-/

namespace HegemonCrypto
namespace SmallWood
namespace V8Smz9AdaptiveFiniteAccounting

open scoped BigOperators
open MvPolynomial

set_option maxHeartbeats 0
set_option maxRecDepth 100000
set_option exponentiation.threshold 4096

noncomputable section

def globalSha512QromLifetimeReceiptId : String :=
  "hegemon.formal.smallwood-smz9.global-sha512-qrom-lifetime.v1"

theorem exact_global_qrom_lifetime_receipt_id :
    globalSha512QromLifetimeReceiptId =
      "hegemon.formal.smallwood-smz9.global-sha512-qrom-lifetime.v1" := by
  rfl

namespace Historical

abbrev goldilocksOrder : Nat := V8Smz9QromAccounting.goldilocksOrder
abbrev packingFactor : Nat := V8Smz9QromAccounting.packingFactor
abbrev piopOpenings : Nat := V8Smz9QromAccounting.piopOpenings
abbrev decsDomainSize : Nat := V8Smz9QromAccounting.decsDomainSize
abbrev decsOpenings : Nat := V8Smz9QromAccounting.decsOpenings
abbrev transcriptHashBits : Nat := V8Smz9QromAccounting.transcriptHashBits
abbrev analysisGlobalQueryBudget : Nat := V8Smz9QromAccounting.analysisGlobalQueryBudget
abbrev analysisHistoryProofInteractions : Nat :=
  V8Smz9QromAccounting.analysisHistoryProofInteractions
abbrev analysisTotalSha512OracleExposures : Nat :=
  V8Smz9QromAccounting.totalSha512OracleExposures analysisGlobalQueryBudget
abbrev fallingProduct := V8Smz9QromAccounting.fallingProduct

end Historical

open Historical

structure ExactNatRatio where
  numerator : Nat
  denominator : Nat
deriving DecidableEq, Repr

namespace ExactNatRatio

def add (left right : ExactNatRatio) : ExactNatRatio where
  numerator := left.numerator * right.denominator + right.numerator * left.denominator
  denominator := left.denominator * right.denominator

def scale (ratio : ExactNatRatio) (factor : Nat) : ExactNatRatio where
  numerator := factor * ratio.numerator
  denominator := ratio.denominator

abbrev supportsBits (ratio : ExactNatRatio) (bits : Nat) : Prop :=
  2 ^ bits * ratio.numerator ≤ ratio.denominator

/-- Strict `2^-bits` target used by the adaptive-programming ceilings below. -/
abbrev strictlyBelowBits (ratio : ExactNatRatio) (bits : Nat) : Prop :=
  ratio.numerator * 2 ^ bits < ratio.denominator

def maximumUnionCountAtBits (ratio : ExactNatRatio) (bits : Nat) : Nat :=
  ratio.denominator / (2 ^ bits * ratio.numerator)

end ExactNatRatio

/-! ## Generic proof-exposure accounting

The finite-history value `2,097,152` is one arithmetic specialization of the proof-view exposure
variable `T`.  In a lifetime claim, `T` counts every honest proof view generated or exposed to the
adversary, including wallet-generated, rejected, orphaned, side-fork, and repeated-verifier views;
it is not the canonical accepted-action count.  For `T` such observed views, the conservative eager
schedule exposes all
`2^24 - 1` DECS tree programs and the one final-PIOP program per proof.  SHA-512 therefore sees
`E(T) = 2^64 + 2^24 T` total adversarial-plus-honest exposures.  The exponent below is a strict
power-of-two ceiling: even when `E(T)` itself is a power of two it returns one more than its binary
logarithm, so `E(T) < 2 ^ e(T)` always holds.

These definitions are arithmetic for a proposed GHHM-shaped reduction.  Their use for the Rust
transcript remains conditional on the constructor-free applicability/refinement premises recorded
in the QROM and logical-oracle modules.
-/

def eagerTreeProgramsPerProof : Nat := 2 * decsDomainSize - 1
def finalPiopProgramsPerProof : Nat := 1
def eagerAllProgramsPerProof : Nat :=
  eagerTreeProgramsPerProof + finalPiopProgramsPerProof

def honestProgramExposures (observedHonestProofViews : Nat) : Nat :=
  eagerAllProgramsPerProof * observedHonestProofViews

def totalOracleExposures (observedHonestProofViews : Nat) : Nat :=
  analysisGlobalQueryBudget + honestProgramExposures observedHonestProofViews

/-- Strict bit-length exponent `e(T) = floor(log2(E(T))) + 1`. -/
def totalOracleExposureExponent (observedHonestProofViews : Nat) : Nat :=
  Nat.log2 (totalOracleExposures observedHonestProofViews) + 1

theorem total_oracle_exposures_lt_power_ceiling (observedHonestProofViews : Nat) :
    totalOracleExposures observedHonestProofViews <
      2 ^ totalOracleExposureExponent observedHonestProofViews := by
  unfold totalOracleExposureExponent
  rw [Nat.log2_eq_log_two]
  simpa [Nat.succ_eq_add_one] using
    (Nat.lt_pow_succ_log_self (by decide : 1 < 2)
      (totalOracleExposures observedHonestProofViews))

/-- The GHHM-shaped ratio is applicable only when the strict exposure exponent fits in the
conditional-min-entropy budget. -/
abbrev genericAdaptiveProgrammingApplicable
    (entropyBits observedHonestProofViews : Nat) : Prop :=
  totalOracleExposureExponent observedHonestProofViews ≤ entropyBits

def genericAdaptiveProgrammingRatio
    (programsPerProof entropyBits observedHonestProofViews : Nat) : ExactNatRatio where
  numerator := 3 * programsPerProof * observedHonestProofViews
  denominator :=
    2 ^ (1 + (entropyBits - totalOracleExposureExponent observedHonestProofViews) / 2)

/-- All `2^24` eager program points charged at 512 conditional-entropy bits. -/
def q20Eager512ProgrammingRatio (observedHonestProofViews : Nat) : ExactNatRatio :=
  genericAdaptiveProgrammingRatio eagerAllProgramsPerProof 512 observedHonestProofViews

/-- The `2^24 - 1` tree points charged at 448 bits and the final PIOP point at 512 bits. -/
def q20Eager448ProgrammingRatio (observedHonestProofViews : Nat) : ExactNatRatio :=
  (genericAdaptiveProgrammingRatio eagerTreeProgramsPerProof 448 observedHonestProofViews).add
    (genericAdaptiveProgrammingRatio finalPiopProgramsPerProof 512 observedHonestProofViews)

def q20Eager512MaximumProofInteractionsAt128 : Nat :=
  1537228672809129301

def q20Eager448MaximumProofInteractionsAt128 : Nat :=
  366503897770

/-- Semantic aliases: these ceilings count observed/generated honest proof views, not accepted
consensus actions. -/
abbrev q20Eager512MaximumObservedHonestProofViewsAt128 : Nat :=
  q20Eager512MaximumProofInteractionsAt128
abbrev q20Eager448MaximumObservedHonestProofViewsAt128 : Nat :=
  q20Eager448MaximumProofInteractionsAt128

theorem exact_generic_eager_program_inventory :
    eagerTreeProgramsPerProof = 16777215 ∧
      finalPiopProgramsPerProof = 1 ∧
      eagerAllProgramsPerProof = 16777216 := by
  norm_num [eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
    eagerAllProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

/--
Exact arithmetic at the canonical `512 * 4096` accepted-proof count.  This is a specialization of
the generic functions, not evidence that all honest programmed proof views over a deployed
lifetime are capped by the consensus accepted-action count.
-/
theorem exact_fixed_history_generic_oracle_exposure :
    honestProgramExposures analysisHistoryProofInteractions = 35184372088832 ∧
      totalOracleExposures analysisHistoryProofInteractions = 18446779258081640448 ∧
      totalOracleExposureExponent analysisHistoryProofInteractions = 65 := by
  change
    honestProgramExposures V8Smz9QromAccounting.analysisHistoryProofInteractions =
        35184372088832 ∧
      totalOracleExposures V8Smz9QromAccounting.analysisHistoryProofInteractions =
        18446779258081640448 ∧
      totalOracleExposureExponent V8Smz9QromAccounting.analysisHistoryProofInteractions = 65
  rw [V8Smz9QromAccounting.exact_analysis_history_proof_interactions]
  have exposureLog :
      Nat.log 2 (totalOracleExposures 2097152) = 64 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        eagerAllProgramsPerProof, eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
        Historical.decsDomainSize, V8Smz9QromAccounting.decsDomainSize,
        Historical.analysisGlobalQueryBudget, V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        eagerAllProgramsPerProof, eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
        Historical.decsDomainSize, V8Smz9QromAccounting.decsDomainSize,
        Historical.analysisGlobalQueryBudget, V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  constructor
  · norm_num [honestProgramExposures, eagerAllProgramsPerProof,
      eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
      V8Smz9QromAccounting.decsDomainSize]
  constructor
  · norm_num [totalOracleExposures, honestProgramExposures,
      eagerAllProgramsPerProof, eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
      Historical.decsDomainSize, V8Smz9QromAccounting.decsDomainSize,
      Historical.analysisGlobalQueryBudget, V8Smz9QromAccounting.analysisGlobalQueryBudget,
      V8Smz9QromAccounting.analysisGlobalQueryExponent]
  · unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, exposureLog]

theorem exact_q20_eager_512_exposure_exponents :
    totalOracleExposureExponent q20Eager512MaximumProofInteractionsAt128 = 85 ∧
      totalOracleExposureExponent (q20Eager512MaximumProofInteractionsAt128 + 1) = 85 := by
  have maximumLog :
      Nat.log 2 (totalOracleExposures q20Eager512MaximumProofInteractionsAt128) = 84 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  have successorLog :
      Nat.log 2 (totalOracleExposures (q20Eager512MaximumProofInteractionsAt128 + 1)) = 84 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  constructor
  · unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, maximumLog]
  · unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, successorLog]

theorem q20_eager_512_entropy_is_applicable_through_successor :
    genericAdaptiveProgrammingApplicable 512 q20Eager512MaximumProofInteractionsAt128 ∧
      genericAdaptiveProgrammingApplicable 512
        (q20Eager512MaximumProofInteractionsAt128 + 1) := by
  change
    totalOracleExposureExponent q20Eager512MaximumProofInteractionsAt128 ≤ 512 ∧
      totalOracleExposureExponent (q20Eager512MaximumProofInteractionsAt128 + 1) ≤ 512
  rw [show totalOracleExposureExponent q20Eager512MaximumProofInteractionsAt128 = 85 from
      exact_q20_eager_512_exposure_exponents.1,
    show totalOracleExposureExponent (q20Eager512MaximumProofInteractionsAt128 + 1) = 85 from
      exact_q20_eager_512_exposure_exponents.2]
  norm_num

theorem q20_eager_512_maximum_strictly_supports_128_bits :
    (q20Eager512ProgrammingRatio q20Eager512MaximumProofInteractionsAt128).strictlyBelowBits
      128 := by
  simp only [q20Eager512ProgrammingRatio, genericAdaptiveProgrammingRatio,
    ExactNatRatio.strictlyBelowBits]
  rw [show totalOracleExposureExponent q20Eager512MaximumProofInteractionsAt128 = 85 from
      exact_q20_eager_512_exposure_exponents.1]
  norm_num [q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
    eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

theorem q20_eager_512_successor_fails_strict_128_bits :
    ¬ (q20Eager512ProgrammingRatio
      (q20Eager512MaximumProofInteractionsAt128 + 1)).strictlyBelowBits 128 := by
  simp only [q20Eager512ProgrammingRatio, genericAdaptiveProgrammingRatio,
    ExactNatRatio.strictlyBelowBits]
  rw [show totalOracleExposureExponent (q20Eager512MaximumProofInteractionsAt128 + 1) = 85 from
      exact_q20_eager_512_exposure_exponents.2]
  norm_num [q20Eager512MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
    eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

theorem exact_q20_eager_448_exposure_exponents :
    totalOracleExposureExponent q20Eager448MaximumProofInteractionsAt128 = 65 ∧
      totalOracleExposureExponent (q20Eager448MaximumProofInteractionsAt128 + 1) = 65 := by
  have maximumLog :
      Nat.log 2 (totalOracleExposures q20Eager448MaximumProofInteractionsAt128) = 64 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  have successorLog :
      Nat.log 2 (totalOracleExposures (q20Eager448MaximumProofInteractionsAt128 + 1)) = 64 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
        eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
        V8Smz9QromAccounting.decsDomainSize, Historical.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  constructor
  · unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, maximumLog]
  · unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, successorLog]

theorem q20_eager_448_entropy_is_applicable_through_successor :
    genericAdaptiveProgrammingApplicable 448 q20Eager448MaximumProofInteractionsAt128 ∧
      genericAdaptiveProgrammingApplicable 448
        (q20Eager448MaximumProofInteractionsAt128 + 1) := by
  change
    totalOracleExposureExponent q20Eager448MaximumProofInteractionsAt128 ≤ 448 ∧
      totalOracleExposureExponent (q20Eager448MaximumProofInteractionsAt128 + 1) ≤ 448
  rw [show totalOracleExposureExponent q20Eager448MaximumProofInteractionsAt128 = 65 from
      exact_q20_eager_448_exposure_exponents.1,
    show totalOracleExposureExponent (q20Eager448MaximumProofInteractionsAt128 + 1) = 65 from
      exact_q20_eager_448_exposure_exponents.2]
  norm_num

theorem q20_eager_448_maximum_strictly_supports_128_bits :
    (q20Eager448ProgrammingRatio q20Eager448MaximumProofInteractionsAt128).strictlyBelowBits
      128 := by
  simp only [q20Eager448ProgrammingRatio, genericAdaptiveProgrammingRatio, ExactNatRatio.add,
    ExactNatRatio.strictlyBelowBits]
  rw [show totalOracleExposureExponent q20Eager448MaximumProofInteractionsAt128 = 65 from
      exact_q20_eager_448_exposure_exponents.1]
  norm_num [q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
    eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

theorem q20_eager_448_successor_fails_strict_128_bits :
    ¬ (q20Eager448ProgrammingRatio
      (q20Eager448MaximumProofInteractionsAt128 + 1)).strictlyBelowBits 128 := by
  simp only [q20Eager448ProgrammingRatio, genericAdaptiveProgrammingRatio, ExactNatRatio.add,
    ExactNatRatio.strictlyBelowBits]
  rw [show totalOracleExposureExponent (q20Eager448MaximumProofInteractionsAt128 + 1) = 65 from
      exact_q20_eager_448_exposure_exponents.2]
  norm_num [q20Eager448MaximumProofInteractionsAt128, eagerAllProgramsPerProof,
    eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

theorem q20_eager_one_proof_strict_bit_floors :
    (q20Eager512ProgrammingRatio 1).strictlyBelowBits 198 ∧
      ¬ (q20Eager512ProgrammingRatio 1).strictlyBelowBits 199 ∧
      (q20Eager448ProgrammingRatio 1).strictlyBelowBits 166 ∧
      ¬ (q20Eager448ProgrammingRatio 1).strictlyBelowBits 167 := by
  have oneLog : Nat.log 2 (totalOracleExposures 1) = 64 := by
    apply Nat.log_eq_of_pow_le_of_lt_pow
    · norm_num [totalOracleExposures, honestProgramExposures,
        eagerAllProgramsPerProof, eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
        Historical.decsDomainSize, V8Smz9QromAccounting.decsDomainSize,
        Historical.analysisGlobalQueryBudget, V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
    · norm_num [totalOracleExposures, honestProgramExposures,
        eagerAllProgramsPerProof, eagerTreeProgramsPerProof, finalPiopProgramsPerProof,
        Historical.decsDomainSize, V8Smz9QromAccounting.decsDomainSize,
        Historical.analysisGlobalQueryBudget, V8Smz9QromAccounting.analysisGlobalQueryBudget,
        V8Smz9QromAccounting.analysisGlobalQueryExponent]
  have oneExponent : totalOracleExposureExponent 1 = 65 := by
    unfold totalOracleExposureExponent
    rw [Nat.log2_eq_log_two, oneLog]
  simp only [q20Eager512ProgrammingRatio, q20Eager448ProgrammingRatio,
    genericAdaptiveProgrammingRatio, ExactNatRatio.add, ExactNatRatio.strictlyBelowBits]
  rw [oneExponent]
  norm_num [eagerAllProgramsPerProof,
    eagerTreeProgramsPerProof, finalPiopProgramsPerProof, Historical.decsDomainSize,
    V8Smz9QromAccounting.decsDomainSize]

def correctionPolynomialDegree : Nat := piopOpenings

def pcsUnstackAdditionalForbiddenValues : Nat := 68

def openingAdmissibilityBadTupleCoefficient : Nat :=
  correctionPolynomialDegree + piopOpenings * pcsUnstackAdditionalForbiddenValues

theorem exact_opening_admissibility_bad_tuple_coefficient :
    openingAdmissibilityBadTupleCoefficient = 414 := by
  decide

def distinctOutsideOpeningTupleCount : Nat :=
  fallingProduct (goldilocksOrder - packingFactor) piopOpenings

def admissibilityRejectedTupleUpperBound : Nat :=
  openingAdmissibilityBadTupleCoefficient * goldilocksOrder ^ (piopOpenings - 1)

def correctionAwareOpeningTupleLowerBound : Nat :=
  distinctOutsideOpeningTupleCount - admissibilityRejectedTupleUpperBound

theorem correction_aware_opening_denominator_is_positive :
    0 < correctionAwareOpeningTupleLowerBound := by
  decide

def correctedEpsilon1 : ExactNatRatio where
  numerator := 1
  denominator := goldilocksOrder ^ V8Smz9QromAccounting.decsEta

def correctedEpsilon2 : ExactNatRatio where
  numerator := 1
  denominator := goldilocksOrder ^ V8Smz9QromAccounting.rho

def correctedEpsilon3 : ExactNatRatio where
  numerator :=
    fallingProduct V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree piopOpenings
  denominator := correctionAwareOpeningTupleLowerBound

def correctedEpsilon4 : ExactNatRatio where
  numerator :=
    fallingProduct V8Smz9QromAccounting.decsPolynomialDegree decsOpenings
  denominator := fallingProduct decsDomainSize decsOpenings

def correctedInteractive : ExactNatRatio :=
  ((correctedEpsilon1.add correctedEpsilon2).add correctedEpsilon3).add correctedEpsilon4

theorem corrected_interactive_supports_288_bits :
    correctedInteractive.supportsBits 288 := by
  decide

theorem corrected_interactive_does_not_support_289_bits :
    ¬ correctedInteractive.supportsBits 289 := by
  decide

def correctedIdealCms (oracleExposures : Nat) : ExactNatRatio :=
  (correctedInteractive.scale (12 * oracleExposures ^ 2)).add {
    numerator := 48 * oracleExposures ^ 3 + 2 * decsDomainSize ^ 2
    denominator := 2 ^ transcriptHashBits
  }

theorem corrected_ideal_cms_at_total_exposure_supports_157_bits :
    (correctedIdealCms analysisTotalSha512OracleExposures).supportsBits 157 := by
  decide

theorem corrected_ideal_cms_at_total_exposure_does_not_support_158_bits :
    ¬ (correctedIdealCms analysisTotalSha512OracleExposures).supportsBits 158 := by
  decide

def sha512PreimageTerm : ExactNatRatio where
  numerator := analysisTotalSha512OracleExposures ^ 2
  denominator := 2 ^ transcriptHashBits

def poseidon2CollisionTerm : ExactNatRatio where
  numerator := analysisGlobalQueryBudget ^ 3
  denominator := goldilocksOrder ^ 7

def poseidon2PreimageTerm : ExactNatRatio where
  numerator := analysisGlobalQueryBudget ^ 2
  denominator := goldilocksOrder ^ 7

def fieldXofRequestedWords : Nat := 102365
def fieldXofCandidateWords : Nat := 102400
def fieldXofMinimumRejections : Nat := 36
def fieldXofRequestUnion : Nat := 2 ^ 25

theorem exact_field_xof_sampler_parameters :
    fieldXofRequestedWords = 102365 ∧ fieldXofCandidateWords = 102400 ∧
      fieldXofMinimumRejections = 36 := by
  decide

def fieldXofAbortTerm : ExactNatRatio where
  numerator :=
    fieldXofRequestUnion * Nat.choose fieldXofCandidateWords fieldXofMinimumRejections *
      (2 ^ 32 - 1) ^ fieldXofMinimumRejections
  denominator := 2 ^ (64 * fieldXofMinimumRejections)

/--
A kernel-friendly conservative envelope for `fieldXofAbortTerm`.  The exact source term remains
above; this replaces only `choose n k` by the standard upper bound `n^k` in the composed ledger.
-/
def fieldXofAbortEnvelopeTerm : ExactNatRatio where
  numerator :=
    fieldXofRequestUnion * fieldXofCandidateWords ^ fieldXofMinimumRejections *
      (2 ^ 32 - 1) ^ fieldXofMinimumRejections
  denominator := 2 ^ (64 * fieldXofMinimumRejections)

theorem choose_abort_numerator_le_pow_envelope (unionBound words rejections tail : Nat) :
    unionBound * Nat.choose words rejections * tail ≤
      unionBound * words ^ rejections * tail :=
  mul_le_mul_left
    (mul_le_mul_right (Nat.choose_le_pow words rejections) unionBound)
    tail

def piopNonceAbortTerm : ExactNatRatio where
  numerator := 813 ^ 16
  denominator := goldilocksOrder ^ 16

/-! ## Exact correction-aware ideal opening sampler -/

abbrev OpeningIndex := Fin piopOpenings

def packingPoint : Fin packingFactor → Goldilocks := fun lane => lane.val

theorem packingPoint_injective : Function.Injective packingPoint := by
  intro left right same
  apply Fin.ext
  change (left.val : Goldilocks) = right.val at same
  rw [ZMod.natCast_eq_natCast_iff'] at same
  have leftSmall :
      left.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus :=
    lt_trans left.isLt (by decide)
  have rightSmall :
      right.val < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus :=
    lt_trans right.isLt (by decide)
  simpa [Nat.mod_eq_of_lt leftSmall, Nat.mod_eq_of_lt rightSmall] using same

def packingEmbedding : Fin packingFactor ↪ Goldilocks :=
  ⟨packingPoint, packingPoint_injective⟩

def packingDomain : Finset Goldilocks :=
  Finset.univ.map packingEmbedding

theorem packingDomain_card : packingDomain.card = packingFactor := by
  simp [packingDomain]

abbrev OutsidePacking := { point : Goldilocks // point ∉ packingDomain }
abbrev DistinctOutsideOpeningTuple := OpeningIndex ↪ OutsidePacking

noncomputable instance : Fintype OutsidePacking := Fintype.ofFinite _
noncomputable instance : Fintype DistinctOutsideOpeningTuple := Fintype.ofFinite _

theorem outsidePacking_card :
    Fintype.card OutsidePacking = goldilocksOrder - packingFactor := by
  rw [Fintype.card_subtype_compl]
  rw [show Fintype.card Goldilocks = goldilocksOrder by
    rw [ZMod.card]
    rfl]
  congr 1

theorem distinctOutsideOpeningTuple_card :
    Fintype.card DistinctOutsideOpeningTuple = distinctOutsideOpeningTupleCount := by
  rw [Fintype.card_embedding_eq, outsidePacking_card]
  simp only [OpeningIndex, Fintype.card_fin]
  unfold distinctOutsideOpeningTupleCount Historical.fallingProduct
  change
    (goldilocksOrder - packingFactor).descFactorial piopOpenings =
      Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct
        (goldilocksOrder - packingFactor) piopOpenings
  rw [UniformSubsetSampling.falling_product_eq_desc_factorial]

def correctionPolynomial : MvPolynomial OpeningIndex Goldilocks :=
  ∑ lane : Fin packingFactor,
    ∏ opening : OpeningIndex,
      (C (lane.val : Goldilocks) - X opening)

def correctionNumerator (points : OpeningIndex → Goldilocks) : Goldilocks :=
  ∑ lane : Fin packingFactor,
    ∏ opening : OpeningIndex,
      ((lane.val : Goldilocks) - points opening)

theorem correctionPolynomial_eval (points : OpeningIndex → Goldilocks) :
    eval points correctionPolynomial = correctionNumerator points := by
  simp [correctionPolynomial, correctionNumerator]

theorem correctionPolynomial_totalDegree_le :
    correctionPolynomial.totalDegree ≤ correctionPolynomialDegree := by
  unfold correctionPolynomial correctionPolynomialDegree
  apply totalDegree_finsetSum_le
  intro lane _
  calc
    (∏ opening : OpeningIndex,
        (C (lane.val : Goldilocks) - X opening)).totalDegree ≤
        ∑ opening : OpeningIndex,
          (C (lane.val : Goldilocks) - X opening).totalDegree :=
      totalDegree_finsetProd _ _
    _ ≤ ∑ _opening : OpeningIndex, 1 := by
      apply Finset.sum_le_sum
      intro opening _
      calc
        (C (lane.val : Goldilocks) - X opening).totalDegree ≤
            max (C (lane.val : Goldilocks) : MvPolynomial OpeningIndex Goldilocks).totalDegree
              (X opening : MvPolynomial OpeningIndex Goldilocks).totalDegree :=
          totalDegree_sub _ _
        _ = 1 := by
          rw [totalDegree_C, totalDegree_X]
          decide
    _ = piopOpenings := by simp

theorem correctionPolynomial_eval_zero_ne :
    eval (fun _ : OpeningIndex => 0) correctionPolynomial ≠ 0 := by
  rw [correctionPolynomial_eval]
  norm_num [correctionNumerator, OpeningIndex, Historical.piopOpenings,
    Historical.packingFactor, V8Smz9QromAccounting.piopOpenings,
    V8Smz9QromAccounting.packingFactor]

theorem correctionPolynomial_ne_zero : correctionPolynomial ≠ 0 := by
  intro isZero
  have evaluated := congrArg (eval (fun _ : OpeningIndex => 0)) isZero
  simp only [map_zero] at evaluated
  exact correctionPolynomial_eval_zero_ne evaluated

def correctionZeroTuples : Finset (OpeningIndex → Goldilocks) :=
  Finset.univ.filter fun points => correctionNumerator points = 0

theorem correctionZeroTuples_eq_schwartzZippelSet :
    correctionZeroTuples =
      (Fintype.piFinset fun _ : OpeningIndex => (Finset.univ : Finset Goldilocks)).filter
        fun points => eval points correctionPolynomial = 0 := by
  ext points
  simp [correctionZeroTuples, correctionPolynomial_eval]

theorem correction_zero_tuple_card_le :
    correctionZeroTuples.card ≤
      correctionPolynomialDegree * goldilocksOrder ^ (piopOpenings - 1) := by
  have schwartz := MvPolynomial.schwartz_zippel_totalDegree
    correctionPolynomial_ne_zero (Finset.univ : Finset Goldilocks)
  rw [← correctionZeroTuples_eq_schwartzZippelSet] at schwartz
  have fieldCard : (Finset.univ : Finset Goldilocks).card = goldilocksOrder := by
    rw [Finset.card_univ, ZMod.card]
    rfl
  rw [fieldCard] at schwartz
  have denominatorPositive :
      (0 : ℚ≥0) < (goldilocksOrder : ℚ≥0) ^ piopOpenings := by
    apply pow_pos
    exact_mod_cast (show 0 < goldilocksOrder by decide)
  have multiplied := (div_le_iff₀ denominatorPositive).mp schwartz
  have normalizeRight :
      ((correctionPolynomial.totalDegree : ℚ≥0) / (goldilocksOrder : ℚ≥0)) *
          (goldilocksOrder : ℚ≥0) ^ piopOpenings =
        (correctionPolynomial.totalDegree : ℚ≥0) *
          (goldilocksOrder : ℚ≥0) ^ (piopOpenings - 1) := by
    norm_num [V8Smz9QromAccounting.piopOpenings,
      V8Smz9QromAccounting.goldilocksOrder,
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldModulus]
    field_simp
  rw [normalizeRight] at multiplied
  have degreeBound :
      (correctionPolynomial.totalDegree : ℚ≥0) ≤ correctionPolynomialDegree := by
    exact_mod_cast correctionPolynomial_totalDegree_le
  have castBound :
      (correctionZeroTuples.card : ℚ≥0) ≤
        (correctionPolynomialDegree : ℚ≥0) *
          (goldilocksOrder : ℚ≥0) ^ (piopOpenings - 1) :=
    multiplied.trans (by gcongr)
  exact_mod_cast castBound

def pcsRootSet (exponent : Nat) : Finset Goldilocks :=
  Finset.univ.filter fun point => point ^ exponent = 1

theorem pcsRootSet_eq_polynomial_rootSet (exponent : Nat) :
    pcsRootSet exponent =
      FiniteFieldSampling.rootSet
        ((Polynomial.X : Polynomial Goldilocks) ^ exponent - Polynomial.C 1) := by
  ext point
  simp [pcsRootSet, FiniteFieldSampling.rootSet, sub_eq_zero]

theorem pcsRootSet_card_le (exponent : Nat) (positive : 0 < exponent) :
    (pcsRootSet exponent).card ≤ exponent := by
  rw [pcsRootSet_eq_polynomial_rootSet]
  have rootBound := FiniteFieldSampling.root_set_card_le_nat_degree
    (Polynomial.X_pow_sub_C_ne_zero (R := Goldilocks) positive 1)
  simpa only [Polynomial.natDegree_X_pow_sub_C] using rootBound

theorem goldilocks_fermat {point : Goldilocks} (nonzero : point ≠ 0) :
    point ^ (goldilocksOrder - 1) = 1 := by
  have fermat := ZMod.pow_card_sub_one_eq_one nonzero
  have orderIdentity :
      goldilocksOrder =
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := by
    decide
  rw [orderIdentity]
  exact fermat

theorem pow35_eq_one_implies_pow5_eq_one
    {point : Goldilocks} (root : point ^ 35 = 1) :
    point ^ 5 = 1 := by
  have nonzero : point ≠ 0 := by
    intro isZero
    rw [isZero, zero_pow (by decide)] at root
    exact zero_ne_one root
  have fermat := goldilocks_fermat nonzero
  have exponentIdentity :
      goldilocksOrder - 1 = 35 * 527049830554702409 + 5 := by
    decide
  rw [exponentIdentity, pow_add, pow_mul, root, one_pow, one_mul] at fermat
  exact fermat

theorem pow63_eq_one_implies_pow3_eq_one
    {point : Goldilocks} (root : point ^ 63 = 1) :
    point ^ 3 = 1 := by
  have nonzero : point ≠ 0 := by
    intro isZero
    rw [isZero, zero_pow (by decide)] at root
    exact zero_ne_one root
  have fermat := goldilocks_fermat nonzero
  have repeatedFermat : point ^ ((goldilocksOrder - 1) * 16) = 1 := by
    rw [pow_mul, fermat, one_pow]
  have exponentIdentity :
      (goldilocksOrder - 1) * 16 = 63 * 4684887382708465859 + 3 := by
    decide
  rw [exponentIdentity, pow_add, pow_mul, root, one_pow, one_mul] at repeatedFermat
  exact repeatedFermat

theorem pcsRootSet64_card_le : (pcsRootSet 64).card ≤ 64 :=
  pcsRootSet_card_le 64 (by decide)

theorem pcsRootSet35_card_le : (pcsRootSet 35).card ≤ 5 := by
  calc
    (pcsRootSet 35).card ≤ (pcsRootSet 5).card := by
      apply Finset.card_le_card
      intro point membership
      simp only [pcsRootSet, Finset.mem_filter, Finset.mem_univ, true_and] at membership ⊢
      exact pow35_eq_one_implies_pow5_eq_one membership
    _ ≤ 5 := pcsRootSet_card_le 5 (by decide)

theorem pcsRootSet63_card_le : (pcsRootSet 63).card ≤ 3 := by
  calc
    (pcsRootSet 63).card ≤ (pcsRootSet 3).card := by
      apply Finset.card_le_card
      intro point membership
      simp only [pcsRootSet, Finset.mem_filter, Finset.mem_univ, true_and] at membership ⊢
      exact pow63_eq_one_implies_pow3_eq_one membership
    _ ≤ 3 := pcsRootSet_card_le 3 (by decide)

def pcsRootUnion : Finset Goldilocks :=
  pcsRootSet 64 ∪ pcsRootSet 35 ∪ pcsRootSet 63

theorem one_mem_pcsRootSet (exponent : Nat) : (1 : Goldilocks) ∈ pcsRootSet exponent := by
  simp [pcsRootSet]

theorem pcsRootUnion_card_le_70 : pcsRootUnion.card ≤ 70 := by
  have firstIntersection :
      1 ≤ (pcsRootSet 64 ∩ pcsRootSet 35).card := by
    exact Finset.card_pos.mpr ⟨1, by simp [one_mem_pcsRootSet]⟩
  have firstUnion : (pcsRootSet 64 ∪ pcsRootSet 35).card ≤ 68 := by
    have unionIdentity := Finset.card_union_add_card_inter (pcsRootSet 64) (pcsRootSet 35)
    have bound64 := pcsRootSet64_card_le
    have bound35 := pcsRootSet35_card_le
    omega
  have secondIntersection :
      1 ≤ ((pcsRootSet 64 ∪ pcsRootSet 35) ∩ pcsRootSet 63).card := by
    exact Finset.card_pos.mpr ⟨1, by simp [one_mem_pcsRootSet]⟩
  unfold pcsRootUnion
  have unionIdentity :=
    Finset.card_union_add_card_inter (pcsRootSet 64 ∪ pcsRootSet 35) (pcsRootSet 63)
  have bound63 := pcsRootSet63_card_le
  omega

def pcsAdditionalRootSet : Finset Goldilocks :=
  pcsRootUnion \ packingDomain

theorem one_mem_packingDomain : (1 : Goldilocks) ∈ packingDomain := by
  rw [packingDomain, Finset.mem_map]
  exact ⟨(⟨1, by decide⟩ : Fin packingFactor), Finset.mem_univ _, rfl⟩

theorem eight_mem_packingDomain : (8 : Goldilocks) ∈ packingDomain := by
  rw [packingDomain, Finset.mem_map]
  exact ⟨(⟨8, by decide⟩ : Fin packingFactor), Finset.mem_univ _, rfl⟩

theorem one_mem_pcsRootUnion : (1 : Goldilocks) ∈ pcsRootUnion := by
  exact Finset.mem_union_left _ (Finset.mem_union_left _ (one_mem_pcsRootSet 64))

theorem eight_mem_pcsRootUnion : (8 : Goldilocks) ∈ pcsRootUnion := by
  have root64 : (8 : Goldilocks) ^ 64 = 1 := by decide
  simp [pcsRootUnion, pcsRootSet, root64]

theorem pcs_additional_root_set_card_le : pcsAdditionalRootSet.card ≤ 68 := by
  have pairSubset :
      ({(1 : Goldilocks), (8 : Goldilocks)} : Finset Goldilocks) ⊆
        pcsRootUnion ∩ packingDomain := by
    intro point membership
    simp only [Finset.mem_insert, Finset.mem_singleton] at membership
    rcases membership with rfl | rfl
    · exact Finset.mem_inter.mpr ⟨one_mem_pcsRootUnion, one_mem_packingDomain⟩
    · exact Finset.mem_inter.mpr ⟨eight_mem_pcsRootUnion, eight_mem_packingDomain⟩
  have pairCard : ({(1 : Goldilocks), (8 : Goldilocks)} : Finset Goldilocks).card = 2 := by
    decide
  have intersectionLower : 2 ≤ (pcsRootUnion ∩ packingDomain).card := by
    rw [← pairCard]
    exact Finset.card_le_card pairSubset
  have differenceIdentity := Finset.card_sdiff_add_card_inter pcsRootUnion packingDomain
  have unionBound := pcsRootUnion_card_le_70
  unfold pcsAdditionalRootSet
  omega

abbrev OpeningTuple := OpeningIndex → Goldilocks

abbrev CoordinateInSet (values : Finset Goldilocks) (coordinate : OpeningIndex) :=
  { points : OpeningTuple // points coordinate ∈ values }

noncomputable def coordinateInSetEquiv
    (values : Finset Goldilocks) (coordinate : OpeningIndex) :
    CoordinateInSet values coordinate ≃
      values × (Fin 5 → Goldilocks) where
  toFun points :=
    (⟨points.1 coordinate, points.2⟩, coordinate.removeNth points.1)
  invFun data :=
    ⟨coordinate.insertNth data.1.1 data.2, by simp⟩
  left_inv points := by
    apply Subtype.ext
    exact coordinate.insertNth_self_removeNth points.1
  right_inv data := by
    rcases data with ⟨value, rest⟩
    apply Prod.ext
    · apply Subtype.ext
      simp
    · exact Fin.removeNth_insertNth
        (α := fun _ : Fin 6 => Goldilocks) coordinate value.1 rest

theorem coordinate_in_set_card
    (values : Finset Goldilocks) (coordinate : OpeningIndex) :
    Fintype.card (CoordinateInSet values coordinate) =
      values.card * goldilocksOrder ^ (piopOpenings - 1) := by
  rw [Fintype.card_congr (coordinateInSetEquiv values coordinate)]
  simp only [Fintype.card_prod, Fintype.card_coe, Fintype.card_fun,
    Fintype.card_fin]
  have fieldCard : Fintype.card Goldilocks = goldilocksOrder := by
    rw [ZMod.card]
    rfl
  rw [fieldCard]
  congr 1

abbrev TupleHitsSet (values : Finset Goldilocks) :=
  { points : OpeningTuple // ∃ coordinate, points coordinate ∈ values }

noncomputable def tupleHitsSetEmbedding (values : Finset Goldilocks) :
    TupleHitsSet values ↪
      Sigma fun coordinate : OpeningIndex => CoordinateInSet values coordinate where
  toFun points :=
    let coordinate := Classical.choose points.2
    ⟨coordinate, ⟨points.1, Classical.choose_spec points.2⟩⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    exact congrArg (fun item => item.2.1) same

theorem tuple_hits_set_card_le (values : Finset Goldilocks) :
    Fintype.card (TupleHitsSet values) ≤
      piopOpenings * values.card * goldilocksOrder ^ (piopOpenings - 1) := by
  calc
    Fintype.card (TupleHitsSet values) ≤
        Fintype.card (Sigma fun coordinate : OpeningIndex => CoordinateInSet values coordinate) :=
      Fintype.card_le_of_embedding (tupleHitsSetEmbedding values)
    _ = ∑ coordinate : OpeningIndex,
        Fintype.card (CoordinateInSet values coordinate) := Fintype.card_sigma
    _ = ∑ _coordinate : OpeningIndex,
        values.card * goldilocksOrder ^ (piopOpenings - 1) := by
      apply Finset.sum_congr rfl
      intro coordinate _
      exact coordinate_in_set_card values coordinate
    _ = piopOpenings * values.card * goldilocksOrder ^ (piopOpenings - 1) := by
      simp [OpeningIndex, mul_assoc]

def baseOpeningPoints (base : DistinctOutsideOpeningTuple) : OpeningTuple :=
  fun coordinate => (base coordinate).1

theorem baseOpeningPoints_injective (base : DistinctOutsideOpeningTuple) :
    Function.Injective (baseOpeningPoints base) := by
  intro left right same
  apply base.injective
  apply Subtype.ext
  exact same

theorem baseOpeningPoints_outside_packing
    (base : DistinctOutsideOpeningTuple) (coordinate : OpeningIndex) :
    baseOpeningPoints base coordinate ∉ packingDomain :=
  (base coordinate).2

def extraOpeningAdmissible (base : DistinctOutsideOpeningTuple) : Prop :=
  correctionNumerator (baseOpeningPoints base) ≠ 0 ∧
    ∀ coordinate, baseOpeningPoints base coordinate ∉ pcsAdditionalRootSet

abbrev FullAdmissibleOpeningTuple :=
  { base : DistinctOutsideOpeningTuple // extraOpeningAdmissible base }

abbrev RejectedDistinctOutsideOpeningTuple :=
  { base : DistinctOutsideOpeningTuple // ¬ extraOpeningAdmissible base }

abbrev CorrectionZeroTuple :=
  { points : OpeningTuple // correctionNumerator points = 0 }

noncomputable instance : Fintype CorrectionZeroTuple := Fintype.ofFinite _

theorem correction_zero_tuple_fintype_card_le :
    Fintype.card CorrectionZeroTuple ≤
      correctionPolynomialDegree * goldilocksOrder ^ (piopOpenings - 1) := by
  rw [Fintype.card_subtype]
  simpa [correctionZeroTuples] using correction_zero_tuple_card_le

abbrev ExtraPcsHitTuple := TupleHitsSet pcsAdditionalRootSet

def rejectedViolationUnderlying :
    CorrectionZeroTuple ⊕ ExtraPcsHitTuple → OpeningTuple
  | Sum.inl points => points.1
  | Sum.inr points => points.1

noncomputable def rejectedDistinctOutsideEmbedding :
    RejectedDistinctOutsideOpeningTuple ↪ CorrectionZeroTuple ⊕ ExtraPcsHitTuple where
  toFun rejected := by
    by_cases correctionZero : correctionNumerator (baseOpeningPoints rejected.1) = 0
    · exact Sum.inl ⟨baseOpeningPoints rejected.1, correctionZero⟩
    · apply Sum.inr
      refine ⟨baseOpeningPoints rejected.1, ?_⟩
      unfold extraOpeningAdmissible at rejected
      push_neg at rejected
      exact rejected.2 correctionZero
  inj' := by
    intro left right same
    have underlyingSame : baseOpeningPoints left.1 = baseOpeningPoints right.1 :=
      congrArg rejectedViolationUnderlying same
    apply Subtype.ext
    apply DFunLike.ext _ _
    intro coordinate
    apply Subtype.ext
    exact congrFun underlyingSame coordinate

theorem rejected_distinct_outside_card_le :
    Fintype.card RejectedDistinctOutsideOpeningTuple ≤
      openingAdmissibilityBadTupleCoefficient *
        goldilocksOrder ^ (piopOpenings - 1) := by
  have correctionBound := correction_zero_tuple_fintype_card_le
  have hitBound := tuple_hits_set_card_le pcsAdditionalRootSet
  have rootBound := pcs_additional_root_set_card_le
  have scaledHitBound :
      Fintype.card ExtraPcsHitTuple ≤
        piopOpenings * pcsUnstackAdditionalForbiddenValues *
          goldilocksOrder ^ (piopOpenings - 1) := by
    calc
      Fintype.card ExtraPcsHitTuple ≤
          piopOpenings * pcsAdditionalRootSet.card *
            goldilocksOrder ^ (piopOpenings - 1) := hitBound
      _ ≤ piopOpenings * pcsUnstackAdditionalForbiddenValues *
            goldilocksOrder ^ (piopOpenings - 1) := by
        apply Nat.mul_le_mul_right
        exact Nat.mul_le_mul_left _ rootBound
  calc
    Fintype.card RejectedDistinctOutsideOpeningTuple ≤
        Fintype.card (CorrectionZeroTuple ⊕ ExtraPcsHitTuple) :=
      Fintype.card_le_of_embedding rejectedDistinctOutsideEmbedding
    _ = Fintype.card CorrectionZeroTuple + Fintype.card ExtraPcsHitTuple :=
      Fintype.card_sum
    _ ≤ correctionPolynomialDegree * goldilocksOrder ^ (piopOpenings - 1) +
          piopOpenings * pcsUnstackAdditionalForbiddenValues *
            goldilocksOrder ^ (piopOpenings - 1) :=
      Nat.add_le_add correctionBound scaledHitBound
    _ = openingAdmissibilityBadTupleCoefficient *
          goldilocksOrder ^ (piopOpenings - 1) := by
      unfold openingAdmissibilityBadTupleCoefficient
      omega

theorem full_admissible_opening_tuple_card_lower_bound :
    correctionAwareOpeningTupleLowerBound ≤
      Fintype.card FullAdmissibleOpeningTuple := by
  have partition := Fintype.card_subtype_compl extraOpeningAdmissible
  have rejectedBound := rejected_distinct_outside_card_le
  rw [distinctOutsideOpeningTuple_card] at partition
  unfold correctionAwareOpeningTupleLowerBound admissibilityRejectedTupleUpperBound
  omega

abbrev OrderedCollisionPair :=
  { pair : OpeningIndex × OpeningIndex // pair.1.val < pair.2.val }

theorem orderedCollisionPair_card : Fintype.card OrderedCollisionPair = 15 := by
  decide

abbrev CollisionFiber (pair : OrderedCollisionPair) :=
  { points : OpeningTuple // points pair.1.1 = points pair.1.2 }

def collisionFiberEmbedding (pair : OrderedCollisionPair) :
    CollisionFiber pair ↪ (Fin 5 → Goldilocks) where
  toFun points := pair.1.2.removeNth points.1
  inj' := by
    intro left right removedSame
    have distinct : pair.1.1 ≠ pair.1.2 := by
      intro same
      rw [same] at pair
      exact Nat.lt_irrefl _ pair.2
    obtain ⟨coordinate, coordinateSpec⟩ := Fin.exists_succAbove_eq distinct
    have firstSame : left.1 pair.1.1 = right.1 pair.1.1 := by
      have coordinateSame := congrFun removedSame coordinate
      simpa [Fin.removeNth_apply, coordinateSpec] using coordinateSame
    have secondSame : left.1 pair.1.2 = right.1 pair.1.2 := by
      rw [← left.2, ← right.2]
      exact firstSame
    calc
      left.1 = pair.1.2.insertNth (left.1 pair.1.2) (pair.1.2.removeNth left.1) :=
        (pair.1.2.insertNth_self_removeNth left.1).symm
      _ = pair.1.2.insertNth (right.1 pair.1.2) (pair.1.2.removeNth right.1) := by
        rw [secondSame, removedSame]
      _ = right.1 := pair.1.2.insertNth_self_removeNth right.1

theorem collision_fiber_card_le (pair : OrderedCollisionPair) :
    Fintype.card (CollisionFiber pair) ≤
      goldilocksOrder ^ (piopOpenings - 1) := by
  calc
    Fintype.card (CollisionFiber pair) ≤ Fintype.card (Fin 5 → Goldilocks) :=
      Fintype.card_le_of_embedding (collisionFiberEmbedding pair)
    _ = Fintype.card Goldilocks ^ 5 := by simp
    _ = goldilocksOrder ^ (piopOpenings - 1) := by
      rw [show Fintype.card Goldilocks = goldilocksOrder by
        rw [ZMod.card]
        rfl]
      congr

abbrev CollisionTuple := { points : OpeningTuple // ¬ Function.Injective points }

theorem collision_tuple_has_ordered_pair (points : CollisionTuple) :
    ∃ pair : OrderedCollisionPair, points.1 pair.1.1 = points.1 pair.1.2 := by
  unfold Function.Injective at points
  push_neg at points
  rcases points.2 with ⟨left, right, sameValue, different⟩
  by_cases ordered : left.val < right.val
  · exact ⟨⟨(left, right), ordered⟩, sameValue⟩
  · have reverseOrdered : right.val < left.val := by
      have valuesDifferent : left.val ≠ right.val := by
        intro same
        apply different
        exact Fin.ext same
      omega
    exact ⟨⟨(right, left), reverseOrdered⟩, sameValue.symm⟩

def collisionSigmaUnderlying :
    (Sigma fun pair : OrderedCollisionPair => CollisionFiber pair) → OpeningTuple :=
  fun item => item.2.1

noncomputable def collisionTupleEmbedding :
    CollisionTuple ↪ Sigma fun pair : OrderedCollisionPair => CollisionFiber pair where
  toFun points :=
    let pair := Classical.choose (collision_tuple_has_ordered_pair points)
    ⟨pair, ⟨points.1, Classical.choose_spec (collision_tuple_has_ordered_pair points)⟩⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    exact congrArg collisionSigmaUnderlying same

theorem collision_tuple_card_le :
    Fintype.card CollisionTuple ≤
      15 * goldilocksOrder ^ (piopOpenings - 1) := by
  calc
    Fintype.card CollisionTuple ≤
        Fintype.card (Sigma fun pair : OrderedCollisionPair => CollisionFiber pair) :=
      Fintype.card_le_of_embedding collisionTupleEmbedding
    _ = ∑ pair : OrderedCollisionPair, Fintype.card (CollisionFiber pair) :=
      Fintype.card_sigma
    _ ≤ ∑ _pair : OrderedCollisionPair,
        goldilocksOrder ^ (piopOpenings - 1) := by
      apply Finset.sum_le_sum
      intro pair _
      exact collision_fiber_card_le pair
    _ = 15 * goldilocksOrder ^ (piopOpenings - 1) := by
      simp [orderedCollisionPair_card]

theorem correctionNumerator_eq_exact_rust_numerator (points : OpeningTuple) :
    correctionNumerator points =
      V8Smz9ZeroKnowledge.linearPiopCorrectionNumerator points := by
  rfl

theorem not_mem_pcsRootUnion_iff (point : Goldilocks) :
    point ∉ pcsRootUnion ↔
      point ^ 64 ≠ 1 ∧ point ^ 35 ≠ 1 ∧ point ^ 63 ≠ 1 := by
  simp [pcsRootUnion, pcsRootSet]

theorem zero_mem_packingDomain : (0 : Goldilocks) ∈ packingDomain := by
  rw [packingDomain, Finset.mem_map]
  exact ⟨(0 : Fin packingFactor), Finset.mem_univ _, rfl⟩

def CorrectionAwareOpeningPredicate (points : OpeningTuple) : Prop :=
  Function.Injective points ∧
    (∀ coordinate, points coordinate ∉ packingDomain) ∧
    V8Smz9ZeroKnowledge.linearPiopCorrectionNumerator points ≠ 0 ∧
    (∀ coordinate,
      points coordinate ^ 64 ≠ 1 ∧
      points coordinate ^ 35 ≠ 1 ∧
      points coordinate ^ 63 ≠ 1)

theorem full_admissible_satisfies_exact_predicate
    (accepted : FullAdmissibleOpeningTuple) :
    CorrectionAwareOpeningPredicate (baseOpeningPoints accepted.1) := by
  refine ⟨baseOpeningPoints_injective accepted.1,
    baseOpeningPoints_outside_packing accepted.1, ?_, ?_⟩
  · simpa [← correctionNumerator_eq_exact_rust_numerator] using accepted.2.1
  · intro coordinate
    rw [← not_mem_pcsRootUnion_iff]
    intro rootMembership
    exact accepted.2.2 coordinate
      (Finset.mem_sdiff.mpr
        ⟨rootMembership, baseOpeningPoints_outside_packing accepted.1 coordinate⟩)

theorem full_admissible_linear_piop_exact
    (accepted : FullAdmissibleOpeningTuple) :
    V8Smz9ZeroKnowledge.Smz9LinearPiopAdmissible
      (baseOpeningPoints accepted.1) := by
  have exactPredicate := full_admissible_satisfies_exact_predicate accepted
  have nonzero : ∀ coordinate, baseOpeningPoints accepted.1 coordinate ≠ 0 := by
    intro coordinate isZero
    exact exactPredicate.2.1 coordinate (isZero ▸ zero_mem_packingDomain)
  refine {
    packingCardinalityNonzero := by decide
    pointsInjective := exactPredicate.1
    pointsNonzero := nonzero
    pointsOutsidePacking := ?_
    correctionFactorNonzero := ?_
  }
  · intro coordinate lane same
    exact exactPredicate.2.1 coordinate (by
      rw [packingDomain, Finset.mem_map]
      exact ⟨lane, Finset.mem_univ _, same.symm⟩)
  · unfold V8Smz9ZeroKnowledge.linearPiopCorrectionFactor
    apply mul_ne_zero exactPredicate.2.2.1
    apply inv_ne_zero
    unfold V8Smz9ZeroKnowledge.linearPiopCorrectionDenominator
    apply Finset.prod_ne_zero_iff.mpr
    intro coordinate _
    exact neg_ne_zero.mpr (nonzero coordinate)

theorem full_admissible_pcs_unstack_exact
    (accepted : FullAdmissibleOpeningTuple) :
    V8Smz9ZeroKnowledge.Smz9PcsUnstackAdmissible
      (baseOpeningPoints accepted.1) := by
  have exactPredicate := full_admissible_satisfies_exact_predicate accepted
  refine {
    pointsInjective := exactPredicate.1
    pointsNonzero := ?_
    pow64NeOne := fun coordinate => (exactPredicate.2.2.2 coordinate).1
    pow35NeOne := fun coordinate => (exactPredicate.2.2.2 coordinate).2.1
    pow63NeOne := fun coordinate => (exactPredicate.2.2.2 coordinate).2.2
  }
  intro coordinate isZero
  exact exactPredicate.2.1 coordinate (isZero ▸ zero_mem_packingDomain)

abbrev PackingHitTuple := TupleHitsSet packingDomain

abbrev InvalidOpeningTuple :=
  { points : OpeningTuple // ¬ CorrectionAwareOpeningPredicate points }

abbrev OpeningViolation :=
  PackingHitTuple ⊕ (CollisionTuple ⊕ (CorrectionZeroTuple ⊕ ExtraPcsHitTuple))

def openingViolationUnderlying : OpeningViolation → OpeningTuple
  | Sum.inl points => points.1
  | Sum.inr (Sum.inl points) => points.1
  | Sum.inr (Sum.inr (Sum.inl points)) => points.1
  | Sum.inr (Sum.inr (Sum.inr points)) => points.1

noncomputable def invalidOpeningTupleEmbedding :
    InvalidOpeningTuple ↪ OpeningViolation where
  toFun invalid := by
    by_cases outside : ∀ coordinate, invalid.1 coordinate ∉ packingDomain
    · by_cases injective : Function.Injective invalid.1
      · by_cases correctionNonzero :
          V8Smz9ZeroKnowledge.linearPiopCorrectionNumerator invalid.1 ≠ 0
        · apply Sum.inr
          apply Sum.inr
          apply Sum.inr
          refine ⟨invalid.1, ?_⟩
          have notAllFactors : ¬ ∀ coordinate,
              invalid.1 coordinate ^ 64 ≠ 1 ∧
              invalid.1 coordinate ^ 35 ≠ 1 ∧
              invalid.1 coordinate ^ 63 ≠ 1 := by
            intro allFactors
            exact invalid.2 ⟨injective, outside, correctionNonzero, allFactors⟩
          push_neg at notAllFactors
          rcases notAllFactors with ⟨coordinate, badFactor⟩
          refine ⟨coordinate, Finset.mem_sdiff.mpr ⟨?_, outside coordinate⟩⟩
          by_contra notRoot
          exact badFactor ((not_mem_pcsRootUnion_iff _).mp notRoot)
        · apply Sum.inr
          apply Sum.inr
          apply Sum.inl
          refine ⟨invalid.1, ?_⟩
          rw [correctionNumerator_eq_exact_rust_numerator]
          exact Classical.not_not.mp correctionNonzero
      · exact Sum.inr (Sum.inl ⟨invalid.1, injective⟩)
    · apply Sum.inl
      push_neg at outside
      exact ⟨invalid.1, outside⟩
  inj' := by
    intro left right same
    apply Subtype.ext
    exact congrArg openingViolationUnderlying same

def rawOpeningBadTupleCoefficient : Nat :=
  piopOpenings * packingFactor + Nat.choose piopOpenings 2 +
    correctionPolynomialDegree +
    piopOpenings * pcsUnstackAdditionalForbiddenValues

theorem exact_raw_opening_bad_tuple_coefficient :
    rawOpeningBadTupleCoefficient = 813 := by
  decide

theorem invalid_opening_tuple_card_le :
    Fintype.card InvalidOpeningTuple ≤
      rawOpeningBadTupleCoefficient *
        goldilocksOrder ^ (piopOpenings - 1) := by
  have packingHitBound := tuple_hits_set_card_le packingDomain
  have packingCard := packingDomain_card
  have collisionBound := collision_tuple_card_le
  have correctionBound := correction_zero_tuple_fintype_card_le
  have pcsHitBound := tuple_hits_set_card_le pcsAdditionalRootSet
  have pcsRootBound := pcs_additional_root_set_card_le
  have scaledPackingHitBound :
      Fintype.card PackingHitTuple ≤
        piopOpenings * packingFactor *
          goldilocksOrder ^ (piopOpenings - 1) := by
    simpa [packingCard] using packingHitBound
  have scaledPcsHitBound :
      Fintype.card ExtraPcsHitTuple ≤
        piopOpenings * pcsUnstackAdditionalForbiddenValues *
          goldilocksOrder ^ (piopOpenings - 1) := by
    calc
      Fintype.card ExtraPcsHitTuple ≤
          piopOpenings * pcsAdditionalRootSet.card *
            goldilocksOrder ^ (piopOpenings - 1) := pcsHitBound
      _ ≤ piopOpenings * pcsUnstackAdditionalForbiddenValues *
            goldilocksOrder ^ (piopOpenings - 1) := by
        apply Nat.mul_le_mul_right
        exact Nat.mul_le_mul_left _ pcsRootBound
  calc
    Fintype.card InvalidOpeningTuple ≤ Fintype.card OpeningViolation :=
      Fintype.card_le_of_embedding invalidOpeningTupleEmbedding
    _ = Fintype.card PackingHitTuple + Fintype.card CollisionTuple +
          Fintype.card CorrectionZeroTuple + Fintype.card ExtraPcsHitTuple := by
      simp [OpeningViolation, add_assoc]
    _ ≤ piopOpenings * packingFactor * goldilocksOrder ^ (piopOpenings - 1) +
          15 * goldilocksOrder ^ (piopOpenings - 1) +
          correctionPolynomialDegree * goldilocksOrder ^ (piopOpenings - 1) +
          piopOpenings * pcsUnstackAdditionalForbiddenValues *
            goldilocksOrder ^ (piopOpenings - 1) := by
      omega
    _ = rawOpeningBadTupleCoefficient *
          goldilocksOrder ^ (piopOpenings - 1) := by
      unfold rawOpeningBadTupleCoefficient
      norm_num [Historical.piopOpenings, V8Smz9QromAccounting.piopOpenings]
      ring

abbrev OpeningTrialStream := Fin 16 → OpeningTuple
abbrev ExhaustedOpeningTrialStream := Fin 16 → InvalidOpeningTuple

theorem openingTuple_card :
    Fintype.card OpeningTuple = goldilocksOrder ^ piopOpenings := by
  simp only [OpeningTuple, OpeningIndex, Fintype.card_fun, Fintype.card_fin]
  rw [show Fintype.card Goldilocks = goldilocksOrder by
    rw [ZMod.card]
    rfl]

theorem openingTrialStream_card :
    Fintype.card OpeningTrialStream =
      (goldilocksOrder ^ piopOpenings) ^ 16 := by
  simp [OpeningTrialStream, openingTuple_card]

theorem exhaustedOpeningTrialStream_card :
    Fintype.card ExhaustedOpeningTrialStream =
      Fintype.card InvalidOpeningTuple ^ 16 := by
  simp [ExhaustedOpeningTrialStream]

/--
Cross-multiplied probability bound for sixteen independent uniform raw opening tuples.  This is
exactly `actualAbortRatio ≤ piopNonceAbortTerm`, without importing an analytic probability model.
-/
theorem sixteen_trial_nonce_abort_bound :
    Fintype.card ExhaustedOpeningTrialStream * piopNonceAbortTerm.denominator ≤
      piopNonceAbortTerm.numerator * Fintype.card OpeningTrialStream := by
  rw [exhaustedOpeningTrialStream_card, openingTrialStream_card]
  unfold piopNonceAbortTerm
  change
    Fintype.card InvalidOpeningTuple ^ 16 * goldilocksOrder ^ 16 ≤
      813 ^ 16 * (goldilocksOrder ^ piopOpenings) ^ 16
  have invalidBound := invalid_opening_tuple_card_le
  rw [exact_raw_opening_bad_tuple_coefficient] at invalidBound
  have poweredBound := Nat.pow_le_pow_left invalidBound 16
  calc
    Fintype.card InvalidOpeningTuple ^ 16 * goldilocksOrder ^ 16 ≤
        (813 * goldilocksOrder ^ (piopOpenings - 1)) ^ 16 *
          goldilocksOrder ^ 16 := Nat.mul_le_mul_right _ poweredBound
    _ = 813 ^ 16 * (goldilocksOrder ^ piopOpenings) ^ 16 := by
      norm_num [Historical.piopOpenings, V8Smz9QromAccounting.piopOpenings]
      ring

def fixedDecsSamplerAbortTerm : ExactNatRatio where
  numerator := 2 ^ 50 * 50 ^ 31
  denominator := decsDomainSize ^ 31

/--
Legacy conservative per-proof union diagnostic.  It deliberately repeats the already-full-history
CMS/SHA exposure term for every proof and mixes fail-closed completeness-abort terms into the same
ratio.  Consequently, `conditionalAnalysisHistory` and the `conditionalMaximum...` values below
are not the indexed global-once security composition and are not protocol-lifetime maxima.  The
generic `T`/`e(T)` adaptive-programming surface above and the separate QROM composition theorem are
the relevant lifetime interfaces.
-/
def conditionalPerProof : ExactNatRatio :=
  (((((correctedIdealCms analysisTotalSha512OracleExposures).add sha512PreimageTerm).add
      poseidon2CollisionTerm).add poseidon2PreimageTerm).add fieldXofAbortEnvelopeTerm).add
      piopNonceAbortTerm |>.add fixedDecsSamplerAbortTerm

def projectedPublicArgsBytes : Nat := V8Smz9QromAccounting.projectedTwoOutputActionBytes
def projectedPendingActionOverheadBytes : Nat := 225
def projectedPendingActionBytes : Nat :=
  projectedPublicArgsBytes + projectedPendingActionOverheadBytes
def blockActionByteCap : Nat := 64 * 1024 * 1024
def projectedProofsPerBlock : Nat := blockActionByteCap / projectedPendingActionBytes
abbrev consensusProofsPerBlock : Nat :=
  V8Smz9QromAccounting.consensusProofActionsPerBlock
abbrev analysisHistoryBlocks : Nat := V8Smz9QromAccounting.analysisHistoryBlocks

theorem exact_pending_action_byte_accounting :
    projectedPublicArgsBytes = 128297 ∧ projectedPendingActionOverheadBytes = 225 ∧
      projectedPendingActionBytes = 128522 ∧ blockActionByteCap = 67108864 ∧
      projectedProofsPerBlock = 522 ∧ consensusProofsPerBlock = 512 ∧
      blockActionByteCap % projectedPendingActionBytes = 20380 := by
  decide

theorem exact_analysis_history_interaction_count :
    analysisHistoryProofInteractions = 2097152 := by
  exact V8Smz9QromAccounting.exact_analysis_history_proof_interactions

theorem conditional_one_proof_supports_157_bits :
    conditionalPerProof.supportsBits 157 := by
  decide

theorem conditional_one_proof_does_not_support_158_bits :
    ¬ conditionalPerProof.supportsBits 158 := by
  decide

def conditionalAnalysisHistory : ExactNatRatio :=
  conditionalPerProof.scale analysisHistoryProofInteractions

theorem conditional_analysis_history_supports_136_bits :
    conditionalAnalysisHistory.supportsBits 136 := by
  decide

theorem conditional_analysis_history_does_not_support_137_bits :
    ¬ conditionalAnalysisHistory.supportsBits 137 := by
  decide

def fourEqualExternalTerms (bits : Nat) : ExactNatRatio where
  numerator := 4
  denominator := 2 ^ bits

def composedPerProof (externalBits : Nat) : ExactNatRatio :=
  conditionalPerProof.add (fourEqualExternalTerms externalBits)

def composedAnalysisHistory (externalBits : Nat) : ExactNatRatio :=
  (composedPerProof externalBits).scale analysisHistoryProofInteractions

theorem four_152_bit_external_terms_one_proof_supports_149_bits :
    (composedPerProof 152).supportsBits 149 := by
  decide

theorem four_152_bit_external_terms_one_proof_does_not_support_150_bits :
    ¬ (composedPerProof 152).supportsBits 150 := by
  decide

theorem four_152_bit_external_terms_history_supports_128_bits :
    (composedAnalysisHistory 152).supportsBits 128 := by
  decide

theorem four_152_bit_external_terms_history_does_not_support_129_bits :
    ¬ (composedAnalysisHistory 152).supportsBits 129 := by
  decide

theorem four_151_bit_external_terms_history_supports_127_bits :
    (composedAnalysisHistory 151).supportsBits 127 := by
  decide

theorem four_151_bit_external_terms_history_does_not_support_128_bits :
    ¬ (composedAnalysisHistory 151).supportsBits 128 := by
  decide

def conditionalMaximumProofsAt128 : Nat :=
  conditionalPerProof.maximumUnionCountAtBits 128

def four152MaximumProofsAt128 : Nat :=
  (composedPerProof 152).maximumUnionCountAtBits 128

def four151MaximumProofsAt128 : Nat :=
  (composedPerProof 151).maximumUnionCountAtBits 128

theorem exact_conditional_maximum_proofs_at_128 :
    conditionalMaximumProofsAt128 = 621728502 := by
  decide

theorem conditional_maximum_supports_128_bits :
    (conditionalPerProof.scale conditionalMaximumProofsAt128).supportsBits 128 := by
  decide

theorem conditional_maximum_successor_does_not_support_128_bits :
    ¬ (conditionalPerProof.scale (conditionalMaximumProofsAt128 + 1)).supportsBits 128 := by
  decide

theorem exact_four152_maximum_proofs_at_128 :
    four152MaximumProofsAt128 = 4166198 := by
  decide

theorem four152_maximum_supports_128_bits :
    ((composedPerProof 152).scale four152MaximumProofsAt128).supportsBits 128 := by
  decide

theorem four152_maximum_successor_does_not_support_128_bits :
    ¬ ((composedPerProof 152).scale (four152MaximumProofsAt128 + 1)).supportsBits 128 := by
  decide

theorem exact_four151_maximum_proofs_at_128 :
    four151MaximumProofsAt128 = 2090101 := by
  decide

theorem four151_maximum_supports_128_bits :
    ((composedPerProof 151).scale four151MaximumProofsAt128).supportsBits 128 := by
  decide

theorem four151_maximum_successor_does_not_support_128_bits :
    ¬ ((composedPerProof 151).scale (four151MaximumProofsAt128 + 1)).supportsBits 128 := by
  decide

/-! ## Ideal opening-sampling evidence and deployed adaptive bridge boundary -/

/--
Constructive evidence for the finite ideal sampler only.  The fields bind the exact six-opening
predicate used by the algebraic SMZ9 maps to the conservative denominator and sixteen-trial abort
term.  They do not bind canonical bytes, SHA-512, a random oracle, or production execution.
-/
structure CorrectionAwareOpeningSamplingRefinement : Prop where
  sixOpenings : piopOpenings = 6
  packingPoints : packingDomain.card = 64
  correctionDegree : correctionPolynomial.totalDegree ≤ 6
  correctionNonzero : correctionPolynomial ≠ 0
  pcsFactorRootBounds :
    (pcsRootSet 64).card ≤ 64 ∧
      (pcsRootSet 35).card ≤ 5 ∧
      (pcsRootSet 63).card ≤ 3
  pcsAdditionalRoots : pcsAdditionalRootSet.card ≤ 68
  exactAcceptedPredicate :
    ∀ accepted : FullAdmissibleOpeningTuple,
      CorrectionAwareOpeningPredicate (baseOpeningPoints accepted.1)
  acceptedTupleLowerBound :
    correctionAwareOpeningTupleLowerBound ≤
      Fintype.card FullAdmissibleOpeningTuple
  rawTrialBadTupleBound :
    Fintype.card InvalidOpeningTuple ≤
      813 * goldilocksOrder ^ (piopOpenings - 1)
  sixteenTrialAbortBound :
    Fintype.card ExhaustedOpeningTrialStream * piopNonceAbortTerm.denominator ≤
      piopNonceAbortTerm.numerator * Fintype.card OpeningTrialStream

theorem correction_aware_opening_sampling_refinement :
    CorrectionAwareOpeningSamplingRefinement where
  sixOpenings := by decide
  packingPoints := by simpa [Historical.packingFactor] using packingDomain_card
  correctionDegree := by
    simpa [correctionPolynomialDegree, Historical.piopOpenings] using
      correctionPolynomial_totalDegree_le
  correctionNonzero := correctionPolynomial_ne_zero
  pcsFactorRootBounds :=
    ⟨pcsRootSet64_card_le, pcsRootSet35_card_le, pcsRootSet63_card_le⟩
  pcsAdditionalRoots := pcs_additional_root_set_card_le
  exactAcceptedPredicate := full_admissible_satisfies_exact_predicate
  acceptedTupleLowerBound := full_admissible_opening_tuple_card_lower_bound
  rawTrialBadTupleBound := by
    simpa [exact_raw_opening_bad_tuple_coefficient] using invalid_opening_tuple_card_le
  sixteenTrialAbortBound := sixteen_trial_nonce_abort_bound

inductive ConcreteSha512FiatShamirQromReduction : Prop
inductive Poseidon2PrimitiveSecurityReduction : Prop
inductive AdaptiveWholeViewCompleteZeroKnowledge : Prop
inductive ProtocolLifetimeGlobalQueryBudgetBinding : Nat → Nat → Prop
/-- Lifetime binding for `T` as every observed/generated honest proof view, not accepted actions. -/
inductive ProtocolLifetimeGlobalQueryAndObservedViewBudgetBinding : Nat → Nat → Prop
inductive ExactV8RelationAndSmz9TranscriptRefinement : Prop
inductive AuthenticatedIndependentGlobalSha512QromReview : Prop
/-- Identifies the real quantity bounded below with the exact indexed logical-QROM failure event. -/
inductive ExactSmz9IndexedLogicalFailureProbabilityIdentification : ℝ → Prop

/-- The exact PQ128 target used by the conditional global SHA-512 lifetime theorem. -/
def globalSha512QromLifetimeFailureProbabilityTarget : ℝ :=
  1 / (2 : ℝ) ^ 128

/--
Additional exact adaptive-programming and external-reduction terms.  The ideal-CMS and primitive
terms are fixed source functions of the same global `(Q,T)` in `exactComposedRatio`; callers cannot
replace them with an unrelated real-valued bound.
-/
structure GlobalSha512QromLifetimeComposedTerms
    (globalQuantumQueries observedHonestProofViews : Nat) where
  adaptiveProgramming : V8Smz9QromAccounting.CompositionRatio
  explicitReductionLoss : V8Smz9QromAccounting.CompositionRatio

def exactComposedRatio
    (globalQuantumQueries observedHonestProofViews : Nat)
    (terms : GlobalSha512QromLifetimeComposedTerms
      globalQuantumQueries observedHonestProofViews) :
    V8Smz9QromAccounting.CompositionRatio :=
  (((V8Smz9QromAccounting.globalIdealCmsRatio
      globalQuantumQueries observedHonestProofViews).add
    (V8Smz9QromAccounting.primitiveRemainderRatio
      globalQuantumQueries observedHonestProofViews)).add
    terms.adaptiveProgramming).add terms.explicitReductionLoss

def exactComposedBound
    (globalQuantumQueries observedHonestProofViews : Nat)
    (terms : GlobalSha512QromLifetimeComposedTerms
      globalQuantumQueries observedHonestProofViews) : ℝ :=
  ((exactComposedRatio globalQuantumQueries observedHonestProofViews terms).numerator : ℝ) /
    (exactComposedRatio globalQuantumQueries observedHonestProofViews terms).denominator

/-- Event/refinement evidence that the indexed failure probability is bounded by the exact
`(Q,T,terms)` composition. -/
structure GlobalSha512QromLifetimeEventReductionBound
    (globalQuantumQueries observedHonestProofViews : Nat)
    (terms : GlobalSha512QromLifetimeComposedTerms
      globalQuantumQueries observedHonestProofViews)
    (failureProbability : ℝ) : Prop where
  failureProbabilityLeExactComposedBound :
    failureProbability ≤
      exactComposedBound globalQuantumQueries observedHonestProofViews terms

/-- Arithmetic evidence, separate from the event/refinement bound, that the exact composed ratio
meets the 128-bit target. -/
structure GlobalSha512QromLifetimeQuantitativeBound
    (globalQuantumQueries observedHonestProofViews : Nat)
    (terms : GlobalSha512QromLifetimeComposedTerms
      globalQuantumQueries observedHonestProofViews) : Prop where
  exactGlobalQueryBudget : globalQuantumQueries = analysisGlobalQueryBudget
  exposureExponentFitsSha512 : totalOracleExposureExponent observedHonestProofViews ≤ 512
  exactComposedDenominatorPositive :
    0 < (exactComposedRatio globalQuantumQueries observedHonestProofViews terms).denominator
  exactComposedBoundLeTarget :
    exactComposedBound globalQuantumQueries observedHonestProofViews terms ≤
      globalSha512QromLifetimeFailureProbabilityTarget

/--
Every premise needed before the exact theorem name recorded by the release checker may be cited.
The three logical-oracle bridges are the separately named constructor-free SMZ9 transition,
failure-selector, and CMS-instability refinements.  The SHA-to-indexed-product reduction, concrete
Fiat-Shamir reduction, exact identification of the bounded real with the indexed failure event,
adaptive whole-view privacy, global `(Q,T)` binding, quantitative bound, and authenticated
independent review are also explicit and are not manufactured here.
-/
structure DeployedSmz9GlobalSha512QromLifetimePremises where
  globalQuantumQueries : Nat
  observedHonestProofViews : Nat
  failureProbability : ℝ
  composedTerms :
    GlobalSha512QromLifetimeComposedTerms globalQuantumQueries observedHonestProofViews
  correctionAwareOpeningSamplingRefinement : CorrectionAwareOpeningSamplingRefinement
  exactRelationAndTranscriptRefinement : ExactV8RelationAndSmz9TranscriptRefinement
  exactSmz9RoundTransitionRefinement :
    V8Smz9LogicalOracle.ExactSmz9RoundTransitionRefinement
  exactSmz9FailureSelectorRefinement :
    V8Smz9LogicalOracle.ExactSmz9FailureSelectorRefinement
  exactSmz9CmsInstability : V8Smz9LogicalOracle.ExactSmz9CmsInstability
  indexedLogicalFailureProbabilityIdentification :
    ExactSmz9IndexedLogicalFailureProbabilityIdentification failureProbability
  sha512ToIndexedProductOracleReduction :
    HeterogeneousCmsQrom.Sha512ToIndexedProductOracleReduction
  concreteSha512FiatShamirQromReduction : ConcreteSha512FiatShamirQromReduction
  adaptiveWholeViewCompleteZeroKnowledge : AdaptiveWholeViewCompleteZeroKnowledge
  protocolLifetimeBudgetBinding :
    ProtocolLifetimeGlobalQueryAndObservedViewBudgetBinding
      globalQuantumQueries observedHonestProofViews
  eventReductionBound :
    GlobalSha512QromLifetimeEventReductionBound
      globalQuantumQueries observedHonestProofViews composedTerms failureProbability
  quantitativeBound :
    GlobalSha512QromLifetimeQuantitativeBound
      globalQuantumQueries observedHonestProofViews composedTerms
  independentReview : AuthenticatedIndependentGlobalSha512QromReview

/--
Premise-conditional theorem matching the release-checker identifier.  Its result is deliberately
tagged `conditionalSupply`, never `deployedEndToEnd`: the theorem consumes all SMZ9 indexed-oracle,
SHA-512, adaptive-privacy, lifetime-budget, quantitative, and review evidence but constructs none
of it and does not mint a production receipt.
-/
theorem deployed_smz9_global_sha512_qrom_lifetime_failure_probability_le
    (premises : DeployedSmz9GlobalSha512QromLifetimePremises) :
    HegemonCrypto.SecurityAuthority.ScopedSecurityClaim .conditionalSupply
      (premises.failureProbability ≤ globalSha512QromLifetimeFailureProbabilityTarget) := by
  exact HegemonCrypto.SecurityAuthority.ScopedSecurityClaim.ofConditionalSupply
    (premises.eventReductionBound.failureProbabilityLeExactComposedBound.trans
      premises.quantitativeBound.exactComposedBoundLeTarget)

theorem deployed_smz9_global_sha512_qrom_lifetime_premises_are_unavailable :
    ¬ Nonempty DeployedSmz9GlobalSha512QromLifetimePremises := by
  intro available
  rcases available with ⟨premises⟩
  exact V8Smz9LogicalOracle.exact_smz9_round_transition_refinement_is_unavailable
    premises.exactSmz9RoundTransitionRefinement

theorem global_qrom_lifetime_receipt_is_not_constructed_by_finite_accounting
    (globalQuantumQueries totalProofInteractions : Nat) :
    ¬ ProtocolLifetimeGlobalQueryBudgetBinding
        globalQuantumQueries totalProofInteractions := by
  intro evidence
  exact nomatch evidence

/--
The missing deployed specialization of
`SmallWoodHeterogeneousCmsQrom.indexed_ideal_logical_qrom_failure_probability_le`.
`globalQuantumQueries` is one protocol-lifetime total, not a per-proof allowance, and
`totalProofInteractions` is not reset by the stablecoin state epoch.
-/
structure DeployedAdaptiveFiniteProofPremises where
  globalQuantumQueries : Nat
  totalProofInteractions : Nat
  correctionAwareOpeningSamplingRefinement : CorrectionAwareOpeningSamplingRefinement
  exactRelationAndTranscriptRefinement : ExactV8RelationAndSmz9TranscriptRefinement
  concreteSha512FiatShamirQromReduction : ConcreteSha512FiatShamirQromReduction
  poseidon2PrimitiveSecurityReduction : Poseidon2PrimitiveSecurityReduction
  adaptiveWholeViewCompleteZeroKnowledge : AdaptiveWholeViewCompleteZeroKnowledge
  protocolLifetimeBudgetBinding :
    ProtocolLifetimeGlobalQueryBudgetBinding globalQuantumQueries totalProofInteractions

theorem deployed_adaptive_finite_proof_premises_are_unavailable :
    ¬ Nonempty DeployedAdaptiveFiniteProofPremises := by
  intro available
  rcases available with ⟨premises⟩
  exact nomatch premises.exactRelationAndTranscriptRefinement

end
end V8Smz9AdaptiveFiniteAccounting
end SmallWood
end HegemonCrypto
