import HegemonCrypto.CmsQuerySequence
import Mathlib.Analysis.Real.Sqrt
import Mathlib.Tactic.Linarith

/-!
# Exact CMS lifting arithmetic

This module records the concrete inequalities in the Chiesa-Manohar-Spooner lifting argument
without asymptotic notation or invented constants.

The database-game proof has two mathematical steps:

1. a telescoping argument bounds final winning amplitude by `q` times a one-query transition
   amplitude;
2. the local compressed-oracle operator lemma bounds the square of that transition amplitude by
   `6 * instability`.

Their composition is the exact database-game probability bound `6 * q^2 * instability`.
`CmsQuerySequence` proves this bound for the implemented compressed-oracle kernel and raw
reachable execution.  The oracle-game bridge then adds the paper's square-root term before
squaring; the arithmetic composition in this file is kept separate from the oracle-simulation
theorem so an inequality premise cannot be mistaken for its proof.
-/

namespace HegemonCrypto.CmsLifting

noncomputable section

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsQuerySequence

/-- Exact right-hand side of CMS Lemma 6/9 for a database game. -/
def databaseLoss
    (queries : Nat)
    (instability : ℝ) : ℝ :=
  6 * (queries : ℝ) ^ 2 * instability

/--
The exact algebraic composition of the telescoping and local-operator inequalities.  This is where
the concrete factor `6` and the quadratic query loss enter; no hidden multiplier remains.
-/
theorem database_lifting_from_local_operator
    (queries : Nat)
    (instability transitionAmplitude winningAmplitude : ℝ)
    (transitionAmplitudeNonnegative : 0 <= transitionAmplitude)
    (winningAmplitudeNonnegative : 0 <= winningAmplitude)
    (telescoping :
      winningAmplitude <= (queries : ℝ) * transitionAmplitude)
    (localOperator :
      transitionAmplitude ^ 2 <= 6 * instability) :
    winningAmplitude ^ 2 <= databaseLoss queries instability := by
  have queryNonnegative : (0 : ℝ) <= queries := by positivity
  have productNonnegative :
      0 <= (queries : ℝ) * transitionAmplitude :=
    mul_nonneg queryNonnegative transitionAmplitudeNonnegative
  have squaredTelescoping :
      winningAmplitude ^ 2 <=
        ((queries : ℝ) * transitionAmplitude) ^ 2 := by
    simpa [pow_two] using
      mul_self_le_mul_self winningAmplitudeNonnegative telescoping
  calc
    winningAmplitude ^ 2 <=
        ((queries : ℝ) * transitionAmplitude) ^ 2 :=
      squaredTelescoping
    _ = (queries : ℝ) ^ 2 * transitionAmplitude ^ 2 := by ring
    _ <= (queries : ℝ) ^ 2 * (6 * instability) := by
      exact mul_le_mul_of_nonneg_left localOperator (sq_nonneg (queries : ℝ))
    _ = databaseLoss queries instability := by
      unfold databaseLoss
      ring

section ImplementedDatabaseGame

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/--
The exact database loss applies to the raw implemented compressed-oracle execution.  The support
projections used in the proof are identities for an empty-database initial state and at most
`queryBound` calls.
-/
theorem implemented_raw_database_game_le_database_loss
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    {instabilityBound : ℝ}
    (instability : RealInstabilityBound property queryBound instabilityBound)
    (queryCapacity : steps.length <= queryBound)
    (emptyDatabaseSupport : BoundedState 0 state)
    (subnormalized : Subnormalized state)
    (initiallyOutside :
      project property queryBound state = 0) :
    normSquared
        (project property queryBound
          (rawRun system queryBound steps state)) <=
      databaseLoss steps.length instabilityBound := by
  exact raw_database_game_probability_le
    system property queryBound steps state instability queryCapacity
      emptyDatabaseSupport subnormalized initiallyOutside

end ImplementedDatabaseGame

/-- Exact CMS conditional-instability sum used in Lemma 9. -/
def conditionalInstability
    (gameGivenGoodDatabase collisionInstability : ℝ) : ℝ :=
  gameGivenGoodDatabase + collisionInstability

theorem conditional_database_lifting_from_local_operator
    (queries : Nat)
    (gameGivenGoodDatabase collisionInstability transitionAmplitude
      winningAmplitude : ℝ)
    (transitionAmplitudeNonnegative : 0 <= transitionAmplitude)
    (winningAmplitudeNonnegative : 0 <= winningAmplitude)
    (telescoping :
      winningAmplitude <= (queries : ℝ) * transitionAmplitude)
    (localOperator :
      transitionAmplitude ^ 2 <=
        6 * conditionalInstability gameGivenGoodDatabase collisionInstability) :
    winningAmplitude ^ 2 <=
      databaseLoss queries
        (conditionalInstability gameGivenGoodDatabase collisionInstability) := by
  exact database_lifting_from_local_operator
    queries
    (conditionalInstability gameGivenGoodDatabase collisionInstability)
    transitionAmplitude
    winningAmplitude
    transitionAmplitudeNonnegative
    winningAmplitudeNonnegative
    telescoping
    localOperator

/--
The oracle-to-database bridge term from CMS Lemma 1.  `baseGameArity` is the number of
oracle input-output pairs whose presence certifies a win; `outputCardinality` is `2^n` for an
`n`-bit random oracle.
-/
def oracleBridgeLoss
    (baseGameArity : Nat)
    (outputCardinality : ℝ) : ℝ :=
  (baseGameArity : ℝ) / outputCardinality

/-- Exact oracle-game loss after the square-root bridge is applied. -/
def oracleLoss
    (databaseGameLoss bridgeLoss : ℝ) : ℝ :=
  (Real.sqrt databaseGameLoss + Real.sqrt bridgeLoss) ^ 2

/--
Squaring the CMS Lemma 1 amplitude inequality is sound because both sides are nonnegative.
-/
theorem oracle_to_database_transfer
    (oracleGameLoss databaseGameLoss bridgeLoss : ℝ)
    (oracleNonnegative : 0 <= oracleGameLoss)
    (amplitudeTransfer :
      Real.sqrt oracleGameLoss <=
        Real.sqrt databaseGameLoss + Real.sqrt bridgeLoss) :
    oracleGameLoss <= oracleLoss databaseGameLoss bridgeLoss := by
  have squareBound :
      (Real.sqrt oracleGameLoss) ^ 2 <=
        (Real.sqrt databaseGameLoss + Real.sqrt bridgeLoss) ^ 2 := by
    simpa [pow_two] using
      mul_self_le_mul_self (Real.sqrt_nonneg oracleGameLoss) amplitudeTransfer
  calc
    oracleGameLoss = (Real.sqrt oracleGameLoss) ^ 2 := by
      symm
      exact Real.sq_sqrt oracleNonnegative
    _ <= (Real.sqrt databaseGameLoss + Real.sqrt bridgeLoss) ^ 2 :=
      squareBound
    _ = oracleLoss databaseGameLoss bridgeLoss := rfl

/--
Rational security ledgers can conservatively eliminate square roots using
`(sqrt a + sqrt b)^2 <= 2a + 2b`.  This costs at most one bit and does not hide a
floating-point approximation.
-/
theorem oracle_loss_le_two_sum
    (databaseGameLoss bridgeLoss : ℝ)
    (databaseNonnegative : 0 <= databaseGameLoss)
    (bridgeNonnegative : 0 <= bridgeLoss) :
    oracleLoss databaseGameLoss bridgeLoss <=
      2 * databaseGameLoss + 2 * bridgeLoss := by
  have databaseSquare :
      (Real.sqrt databaseGameLoss) ^ 2 = databaseGameLoss :=
    Real.sq_sqrt databaseNonnegative
  have bridgeSquare :
      (Real.sqrt bridgeLoss) ^ 2 = bridgeLoss :=
    Real.sq_sqrt bridgeNonnegative
  have squareDifference :
      0 <= (Real.sqrt databaseGameLoss - Real.sqrt bridgeLoss) ^ 2 :=
    sq_nonneg _
  unfold oracleLoss
  nlinarith

/-- Final exact form after applying both the factor-6 database lifting and Lemma 1. -/
def completeOracleLoss
    (queries : Nat)
    (instability : ℝ)
    (baseGameArity : Nat)
    (outputCardinality : ℝ) : ℝ :=
  oracleLoss
    (databaseLoss queries instability)
    (oracleBridgeLoss baseGameArity outputCardinality)

theorem complete_oracle_loss_is_exact
    (queries : Nat)
    (instability : ℝ)
    (baseGameArity : Nat)
    (outputCardinality : ℝ) :
    completeOracleLoss queries instability baseGameArity outputCardinality =
      (Real.sqrt (6 * (queries : ℝ) ^ 2 * instability) +
        Real.sqrt ((baseGameArity : ℝ) / outputCardinality)) ^ 2 := by
  rfl

theorem database_loss_nonnegative
    (queries : Nat)
    {instability : ℝ}
    (instabilityNonnegative : 0 <= instability) :
    0 <= databaseLoss queries instability := by
  unfold databaseLoss
  positivity

theorem oracle_bridge_loss_nonnegative
    (baseGameArity : Nat)
    {outputCardinality : ℝ}
    (outputCardinalityNonnegative : 0 <= outputCardinality) :
    0 <= oracleBridgeLoss baseGameArity outputCardinality := by
  unfold oracleBridgeLoss
  positivity

end

end HegemonCrypto.CmsLifting
