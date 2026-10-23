import HegemonCrypto.NativePrivateSpendQ58CurrentTotalNativeSourceOutcome
import HegemonCrypto.NativePrivateSpendQ58CurrentPersistentHistory
import HegemonCrypto.NativePrivateSpendQ58SharedQueryLifetime

/-!
# Ongoing HGN operation: explicit adversary resources, no chain expiry

The historical `2^21` specialization remains unchanged. This additive module
retains the actual current G3 soundness/custody theorem with its seven primitive
games, widens the actual persistent-history G4 privacy specialization, and checks
the source-inclusive G5 resource class. No block-height, accepted-transaction,
restart, epoch or runtime limiter is used to enforce these security assumptions.

These are conditional finite-resource theorems, not unlimited-adversary claims.
The actual native/source interpretation (F1), ideal oracle/coins, compiler and
primitive assumptions and external adaptive reprogramming remain explicit in
the inherited endpoints. The soundness and privacy bounds are separate games;
their individual bounds are not a claim that their union is below `2^-128`.
-/

namespace HegemonCrypto.SmallWood.NativePrivateSpendOngoingSecurity

open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9MixedMaskCompiler V8Smz9MeasuredRunContinuity
open Q38WholeViewCmsSemantics
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentInitializedPublic
open NativePrivateSpendQ58CurrentOriginalRequest NativePrivateSpendQ58CurrentHistoryMass
open NativePrivateSpendQ58CurrentHistoryContinuation
open NativePrivateSpendQ58CurrentFreshAccounting NativePrivateSpendQ58CurrentFreshInitialized
open NativePrivateSpendQ58CurrentPersistentHistory
open NativePrivateSpendQ58SharedQueryLifetime
open scoped Classical BigOperators ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- A theorem-resource class, never an accepted-chain counter. Honest and
adversarial prehistory, selection and fixed-write retrievals share one budget.
Failed, unused and successful attempts all count. Repeated verification is
charged, as is the optional full verifier trace. -/
def ResourceClass (resources : Resources) : Prop :=
  resources.prehistory + resources.adversary + resources.selection +
      resources.fixedWriteReads ≤ 2^65 ∧
    resources.proofAttempts ≤ 2^39 ∧
    resources.verificationAttempts ≤ 2^39 ∧
    resources.traceAttempts ≤ 2^39

def maximumResources : Resources :=
  ⟨2^64, 2^64, 0, 0, 2^39, 2^39, 2^39⟩

theorem maximum_resources_in_class : ResourceClass maximumResources := by
  norm_num [ResourceClass, maximumResources]

/-- All source consumers share one unchanged oracle. This accounting charges
the literal conservative source read caps already defined in the inherited
source-inclusive module; it does not assert Rust equivalence. -/
theorem source_inclusive_resource_bound (resources : Resources)
    (bounded : ResourceClass resources) :
    chargedQueries resources ≤ 3 * 2^64 := by
  rcases bounded with ⟨ordinary, provers, verifiers, traces⟩
  rcases exact_source_caps with ⟨_, _, proverCap, verifierCap, traceCap⟩
  have p := Nat.mul_le_mul_right proverReadCap provers
  have v := Nat.mul_le_mul_right verifierReadCap verifiers
  have t := Nat.mul_le_mul_right verifierTraceReadCap traces
  unfold chargedQueries
  simp only [proverCap, verifierCap, traceCap] at p v t ⊢
  omega

theorem exact_maximum_source_inclusive_queries :
    chargedQueries maximumResources = 47966103502262894592 := by
  rcases exact_source_caps with ⟨_, _, proverCap, verifierCap, traceCap⟩
  norm_num [chargedQueries, maximumResources, proverCap, verifierCap, traceCap]

theorem source_query_headroom :
    3 * 2^64 - chargedQueries maximumResources = 7374128718865760256 := by
  rw [exact_maximum_source_inclusive_queries]
  norm_num

/-- Generic inherited loss, with arbitrary finite M. No `2^21` restriction
occurs in the source theorem to which this expression is applied. -/
def privacyLoss (queries requests : Nat) : ℝ :=
  freshLifetimeLoss queries + (requests : ℝ) * erasureLoss queries

/-- The widened quantitative privacy class retains more than149 bits for
this loss term at the SAME global oracle-query cap. It does not independently
discharge the primitive games or production/source-authorization boundary. -/
theorem privacy_loss_below_149 (queries requests : Nat)
    (queryBudget : queries ≤ 3 * 2^64) (requestBudget : requests ≤ 2^39) :
    privacyLoss queries requests < (2 : ℝ)^(-149 : ℤ) := by
  have qBound : (queries : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by exact_mod_cast queryBudget
  have mBound : (requests : ℝ) ≤ ((2^39 : Nat) : ℝ) := by exact_mod_cast requestBudget
  have squareBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ ≤ ((2 : ℝ)^(-223 : ℤ))^2 := by
    calc
      _ ≤ ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_right qBound (by positivity)
      _ ≤ _ := by
        rw [show (2 ^ 512 : ℝ) = (2 ^ 256 : ℝ)^2 from pow_mul (2 : ℝ) 256 2]
        norm_num
  have rootBound : Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) ≤ (2 : ℝ)^(-223 : ℤ) :=
    Real.sqrt_le_iff.mpr ⟨by positivity, squareBound⟩
  have linearBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 ≤
      ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 :=
    div_le_div_of_nonneg_right (mul_le_mul_of_nonneg_right qBound (by positivity)) (by norm_num)
  have freshRounded : freshLifetimeLoss queries < (2 : ℝ)^(-157 : ℤ) := by
    unfold freshLifetimeLoss
    calc
      _ ≤ (queries : ℝ) * ((2 : ℝ)^(-223 : ℤ) + ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
        mul_le_mul_of_nonneg_left (add_le_add rootBound linearBound) (Nat.cast_nonneg _)
      _ ≤ ((3 * 2^64 : Nat) : ℝ) *
          ((2 : ℝ)^(-223 : ℤ) + ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
        mul_le_mul_of_nonneg_right qBound (by positivity)
      _ < _ := by
        rw [show (2 ^ 512 : ℝ) = (2 ^ 256 : ℝ)^2 from pow_mul (2 : ℝ) 256 2]
        norm_num
  have erasureRounded : (requests : ℝ) * erasureLoss queries ≤
      ((2^39 : Nat) : ℝ) * (4 * ((3 * 2^64 : Nat) : ℝ) / (2 ^ 256 : ℝ)) := by
    apply mul_le_mul mBound _ (erasure_loss_nonnegative queries) (by positivity)
    unfold erasureLoss
    exact div_le_div_of_nonneg_right (mul_le_mul_of_nonneg_left qBound (by norm_num)) (by positivity)
  exact (add_lt_add_of_lt_of_le freshRounded erasureRounded).trans (by norm_num)

section PersistentPrivacy
variable {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]

/-- Actual initialized persistent-oracle privacy, including all failed/unused
attempts, error continuations and arbitrary intervening operations. Reuses the
unchanged generic PR205-derived source theorem, not a fresh per-proof game. -/
theorem current_initialized_history_below_149 {requests : Nat}
    (schedule : Schedule bound Work requests)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := CurrentInput bound) (Work := Work))
    (queries : Nat)
    (registers : RegisterBasis (Input := CurrentInput bound)
      (Phase := DigestRegister) (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := CurrentInput bound) (Work := Work))‖ = 1)
    (realQueries : queryCount (realHistory schedule) ≤ queries)
    (publicQueries : queryCount (publicHistory schedule) ≤ queries)
    (callerClass : ContinuationQueries queries schedule)
    (queryBudget : queries ≤ 3 * 2^64) (requestBudget : requests ≤ 2^39) :
    |actualPhaseRun queries false (compile (realHistory schedule) []) (emptyCMS registers) -
      actualPhaseRun queries true (compile (publicHistory schedule) []) (emptyCMS registers)| <
      (2 : ℝ)^(-149 : ℤ) :=
  (current_initialized_history_bound schedule ghhm queries registers normalized
    realQueries publicQueries callerClass).trans_lt
      (privacy_loss_below_149 queries requests queryBudget requestBudget)

end PersistentPrivacy

/- Exact unchanged full current G3 composition. It retains the seven explicit
native primitive games and their remaining advantage budget, normalized original
execution, source/read correspondence and inclusive Q bound. Its type has NO
request-count M bound, no height expiry and no accepted-chain quota. This alias
does not strengthen any primitive or native implementation assumption. -/
export NativePrivateSpendQ58CurrentTotalNativeSourceOutcome.Collector
  (initialized_actual_native_global_failure_below_128)

end
end HegemonCrypto.SmallWood.NativePrivateSpendOngoingSecurity
