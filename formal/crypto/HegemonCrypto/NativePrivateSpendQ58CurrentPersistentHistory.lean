import HegemonCrypto.NativePrivateSpendQ58CurrentHistoryContinuation
import HegemonCrypto.NativePrivateSpendQ58CurrentFreshInitialized

/-! One initialized persistent-oracle history of literal current SMZD calls.
The finite adversary syntax includes all query families, arbitrary gates,
complete instruments, random draws and fixed writes. Requests can stop early;
every success/error continuation is present. Q is a whole-program adversary
complexity class, and M is the disclosed proof-attempt class, not a runtime
limiter. Exactly one global fresh hop precedes the derived request induction. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPersistentHistory
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
open scoped Classical BigOperators ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- A fixed finite adaptive strategy. Private witnesses occur only in the
request data. Both executions use this same strategy and response interface. -/
inductive Schedule (bound : Nat) (Work : Type) [Fintype Work] : Nat → Type 1 where
  | finish {requests : Nat} (event : Finset (QueryBasis (CurrentInput bound) DigestRegister Work)) :
      Schedule bound Work requests
  | gate {requests : Nat} (operation : V8Smz9HonestWholeViewGames.GameGate
      (Input := CurrentInput bound) (Work := Work))
      (next : Schedule bound Work requests) : Schedule bound Work requests
  | quantumQuery {requests : Nat} (next : Schedule bound Work requests) : Schedule bound Work requests
  | honestRead {requests : Nat} (input : CurrentInput bound)
      (next : DigestRegister → Schedule bound Work requests) : Schedule bound Work requests
  | instrument {requests count : Nat} (operation : V8Smz9HonestWholeViewGames.Instrument
      (CurrentInput bound) Work count) (next : Fin count → Schedule bound Work requests) :
      Schedule bound Work requests
  | random {requests : Nat} (source : V8Smz9HonestWholeViewGames.RandomSource)
      (next : source.Coins → Schedule bound Work requests) : Schedule bound Work requests
  | write {requests : Nat} (input : CurrentInput bound) (answer : DigestRegister)
      (next : Schedule bound Work requests) : Schedule bound Work requests
  | request {requests : Nat} (data : RequestData bound)
      (next : Context → Except String PublicResult → Schedule bound Work requests) :
      Schedule bound Work (requests + 1)

def realHistory : {requests : Nat} → Schedule bound Work requests → MixedProgram (CurrentInput bound) Work
  | _, .finish event => .finish event
  | _, .gate operation next => .gate operation (realHistory next)
  | _, .quantumQuery next => .quantumQuery (realHistory next)
  | _, .honestRead input next => .honestRead input (fun answer => realHistory (next answer))
  | _, .instrument operation next => .instrument operation (fun outcome => realHistory (next outcome))
  | _, .random source next => .random source (fun coins => realHistory (next coins))
  | _, .write input answer next => .write input answer (realHistory next)
  | _, .request data next => sourceRequest data (fun context outcome => realHistory (next context outcome))

def publicHistory : {requests : Nat} → Schedule bound Work requests → MixedProgram (CurrentInput bound) Work
  | _, .finish event => .finish event
  | _, .gate operation next => .gate operation (publicHistory next)
  | _, .quantumQuery next => .quantumQuery (publicHistory next)
  | _, .honestRead input next => .honestRead input (fun answer => publicHistory (next answer))
  | _, .instrument operation next => .instrument operation (fun outcome => publicHistory (next outcome))
  | _, .random source next => .random source (fun coins => publicHistory (next coins))
  | _, .write input answer next => .write input answer (publicHistory next)
  | _, .request data next => NativePrivateSpendQ58CurrentHistoryMass.publicRequest data
      (fun context outcome => publicHistory (next context outcome))

/-- Uniform caller-query class over every public input, including error inputs
that may be supplied to the current request comparison. This is syntactic query
complexity, not a game-distance or source-correspondence premise. The separate
whole real/public query bounds below charge all preceding work too. -/
def ContinuationQueries (queries : Nat) : {requests : Nat} → Schedule bound Work requests → Prop
  | _, .finish _ => True
  | _, .gate _ next => ContinuationQueries queries next
  | _, .quantumQuery next => ContinuationQueries queries next
  | _, .honestRead _ next => ∀ answer, ContinuationQueries queries (next answer)
  | _, .instrument _ next => ∀ outcome, ContinuationQueries queries (next outcome)
  | _, .random _ next => ∀ coins, ContinuationQueries queries (next coins)
  | _, .write _ _ next => ContinuationQueries queries next
  | _, .request _ next =>
      (∀ context outcome, V8Smz9HonestWholeViewGames.queryCount
        (compile (realHistory (next context outcome)) []) ≤ queries) ∧
      ∀ context outcome, ContinuationQueries queries (next context outcome)

/-- Every actual fresh sampler in the complete real history is a current raw
64-byte taped leaf. Gates, instruments and error continuations add no premise. -/
theorem real_history_mass {requests : Nat} (schedule : Schedule bound Work requests) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (realHistory schedule) := by
  induction schedule with
  | finish event => trivial
  | gate operation next ih => exact ih
  | quantumQuery next ih => exact ih
  | honestRead input next ih => exact ih
  | instrument operation next ih => exact ih
  | random source next ih => exact ih
  | write input answer next ih => exact ih
  | request data next ih =>
      exact original_request_mass data.largeEnough data.relation data.values
        data.statement data.salt data.binding _ ih

/-- Forward telescoping at each literal request. The second leg is proved by
current simulator continuation transport; no adjacent-hybrid bound is assumed.
All prior public writes and all continuing Born branches retain one raw table. -/
theorem all_history_erasure_bound {requests : Nat}
    (schedule : Schedule bound Work requests) (queries : Nat)
    (callerClass : ContinuationQueries queries schedule) :
    BoundedDifference (realHistory schedule) (publicHistory schedule)
      ((requests : ℝ) * erasureLoss queries) := by
  induction schedule with
  | finish event =>
      intro old state
      change |V8Smz9MixedMaskCompiler.run true (.finish event) old state -
        V8Smz9MixedMaskCompiler.run true (.finish event) old state| ≤ _
      rw [sub_self, abs_zero]
      exact mul_nonneg (mul_nonneg (Nat.cast_nonneg _) (erasure_loss_nonnegative queries)) (sq_nonneg _)
  | gate operation next ih => exact gate_difference_bound _ _ _ _ (ih callerClass)
  | quantumQuery next ih => exact query_difference_bound _ _ _ (ih callerClass)
  | honestRead input next ih => exact read_difference_bound _ _ _ _ (fun answer => ih answer (callerClass answer))
  | instrument operation next ih => exact instrument_difference_bound _ _ _ _ (fun outcome => ih outcome (callerClass outcome))
  | random source next ih => exact random_difference_bound _ _ _ _ (fun coins => ih coins (callerClass coins))
  | write input answer next ih => exact write_difference_bound _ _ _ _ _ (ih callerClass)
  | @request requests data next ih =>
      intro old state
      let sourceNext := fun context outcome => realHistory (next context outcome)
      let publicNext := fun context outcome => publicHistory (next context outcome)
      have first := current_request_bound_mass data sourceNext old state queries callerClass.1
      have last : BoundedDifference
          (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data sourceNext)
          (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data publicNext)
          ((requests : ℝ) * erasureLoss queries) :=
        complete_public_continuation_bound data sourceNext publicNext _
          (fun context outcome => ih context outcome (callerClass.2 context outcome))
      calc
        _ ≤ |V8Smz9MixedMaskCompiler.run true (sourceRequest data sourceNext) old state -
              V8Smz9MixedMaskCompiler.run true
                (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data sourceNext) old state| +
            |V8Smz9MixedMaskCompiler.run true
                (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data sourceNext) old state -
              V8Smz9MixedMaskCompiler.run true
                (NativePrivateSpendQ58CurrentHistoryMass.publicRequest data publicNext) old state| :=
          abs_sub_le _ _ _
        _ ≤ _ := add_le_add first (last old state)
        _ = _ := by push_cast; ring

section Initialized
variable [DecidableEq Work]

def emptyCMS (registers : RegisterBasis (Input := CurrentInput bound)
    (Phase := DigestRegister) (Workspace := Work) → ℂ) :=
  partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers)

/-- End-to-end conditional persistent current privacy. There is one initial
empty CMS, one original register vector, one global fresh hop, and the derived
M-request erasure induction. Every family and every failed proof attempt is
charged by the same disclosed total Q and request count. -/
theorem current_initialized_history_bound {requests : Nat}
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
    (callerClass : ContinuationQueries queries schedule) :
    |actualPhaseRun queries false (compile (realHistory schedule) []) (emptyCMS registers) -
      actualPhaseRun queries true (compile (publicHistory schedule) []) (emptyCMS registers)| ≤
      freshLifetimeLoss queries + (requests : ℝ) * erasureLoss queries := by
  have fresh :
      |actualPhaseRun queries false (compile (realHistory schedule) []) (emptyCMS registers) -
        actualPhaseRun queries true (compile (realHistory schedule) []) (emptyCMS registers)| ≤
      freshLifetimeLoss queries := by
    rw [abs_sub_comm]
    exact initialized_persistent_mixed_fresh_bound ghhm (realHistory schedule) queries registers
      normalized realQueries (real_history_mass schedule)
  have erased :
      |actualPhaseRun queries true (compile (realHistory schedule) []) (emptyCMS registers) -
        actualPhaseRun queries true (compile (publicHistory schedule) []) (emptyCMS registers)| ≤
      (requests : ℝ) * erasureLoss queries := by
    unfold emptyCMS
    rw [actual_phase_run_initialized_acceptance queries true (compile (realHistory schedule) [])
        registers ((compiled_query_count_le _ []).trans realQueries),
      actual_phase_run_initialized_acceptance queries true (compile (publicHistory schedule) [])
        registers ((compiled_query_count_le _ []).trans publicQueries),
      compiled_acceptance_eq, compiled_acceptance_eq]
    apply uniform_average_difference_le
    intro old
    have bounded := all_history_erasure_bound schedule queries callerClass old (WithLp.toLp 2 registers)
    simpa only [normalized, one_pow, mul_one] using bounded
  exact (abs_sub_le _ _ _).trans (add_le_add fresh erased)

omit [DecidableEq Work] in
/-- Same compiled execution at every mode, without resetting the table or
introducing an oracle-dependent initial correction record. -/
theorem history_compile_exact {requests : Nat} (mode : Bool)
    (schedule : Schedule bound Work requests) (old : CurrentInput bound → DigestRegister)
    (state : V8Smz9HonestWholeViewGames.GameState (Input := CurrentInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run mode (compile (realHistory schedule) []) old state =
      V8Smz9MixedMaskCompiler.run mode (realHistory schedule) old state :=
  persistent_compile_exact mode (realHistory schedule) old state

end Initialized

/-- PR205's proof-attempt class is retained explicitly. There is no derivation
of M from an obsolete per-request query coefficient and no installed limiter. -/
theorem history_loss_below_128 (queries requests : Nat)
    (queryBudget : queries ≤ 3 * 2^64) (requestBudget : requests ≤ 2^21) :
    freshLifetimeLoss queries + (requests : ℝ) * erasureLoss queries < (2 : ℝ)^(-128 : ℤ) := by
  have qBound : (queries : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by exact_mod_cast queryBudget
  have mBound : (requests : ℝ) ≤ ((2^21 : Nat) : ℝ) := by exact_mod_cast requestBudget
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
      ((2^21 : Nat) : ℝ) * (4 * ((3 * 2^64 : Nat) : ℝ) / (2 ^ 256 : ℝ)) := by
    apply mul_le_mul mBound _ (erasure_loss_nonnegative queries) (by positivity)
    unfold erasureLoss
    exact div_le_div_of_nonneg_right (mul_le_mul_of_nonneg_left qBound (by norm_num)) (by positivity)
  exact (add_lt_add_of_lt_of_le freshRounded erasureRounded).trans (by norm_num)

section Final
variable [DecidableEq Work]

theorem current_initialized_history_below_128 {requests : Nat}
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
    (queryBudget : queries ≤ 3 * 2^64) (requestBudget : requests ≤ 2^21) :
    |actualPhaseRun queries false (compile (realHistory schedule) []) (emptyCMS registers) -
      actualPhaseRun queries true (compile (publicHistory schedule) []) (emptyCMS registers)| <
      (2 : ℝ)^(-128 : ℤ) :=
  (current_initialized_history_bound schedule ghhm queries registers normalized
    realQueries publicQueries callerClass).trans_lt (history_loss_below_128 queries requests queryBudget requestBudget)

end Final

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPersistentHistory
