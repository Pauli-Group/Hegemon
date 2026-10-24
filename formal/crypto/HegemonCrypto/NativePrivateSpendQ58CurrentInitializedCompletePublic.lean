import HegemonCrypto.NativePrivateSpendQ58CurrentCompletePublicJoin

/-! One initialized current real-source/public-simulator comparison. The ideal
public simulator may program its publicly reconstructed selected addresses.
The same external continuation is frozen at its existing future mode, so this
comparison never changes that caller's gates, instruments, registers or oracle.
The shared public context includes all labels and actual commitment layers.
This remains conditional on PR205's external adaptive-reprogramming theorem
and the trusted current source interpretation, not a Rust/OS refinement. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentInitializedCompletePublic
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open V8Smz9HiddenLeafQrom V8Smz9MixedMaskCompiler V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame Q38WholeViewCmsSemantics
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentChronologicalRequest
open NativePrivateSpendQ58CurrentInitializedPublic NativePrivateSpendQ58CurrentOriginalRequest
open NativePrivateSpendQ58CurrentCompletePublicJoin
open NativePrivateSpendQ58CurrentFreshAccounting NativePrivateSpendQ58CurrentFreshInitialized
open scoped Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option exponentiation.threshold 1024

abbrev CurrentInput (bound : Nat) := CurrentFullRawInput bound
abbrev PublicContext := Option ((NativePrivateSpendQ58CurrentCosetSelector.Index → DigestRegister) × CommitPrefix)
abbrev CurrentByte := HegemonCrypto.CanonicalBytes.Byte

variable {Work : Type} [Fintype Work]

def sharedContinuation {bound : Nat} (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (context : PublicContext) (outcome : Except String PublicResult) :
    MixedProgram (CurrentInput bound) Work := frozenCaller future (caller context) outcome

def sourceProgram {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation) (values : NativePrivateSpendQ58CurrentRowBoundary.CurrentValues)
    (statement : Fin 616 → CurrentByte) (salt : Fin 32 → CurrentByte)
    (binding : Fin 77 → Goldilocks) (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work) :
    MixedProgram (CurrentInput bound) Work :=
  originalRequest largeEnough relation values statement salt binding (sharedContinuation future caller)

/-- No private values occur in the simulator constructor or its public input.
`true` in the endpoint allows its explicit public fixed table corrections;
the caller itself executes in the same previously fixed `future` mode. -/
def simulatorProgram {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation) (statement : Fin 616 → CurrentByte)
    (salt : Fin 32 → CurrentByte) (binding : Fin 77 → Goldilocks) (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work) :
    MixedProgram (CurrentInput bound) Work :=
  completePublicSimulator largeEnough relation statement salt binding (sharedContinuation future caller)

/-- Sampler mass is derived from actual raw 64-byte taped leaves. Freezing the
physical continuation removes fresh-request switching there; no whole-view
uniformity, coverage, coupling, or caller-mass hypothesis is supplied. -/
theorem source_program_mass {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation) (values : NativePrivateSpendQ58CurrentRowBoundary.CurrentValues)
    (statement : Fin 616 → CurrentByte) (salt : Fin 32 → CurrentByte)
    (binding : Fin 77 → Goldilocks) (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (sourceProgram largeEnough relation values statement salt binding future caller) := by
  apply original_request_mass
  intro context result
  exact fixed_future_mass future (compile (caller context result) []) _

def emptyCMS {bound : Nat}
    (registers : RegisterBasis (Input := CurrentInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ) :=
  partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers)

def initializedDistance {bound : Nat} (queries : Nat)
    (source simulator : MixedProgram (CurrentInput bound) Work)
    (registers : RegisterBasis (Input := CurrentInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ) : ℝ :=
  |actualPhaseRun queries false (compile source []) (emptyCMS registers) -
    actualPhaseRun queries true (compile simulator []) (emptyCMS registers)|

/-- The same total oracle-query parameter bounds the complete source,
complete simulator and every external continuation. It is an adversary
complexity parameter, not a production runtime counter. Both games start
from this one empty CMS and the same original normalized register vector.
Every measurement, actual success/error branch and persistent table update
remains inside the literal programs supplied by the imported completed join. -/
theorem current_initialized_complete_public_bound [DecidableEq Work]
    {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation) (values : NativePrivateSpendQ58CurrentRowBoundary.CurrentValues)
    (valid : NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation values)
    (statement : Fin 616 → CurrentByte) (salt : Fin 32 → CurrentByte)
    (binding : Fin 77 → Goldilocks) (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := CurrentInput bound) (Work := Work))
    (queries : Nat)
    (registers : RegisterBasis (Input := CurrentInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := CurrentInput bound) (Work := Work))‖ = 1)
    (sourceQueries : queryCount (sourceProgram largeEnough relation values statement salt binding future caller) ≤ queries)
    (publicQueries : queryCount (simulatorProgram largeEnough relation statement salt binding future caller) ≤ queries)
    (callerQueries : ∀ context result,
      V8Smz9HonestWholeViewGames.queryCount
        (compile (sharedContinuation future caller context result) []) ≤ queries) :
    initializedDistance queries
      (sourceProgram largeEnough relation values statement salt binding future caller)
      (simulatorProgram largeEnough relation statement salt binding future caller) registers ≤
      freshLifetimeLoss queries + 4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
  let source := sourceProgram largeEnough relation values statement salt binding future caller
  let simulator := simulatorProgram largeEnough relation statement salt binding future caller
  have sourceCapacity := (compiled_query_count_le source []).trans sourceQueries
  have publicCapacity := (compiled_query_count_le simulator []).trans publicQueries
  have fresh :
      |actualPhaseRun queries false (compile source []) (emptyCMS registers) -
        actualPhaseRun queries true (compile source []) (emptyCMS registers)| ≤ freshLifetimeLoss queries := by
    rw [abs_sub_comm]
    exact initialized_persistent_mixed_fresh_bound ghhm source queries registers normalized sourceQueries
      (source_program_mass largeEnough relation values statement salt binding future caller)
  have erased :
      |actualPhaseRun queries true (compile source []) (emptyCMS registers) -
        actualPhaseRun queries true (compile simulator []) (emptyCMS registers)| ≤
        4 * (queries : ℝ) / (2 ^ 256 : ℝ) := by
    unfold emptyCMS
    rw [actual_phase_run_initialized_acceptance queries true (compile source []) registers sourceCapacity,
      actual_phase_run_initialized_acceptance queries true (compile simulator []) registers publicCapacity,
      compiled_acceptance_eq, compiled_acceptance_eq]
    apply uniform_average_difference_le
    intro oracle
    exact protected_source_complete_public_bound largeEnough relation values valid statement salt binding
      (sharedContinuation future caller) oracle (WithLp.toLp 2 registers) normalized queries callerQueries
  have triangle := (abs_sub_le
    (actualPhaseRun queries false (compile source []) (emptyCMS registers))
    (actualPhaseRun queries true (compile source []) (emptyCMS registers))
    (actualPhaseRun queries true (compile simulator []) (emptyCMS registers))).trans (add_le_add fresh erased)
  have workDeciderEq : (inferInstance : DecidableEq Work) =
      (fun a b => Classical.propDecidable (a = b)) := by
    funext a b
    exact Subsingleton.elim _ _
  dsimp only [inferInstance] at workDeciderEq
  rw [workDeciderEq] at triangle
  unfold initializedDistance
  exact triangle

/-- Conservative rational bounds after the one fresh hop and one unopened
leaf erasure hop. No changed-stream transport coefficient is presumed. -/
theorem total_loss_below_128 (queries : Nat) (budget : queries ≤ 3 * 2^64) :
    freshLifetimeLoss queries + 4 * (queries : ℝ) / (2 ^ 256 : ℝ) < (2 : ℝ)^(-128 : ℤ) := by
  have qNonnegative : (0 : ℝ) ≤ queries := Nat.cast_nonneg _
  have qBound : (queries : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by exact_mod_cast budget
  have squareBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ ≤ ((2 : ℝ)^(-223 : ℤ))^2 := by
    calc
      _ ≤ ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
        mul_le_mul_of_nonneg_right qBound (by positivity)
      _ ≤ _ := by norm_num
  have rootBound : Real.sqrt ((queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) ≤ (2 : ℝ)^(-223 : ℤ) :=
    Real.sqrt_le_iff.mpr ⟨by positivity, squareBound⟩
  have linearBound : (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 ≤
      ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2 :=
    div_le_div_of_nonneg_right
      (mul_le_mul_of_nonneg_right qBound (by positivity)) (by norm_num)
  have freshRounded : freshLifetimeLoss queries < (2 : ℝ)^(-157 : ℤ) := by
    calc
      freshLifetimeLoss queries ≤
          (queries : ℝ) * ((2 : ℝ)^(-223 : ℤ) + ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
        mul_le_mul_of_nonneg_left (add_le_add rootBound linearBound) qNonnegative
      _ ≤ ((3 * 2^64 : Nat) : ℝ) *
          ((2 : ℝ)^(-223 : ℤ) + ((3 * 2^64 : Nat) : ℝ) * (2 ^ 512 : ℝ)⁻¹ / 2) :=
        mul_le_mul_of_nonneg_right qBound (by positivity)
      _ < (2 : ℝ)^(-157 : ℤ) := by norm_num
  have erasureRounded : 4 * (queries : ℝ) / (2 ^ 256 : ℝ) ≤
      4 * ((3 * 2^64 : Nat) : ℝ) / (2 ^ 256 : ℝ) :=
    div_le_div_of_nonneg_right (mul_le_mul_of_nonneg_left qBound (by norm_num)) (by positivity)
  exact (add_lt_add_of_lt_of_le freshRounded erasureRounded).trans (by norm_num)

theorem current_initialized_complete_public_below_128 [DecidableEq Work]
    {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation) (values : NativePrivateSpendQ58CurrentRowBoundary.CurrentValues)
    (valid : NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation values)
    (statement : Fin 616 → CurrentByte) (salt : Fin 32 → CurrentByte)
    (binding : Fin 77 → Goldilocks) (future : Bool)
    (caller : PublicContext → Except String PublicResult → MixedProgram (CurrentInput bound) Work)
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := CurrentInput bound) (Work := Work))
    (queries : Nat)
    (registers : RegisterBasis (Input := CurrentInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := CurrentInput bound) (Work := Work))‖ = 1)
    (sourceQueries : queryCount (sourceProgram largeEnough relation values statement salt binding future caller) ≤ queries)
    (publicQueries : queryCount (simulatorProgram largeEnough relation statement salt binding future caller) ≤ queries)
    (callerQueries : ∀ context result,
      V8Smz9HonestWholeViewGames.queryCount
        (compile (sharedContinuation future caller context result) []) ≤ queries)
    (lifetimeBudget : queries ≤ 3 * 2^64) :
    initializedDistance queries
      (sourceProgram largeEnough relation values statement salt binding future caller)
      (simulatorProgram largeEnough relation statement salt binding future caller) registers < (2 : ℝ)^(-128 : ℤ) :=
  (current_initialized_complete_public_bound largeEnough relation values valid statement salt binding future caller
    ghhm queries registers normalized sourceQueries publicQueries callerQueries).trans_lt
      (total_loss_below_128 queries lifetimeBudget)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentInitializedCompletePublic
