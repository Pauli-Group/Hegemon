import HegemonCrypto.NativePrivateSpendQ58CurrentFreshAccounting
import HegemonCrypto.NativePrivateSpendQ58CurrentFreshNumerics
import Q38WholeViewCmsSemantics

/-! Reuse the dimension-generic initialized CMS theorem underlying PR205.
This transfers the *same* compiled mixed program and original registers. It
does not inherit RP05's 38-selection or public-simulator endpoint constants. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshInitialized

open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open V8Smz9HiddenLeafQrom V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentFreshAccounting Q38WholeViewCmsSemantics
open NativePrivateSpendQ58CurrentFreshNumerics
open scoped Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

variable {Input Work : Type} [Fintype Input] [DecidableEq Input]
  [Fintype Work] [DecidableEq Work]

/-- A literal single empty-CMS initialization. All complete instruments,
error continuations and subsequent reads remain in `program`, and the state is
not reinitialized at request boundaries. No public-erasure premise is accepted. -/
theorem initialized_persistent_mixed_fresh_bound
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := Input) (Work := Work))
    (program : MixedProgram Input Work) (queries : Nat)
    (registers : RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := Input) (Work := Work))‖ = 1)
    (queryBound : queryCount program ≤ queries)
    (massBound : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ program) :
    |actualPhaseRun queries true (compile program [])
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters registers)) -
      actualPhaseRun queries false (compile program [])
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters registers))| ≤ freshLifetimeLoss queries := by
  have compiledBound := (compiled_query_count_le program []).trans queryBound
  rw [actual_phase_run_initialized_acceptance queries true (compile program [])
      registers compiledBound,
    actual_phase_run_initialized_acceptance queries false (compile program [])
      registers compiledBound,
    compiled_acceptance_eq, compiled_acceptance_eq]
  exact persistent_mixed_fresh_bound ghhm program _ queries normalized queryBound massBound

/-- Numerical rounding is applied after the exact initialized comparison;
the same program's total Q is shared by all requests and oracle consumers. -/
theorem initialized_persistent_mixed_fresh_below_128
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := Input) (Work := Work))
    (program : MixedProgram Input Work) (queries : Nat)
    (registers : RegisterBasis (Input := Input) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := Input) (Work := Work))‖ = 1)
    (queryBound : queryCount program ≤ queries)
    (massBound : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ program)
    (lifetimeBudget : queries ≤ 3 * 2^64) :
    |actualPhaseRun queries true (compile program [])
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters registers)) -
      actualPhaseRun queries false (compile program [])
        (partialRandomOracleState (Output := DigestRegister) ∅
          (responseFourierRegisters registers))| < (2 : ℝ)^(-128 : ℤ) :=
  (initialized_persistent_mixed_fresh_bound ghhm program queries registers
    normalized queryBound massBound).trans_lt (fresh_loss_below_128 queries lifetimeBudget)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFreshInitialized
