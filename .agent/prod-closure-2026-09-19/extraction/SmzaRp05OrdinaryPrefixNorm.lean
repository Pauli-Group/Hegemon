import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05CertifiedFiberCompilerRun

/-! # Norm monotonicity for ordinary unprogrammed prefixes

Ordinary queries are isometries on their reachable strict support. Private
gates are only required to be contractions, so the general prefix theorem is
nonincrease rather than equality.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05OrdinaryPrefixNorm

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CertifiedFiberCompiler (contraction_bounded)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- A database-independent private contraction cannot increase squared norm.
The conversion uses `stateNorm ^ 2 = normSquared` and nonnegativity.
-/
theorem private_gate_norm_squared_le
    (step : DatabaseIndependentContraction
      (Input := Key)
      (Output := SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter))
      (Phase := SmzaRp05CurrentAdaptiveExecution.Output (Counter := Counter))
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (step.apply state) ≤ normSquared state := by
  have h : stateNorm (step.apply state) ≤ stateNorm state := by
    exact step.contractive state
  have squared := (sq_le_sq₀
    (state_norm_nonnegative (step.apply state))
    (state_norm_nonnegative state)).2 h
  simpa only [state_norm_sq_eq_norm_squared] using squared

/-- The actual ordinary-prefix interpreter is norm-squared nonincreasing
when its input is bounded by the prefix's starting query count. -/
theorem ordinary_run_norm_squared_le
    {cap start finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) start finish queries)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state) :
    normSquared (ordinaryRun program state) ≤ normSquared state := by
  induction program generalizing state with
  | nil budget => exact le_rfl
  | query occupied room remaining ih =>
      have nextBounded : BoundedState (occupied + 1)
          (HegemonCrypto.CmsQuerySequence.cappedQueryState
            vectorPhaseSystem cap state) := by
        rw [capped_query_state_eq_query_state_of_bounded_lt
          vectorPhaseSystem cap occupied state room bounded]
        exact query_state_bounded_succ_of_bounded
          vectorPhaseSystem cap occupied state room bounded
      have capNorm :
          normSquared (HegemonCrypto.CmsQuerySequence.cappedQueryState
            vectorPhaseSystem cap state) = normSquared state := by
        rw [capped_query_state_eq_query_state_of_bounded_lt
          vectorPhaseSystem cap occupied state room bounded]
        exact query_state_preserves_norm_squared_of_strict_support
          vectorPhaseSystem cap state
          (bounded_state_strict_support bounded room)
      rw [ordinaryRun]
      exact (ih _ nextBounded).trans (le_of_eq capNorm)
  | privateGate budget within step remaining ih =>
      have nextBounded : BoundedState budget (step.apply state) :=
        contraction_bounded step budget bounded
      rw [ordinaryRun]
      exact (ih _ nextBounded).trans
        (private_gate_norm_squared_le step state)

end

end HegemonCrypto.SmallWood.SmzaRp05OrdinaryPrefixNorm
