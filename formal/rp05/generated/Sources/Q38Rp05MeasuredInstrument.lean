import Q38MeasuredCmsNonleaf
import Q38Rp05LeafSupport
import Q38WholeViewCmsSemantics
import Q38CmsAdaptiveWholeViewApplication
import Q38CmsInitializedResampling
import Q38CmsControlledSwap
import Q38Rp05ChronologicalAlgebra
import Q38Rp05ExecutionBridge
import Q38ConcreteAdaptivePrivacy
import SmzaRp05StatementNamespace
import HegemonCrypto.SmallWoodV8Smz9HiddenLeafQrom
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity
import Q38Rp05MeasuredBranchCore

/-!
# RP05 complete measured CMS instrument

The DECS response `D` is an algebraic change-of-variables coordinate.  It is
therefore retained as an outer public/workspace branch and is never coerced to
an oracle digest.  For each such response, the actual `piopSuffix` reads are
measured on one persistent CMS state by successive `phaseReadBranch` maps.
The padded `PublicTrace` retains termination, malformed padding, and
fuel-exhaustion outcomes; the latter branches are zero rather than discarded.
-/

namespace HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Input Public BaseWork Other Result : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Public] [DecidableEq Public]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem response_cms_norm_sq
    {Work : Type} [Fintype Work] [DecidableEq Work]
    (state : PhaseState Input Work) :
    ‖WithLp.toLp 2 state‖ ^ 2 = normSquared state := by
  rw [EuclideanSpace.norm_sq_eq]
  unfold normSquared
  apply Finset.sum_congr rfl
  intro basis _
  exact Complex.sq_norm _

/-- Direct quadratic branch aggregation for a CMS instrument.  Every branch
is charged by its exact unnormalised Born mass, and completeness sums those
masses to the incoming CMS norm.  There is no square-root or branch-count
loss. -/
theorem cms_complete_instrument_quadratic_comparison
    {DomainWork CodomainWork Outcome : Type}
    [Fintype DomainWork] [DecidableEq DomainWork]
    [Fintype CodomainWork] [DecidableEq CodomainWork]
    [Fintype Outcome]
    (instrument : CMSCompleteInstrument Input DomainWork CodomainWork Outcome)
    (left right : Outcome → PhaseState Input CodomainWork → ℝ)
    (leftHomogeneous : ∀ outcome, QuadraticallyHomogeneous (left outcome))
    (rightHomogeneous : ∀ outcome, QuadraticallyHomogeneous (right outcome))
    (delta : ℝ)
    (normalizedBound : ∀ outcome state, ‖WithLp.toLp 2 state‖ = 1 →
      |left outcome state - right outcome state| ≤ delta)
    (state : PhaseState Input DomainWork) (total : GloballyTotal state) :
    |(∑ outcome, left outcome (instrument.branch outcome state)) -
        ∑ outcome, right outcome (instrument.branch outcome state)| ≤
      delta * normSquared state := by
  rw [← Finset.sum_sub_distrib]
  calc
    _ ≤ ∑ outcome,
        |left outcome (instrument.branch outcome state) -
          right outcome (instrument.branch outcome state)| :=
      Finset.abs_sum_le_sum_abs _ _
    _ ≤ ∑ outcome, delta *
        ‖WithLp.toLp 2 (instrument.branch outcome state)‖ ^ 2 := by
      apply Finset.sum_le_sum
      intro outcome _
      -- CMS amplitudes are stored as a plain function. Its ordinary norm is
      -- the sup norm; lift to EuclideanSpace before the homogeneous bound.
      exact normalized_comparison_lifts_to_all_states
        (fun vector : EuclideanSpace ℂ
            (HegemonCrypto.CmsCompressedOracle.Basis
              Input DigestRegister DigestRegister CodomainWork) =>
          left outcome (WithLp.ofLp vector))
        (fun vector : EuclideanSpace ℂ
            (HegemonCrypto.CmsCompressedOracle.Basis
              Input DigestRegister DigestRegister CodomainWork) =>
          right outcome (WithLp.ofLp vector))
        (fun scalar vector => leftHomogeneous outcome scalar (WithLp.ofLp vector))
        (fun scalar vector => rightHomogeneous outcome scalar (WithLp.ofLp vector))
        delta (fun vector unit => normalizedBound outcome (WithLp.ofLp vector) unit)
        (WithLp.toLp 2 (instrument.branch outcome state))
    _ = ∑ outcome, delta *
        normSquared (instrument.branch outcome state) := by
      apply Finset.sum_congr rfl
      intro outcome _
      rw [response_cms_norm_sq]
    _ = delta * normSquared state := by
      rw [← Finset.mul_sum, instrument.complete state total]

section SameReachedAlignment

variable {Index Branch Work : Type}
variable [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Work] [DecidableEq Work]

omit [Fintype Input] [DecidableEq Input] [Fintype Branch] [DecidableEq Branch]
  [Fintype Work] [DecidableEq Work] in
theorem response_fourier_append_uniform_labels
    (state : ResponseCmsState Input (Branch × Work)) :
    responseFourierState
        (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index)
        (responseFourierState state) := by
  funext target
  simp only [responseFourierState, digestResponseFourier, appendUniformLabelState,
    mul_assoc, Finset.sum_mul]

theorem phase_encode_append_uniform_labels
    (state : ResponseCmsState Input (Branch × Work)) :
    phaseEncode (appendUniformLabelState (Index := Index) state) =
      appendUniformLabelState (Index := Index) (phaseEncode state) := by
  unfold phaseEncode
  rw [response_fourier_append_uniform_labels,
    global_decompress_append_uniform_labels]

/-- Exact base alignment for the same pre-resampling reached state.  The
canonical family is built before any tape-dependent controlled swap. -/
theorem initialized_phase_family_of_same_reached
    (reached : ResponseCmsState Input (Branch × Work))
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    initializedPhaseFamily (Environment := Index)
        (canonicalTotalFamily (phaseDecode reached)) =
      initializedFreshState (Index := Index) (coreOfCmsState reached) := by
  rw [initializedFreshState_coreOf_eq_append]
  unfold initializedPhaseFamily
  rw [total_oracle_family_canonical_eq _ supported]
  have appendEq :
      appendUniformEnvironmentState (Environment := Index) (phaseDecode reached) =
        appendUniformLabelState (Index := Index) (phaseDecode reached) := by
    funext basis
    simp only [appendUniformEnvironmentState, appendUniformLabelState,
      Prod.mk.eta, Fintype.card_fun]
  rw [appendEq]
  exact (phase_encode_append_uniform_labels (Index := Index)
    (phaseDecode reached)).trans
      (congrArg (appendUniformLabelState (Index := Index))
        (phase_encode_decode reached))

/-- Slicing the initialized fresh-label state at one public branch is exactly
initializing the corresponding sliced canonical family of the same reached
state. -/
theorem initialized_public_slice_of_same_reached
    (reached : ResponseCmsState Input (Branch × Work))
    (supported : TotalDatabaseSupport (phaseDecode reached))
    (branch : Branch) :
    V8SmzaCmsControlledSwap.slice branch
        (initializedFreshState (Index := Index) (coreOfCmsState reached)) =
      initializedPhaseFamily (Environment := Index)
        (publicSliceFamily (Input := Input) (Public := Branch)
          (BaseWork := Work) branch
          (canonicalTotalFamily (phaseDecode reached))) := by
  rw [← initialized_phase_family_of_same_reached
    (Index := Index) reached supported]
  unfold initializedPhaseFamily
  rw [V8SmzaCmsControlledSwap.slice_global_decompress]
  have slicedRegisters :
      V8SmzaCmsControlledSwap.slice branch
          (responseFourierState
            (appendUniformEnvironmentState (Environment := Index)
              (totalOracleFamilyState
                (canonicalTotalFamily (phaseDecode reached))))) =
        responseFourierState
          (appendUniformEnvironmentState (Environment := Index)
            (publicSlice branch
              (totalOracleFamilyState
                (canonicalTotalFamily (phaseDecode reached))))) := by
    funext basis
    rfl
  rw [slicedRegisters]
  rw [public_slice_total_oracle_family_state]

/-- The exact P7 branch slice.  Controlled resampling on the initialized
state and fixed-branch compressed swaps on the sliced canonical family are
the same vector, with both sides derived from the same `reached` state. -/
theorem controlled_initialized_public_slice_of_same_reached
    (keys : Branch → Index → Input) (indices : List Index)
    (reached : ResponseCmsState Input (Branch × Work))
    (supported : TotalDatabaseSupport (phaseDecode reached))
    (branch : Branch) :
    V8SmzaCmsControlledSwap.slice branch
        (controlledCompressed keys indices
          (initializedFreshState (Index := Index)
            (coreOfCmsState reached))) =
      compressedSwapList (keys branch) indices
        (initializedPhaseFamily (Environment := Index)
          (publicSliceFamily (Input := Input) (Public := Branch)
            (BaseWork := Work) branch
            (canonicalTotalFamily (phaseDecode reached)))) := by
  rw [slice_controlled_compressed,
    initialized_public_slice_of_same_reached reached supported branch]

/-- Literal strict-v2 RP05 specialization of the preceding equality. -/
theorem rp05_controlled_initialized_public_slice_of_same_reached
    {Other : Type} [Fintype Other] [DecidableEq Other]
    (preamble : Branch → SmzaRp05StatementNamespace.Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (tapes : LeafIndex → LeafTape) (indices : List LeafIndex)
    (reached : ResponseCmsState (Rp05LeafInput ⊕ Other) (Branch × Work))
    (supported : TotalDatabaseSupport (phaseDecode reached))
    (branch : Branch) :
    V8SmzaCmsControlledSwap.slice branch
        (controlledCompressed (rp05Selected preamble salt data tapes) indices
          (initializedFreshState (Index := LeafIndex)
            (coreOfCmsState reached))) =
      compressedSwapList
        (fun index => rp05Selected preamble salt data tapes branch index)
        indices
        (initializedPhaseFamily (Environment := LeafIndex)
          (publicSliceFamily (Input := Rp05LeafInput ⊕ Other)
            (Public := Branch) (BaseWork := Work) branch
            (canonicalTotalFamily (phaseDecode reached)))) :=
  controlled_initialized_public_slice_of_same_reached
    (rp05Selected preamble salt data tapes) indices reached supported branch

end SameReachedAlignment

end
end HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
