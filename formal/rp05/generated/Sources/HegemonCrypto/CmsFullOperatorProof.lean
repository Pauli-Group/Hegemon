import HegemonCrypto.CmsLocalOperatorProof

/-!
# Full compressed-oracle local-operator theorem

This module lifts the exact one-fiber CMS local-operator theorem across the orthogonal input,
Fourier-phase, and private-workspace registers.  The homogeneous block bound avoids multiplying the
instability loss by the number of register blocks.
-/

namespace HegemonCrypto.CmsFullOperatorProof

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFiberDecomposition
open HegemonCrypto.CmsLocalOperatorProof

noncomputable section

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

noncomputable local instance complementDecidable
    (property : Property Input Output) :
    DecidablePred (complement property) :=
  Classical.decPred _

/-- Database amplitudes in one fixed input/phase/workspace register block. -/
def blockAmplitude
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (database : Database Input Output) : ℂ :=
  state
    { input := input
      phase := phaseValue
      workspace := workspace
      database := database }

/-- Canonical fiber coefficients induced by one register block of a full state. -/
def blockCoefficients
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace) :
    FiberCoefficients Input Output :=
  coefficientsOfAmplitude input
    (blockAmplitude state input phaseValue workspace)

/-- Direct sum of all exact projected block norms. -/
def fullProjectedNorm
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) : ℝ :=
  ∑ input : Input,
    ∑ phaseValue : Phase,
      ∑ workspace : Workspace,
        projectedQueryNorm system phaseValue property queryBound input
          (blockCoefficients state input phaseValue workspace)

/-- Direct sum of all source block norms. -/
def fullSourceNorm
    (state : State Input Output Phase Workspace) : ℝ :=
  ∑ input : Input,
    ∑ phaseValue : Phase,
      ∑ workspace : Workspace,
        fiberCoefficientNorm input
          (blockCoefficients state input phaseValue workspace)

/-- The actual projected compressed-oracle state `P * O * complement(P)`. -/
def projectedQueryState
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  project property queryBound
    (queryState system queryBound
      (project (complement property) queryBound state))

set_option linter.unusedSimpArgs false
/--
At every target basis coordinate, the actual projected query equals the corresponding exact
database-block amplitude.
-/
theorem projected_query_state_apply
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (target : Basis Input Output Phase Workspace) :
    projectedQueryState system property queryBound state target =
      projectedQueryAmplitude system target.phase property queryBound target.input
        (blockCoefficients state target.input target.phase target.workspace)
        target.database := by
  unfold projectedQueryState projectedQueryAmplitude project
  by_cases targetAllowed :
      size target.database <= queryBound ∧ property target.database
  · simp only [targetAllowed]
    unfold queryState
    rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)).sum_comp
        (fun source =>
          (if size source.database <= queryBound ∧
              complement property source.database then
            state source
          else 0) *
            kernel system queryBound source target)]
    rw [Fintype.sum_prod_type]
    rw [Finset.sum_eq_single target.input]
    · rw [Fintype.sum_prod_type]
      rw [Finset.sum_eq_single target.phase]
      · rw [Fintype.sum_prod_type]
        rw [Finset.sum_eq_single target.workspace]
        · apply Finset.sum_congr rfl
          intro sourceDatabase _
          simp [kernel, basisEquiv, blockCoefficients, blockAmplitude,
            boundedComplementAmplitude,
            fiberAmplitude_coefficientsOfAmplitude]
        · intro sourceWorkspace _ differentWorkspace
          have targetDifferent : target.workspace ≠ sourceWorkspace :=
            Ne.symm differentWorkspace
          simp [kernel, basisEquiv, targetDifferent]
        · simp
      · intro sourcePhase _ differentPhase
        have targetDifferent : target.phase ≠ sourcePhase :=
          Ne.symm differentPhase
        simp [kernel, basisEquiv, targetDifferent]
      · simp
    · intro sourceInput _ differentInput
      have targetDifferent : target.input ≠ sourceInput :=
        Ne.symm differentInput
      simp [kernel, basisEquiv, targetDifferent]
    · simp
  · simp [targetAllowed]

set_option linter.unusedSimpArgs true

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase]
    [DecidableEq Workspace] in
/-- The direct sum of canonical source block norms is the full compressed-oracle state norm. -/
theorem full_source_norm_eq_norm_squared
    (state : State Input Output Phase Workspace) :
    fullSourceNorm state = normSquared state := by
  unfold fullSourceNorm
  simp_rw [fiber_coefficient_norm_eq_database_norm]
  unfold blockCoefficients blockAmplitude normSquared
  simp_rw [fiberAmplitude_coefficientsOfAmplitude]
  rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
    (Workspace := Workspace)).sum_comp
      (fun basis => Complex.normSq (state basis))]
  rw [Fintype.sum_prod_type]
  simp_rw [Fintype.sum_prod_type]
  rfl

/--
The direct sum used by the local-operator proof is exactly the squared norm of the concrete
projected compressed-oracle state.
-/
theorem norm_squared_projected_query_state_eq_full_projected_norm
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    normSquared (projectedQueryState system property queryBound state) =
      fullProjectedNorm system property queryBound state := by
  unfold normSquared fullProjectedNorm
  rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
    (Workspace := Workspace)).sum_comp
      (fun target =>
        Complex.normSq
          (projectedQueryState system property queryBound state target))]
  rw [Fintype.sum_prod_type]
  simp_rw [Fintype.sum_prod_type]
  simp_rw [projected_query_state_apply]
  rfl

omit [DecidableEq Workspace] in
/--
The full projected local-operator norm is at most `6 * instability` times the full source norm.
No factor depending on the number of register blocks is introduced.
-/
theorem full_projected_norm_le_source_norm
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound) :
    fullProjectedNorm system property queryBound state <=
      6 * bound * fullSourceNorm state := by
  unfold fullProjectedNorm fullSourceNorm
  calc
    (∑ input : Input,
      ∑ phaseValue : Phase,
        ∑ workspace : Workspace,
          projectedQueryNorm system phaseValue property queryBound input
            (blockCoefficients state input phaseValue workspace)) <=
        ∑ input : Input,
          ∑ phaseValue : Phase,
            ∑ workspace : Workspace,
              6 * bound *
                fiberCoefficientNorm input
                  (blockCoefficients state input phaseValue workspace) := by
      apply Finset.sum_le_sum
      intro input _
      apply Finset.sum_le_sum
      intro phaseValue _
      apply Finset.sum_le_sum
      intro workspace _
      by_cases zeroPhase : phaseValue = system.zeroPhase
      · subst phaseValue
        rw [projected_query_norm_zero_phase]
        exact mul_nonneg
          (mul_nonneg (by norm_num) instability.1.1)
          (by
            unfold fiberCoefficientNorm
            exact Finset.sum_nonneg fun base _ =>
              add_nonneg
                (Complex.normSq_nonneg _)
                (Finset.sum_nonneg fun output _ => Complex.normSq_nonneg _))
      · exact projected_query_norm_le_source_norm
          system phaseValue zeroPhase property queryBound input
            (blockCoefficients state input phaseValue workspace) instability
    _ = 6 * bound *
        ∑ input : Input,
          ∑ phaseValue : Phase,
            ∑ workspace : Workspace,
              fiberCoefficientNorm input
                (blockCoefficients state input phaseValue workspace) := by
      symm
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro input _
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro phaseValue _
      rw [Finset.mul_sum]

omit [DecidableEq Workspace] in
/-- Full exact CMS local-operator theorem for a normalized compressed-oracle state. -/
theorem full_projected_norm_le_six_instability
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (normalized : normSquared state <= 1) :
    fullProjectedNorm system property queryBound state <= 6 * bound := by
  calc
    fullProjectedNorm system property queryBound state <=
        6 * bound * fullSourceNorm state :=
      full_projected_norm_le_source_norm
        system property queryBound state instability
    _ = 6 * bound * normSquared state := by
      rw [full_source_norm_eq_norm_squared]
    _ <= 6 * bound * 1 := by
      exact mul_le_mul_of_nonneg_left normalized
        (mul_nonneg (by norm_num) instability.1.1)
    _ = 6 * bound := by ring

/--
Exact CMS local-operator theorem for the concrete compressed-oracle operator:
`‖P · O · complement(P) |state⟩‖² ≤ 6 · instability`.
-/
theorem norm_squared_projected_query_state_le_six_instability
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (normalized : normSquared state <= 1) :
    normSquared (projectedQueryState system property queryBound state) <=
      6 * bound := by
  rw [norm_squared_projected_query_state_eq_full_projected_norm]
  exact full_projected_norm_le_six_instability
    system property queryBound state instability normalized

end

end HegemonCrypto.CmsFullOperatorProof
