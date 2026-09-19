import HegemonCrypto.SmallWoodV8Smz9CoherentMerklePartition

/-! Arbitrary database-label-controlled workspace permutations against the
actual physical CMS query. This includes Record/Split permutations; no global
operator-norm or extraction-success premise is supplied. -/
namespace HegemonCrypto.SmallWood.SmzaControlledCmsR2

open V8Smz9CoherentMerklePartition V8Smz9CoherentMerkleInstrument
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsFullOperatorProof
open scoped BigOperators Classical
noncomputable section

variable {Input Output Phase Label Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Label] [DecidableEq Label]
variable [Fintype Workspace] [DecidableEq Workspace]

def controlledBasis (value : Database Input Output → Label)
    (permutation : Label → (Label × Workspace) ≃ (Label × Workspace)) :
    Basis Input Output Phase (Label × Workspace) ≃ Basis Input Output Phase (Label × Workspace) where
  toFun basis := { basis with workspace := permutation (value basis.database) basis.workspace }
  invFun basis := { basis with workspace := (permutation (value basis.database)).symm basis.workspace }
  left_inv basis := by cases basis; simp
  right_inv basis := by cases basis; simp

omit [Fintype Phase] [Fintype Label] [Fintype Workspace] in
theorem controlled_same_label_kernel (system : PhaseSystem Output Phase) (cap : ℕ)
    (value : Database Input Output → Label)
    (permutation : Label → (Label × Workspace) ≃ (Label × Workspace))
    (source target : Basis Input Output Phase (Label × Workspace))
    (same : value source.database = value target.database) :
    boundedKernel system cap (controlledBasis value permutation source)
        (controlledBasis value permutation target) = boundedKernel system cap source target := by
  simp [boundedKernel, kernel, controlledBasis, same]

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
  [Fintype Phase] [DecidableEq Phase] [Fintype Label] [DecidableEq Label]
  [Fintype Workspace] [DecidableEq Workspace] in
theorem controlled_preserves_bounded (value : Database Input Output → Label)
    (permutation : Label → (Label × Workspace) ≃ (Label × Workspace))
    (support : ℕ) (state : State Input Output Phase (Label × Workspace))
    (bounded : BoundedState support state) :
    BoundedState support (permute (controlledBasis value permutation) state) := by
  funext basis
  have atBasis := congrFun bounded ((controlledBasis value permutation).symm basis)
  simpa [project, permute, Function.comp_def, controlledBasis] using atBasis

/-- Genuine full controlled-permutation bound, derived from classical Boolean
instability via the existing physical kernel and dimension-free sign proof. -/
theorem controlled_bounded_query_bound (system : PhaseSystem Output Phase) (cap : ℕ)
    (value : Database Input Output → Label)
    (permutation : Label → (Label × Workspace) ≃ (Label × Workspace))
    (bound : ℝ)
    (instability : ∀ test : Label → Prop,
      RealInstabilityBound (fun database => test (value database)) cap bound)
    (state : State Input Output Phase (Label × Workspace)) :
    normSquared (permute (controlledBasis value permutation) (boundedQuery system cap state) -
      boundedQuery system cap (permute (controlledBasis value permutation) state)) ≤
      192 * bound * normSquared state := by
  have result := full_permutation_commutator_bound
    (fun basis : Basis Input Output Phase (Label × Workspace) => value basis.database)
    (boundedKernel system cap) (controlledBasis value permutation) (by intro basis; rfl)
    (controlled_same_label_kernel system cap value permutation)
    (48 * bound) (by
      intro selection selectedState
      rw [sign_commutator_is_cms_reflection]
      exact reflection_commutator_bound system _ cap selectedState
        (instability (fun label => selection label = true))) state
  rw [bounded_kernel_apply, bounded_kernel_apply] at result
  change normSquared _ ≤ 4 * (48 * bound) * normSquared state at result
  convert result using 1
  ring

theorem controlled_actual_query_bound (system : PhaseSystem Output Phase) (cap support : ℕ)
    (value : Database Input Output → Label)
    (permutation : Label → (Label × Workspace) ≃ (Label × Workspace))
    (bound : ℝ)
    (instability : ∀ test : Label → Prop,
      RealInstabilityBound (fun database => test (value database)) cap bound)
    (state : State Input Output Phase (Label × Workspace))
    (below : support < cap) (bounded : BoundedState support state) :
    normSquared (permute (controlledBasis value permutation) (queryState system cap state) -
      queryState system cap (permute (controlledBasis value permutation) state)) ≤
      192 * bound * normSquared state := by
  have result := controlled_bounded_query_bound system cap value permutation bound instability state
  rw [bounded_query_eq_query system cap support state below bounded,
    bounded_query_eq_query system cap support _ below
      (controlled_preserves_bounded value permutation support state bounded)] at result
  exact result

end
end HegemonCrypto.SmallWood.SmzaControlledCmsR2
