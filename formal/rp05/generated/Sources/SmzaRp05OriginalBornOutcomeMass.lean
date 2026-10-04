import SmzaRp05CurrentAuthorizationCertificate
import HegemonCrypto.CmsAdaptiveClaimBridge

/-! Literal finite CMS outcome weights, retaining all original branches.
This is a change of summation order, not a coupling or a normalized
conditional distribution. The concrete consumer supplies its actual branch
states and accepted-branch predicate. -/
namespace HegemonCrypto.SmallWood.SmzaRp05OriginalBornOutcomeMass

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaRp05CurrentAuthorizationCertificate (outcomeEventMass)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false

variable {Branch Input Output Phase Workspace : Type}

def originalOutcomeWeight
    (states : Branch → State Input Output Phase Workspace)
    (outcome : Branch × Basis Input Output Phase Workspace) : ℝ :=
  Complex.normSq (states outcome.1 outcome.2)

theorem original_outcome_weight_nonnegative
    (states : Branch → State Input Output Phase Workspace)
    (outcome : Branch × Basis Input Output Phase Workspace) :
    0 ≤ originalOutcomeWeight states outcome :=
  Complex.normSq_nonneg _

variable [Fintype Branch]
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output]
variable [Fintype Phase]
variable [Fintype Workspace]

/-- Finite original branch/basis weights equal the exact branch projection
sum. Failed, aborted and unselected original branches remain in the space. -/
theorem original_event_mass_eq_projection_sum
    (states : Branch → State Input Output Phase Workspace)
    (event : Branch → Workspace → Database Input Output → Prop) :
    outcomeEventMass (originalOutcomeWeight states)
      (fun outcome => event outcome.1 outcome.2.workspace outcome.2.database) =
        ∑ branch, normSquared (workspaceEventProjection (event branch)
          (states branch)) := by
  classical
  unfold outcomeEventMass originalOutcomeWeight
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro branch _
  unfold normSquared
  apply Finset.sum_congr rfl
  intro basis _
  by_cases selected : event branch basis.workspace basis.database <;>
    simp [workspaceEventProjection, selected]

/-- The usual accepted-branch sum is an event on the same original outcome
space, not on an acceptance-conditioned or resampled distribution. -/
theorem original_accepted_event_mass_eq_projection_sum
    (states : Branch → State Input Output Phase Workspace)
    (accepted : Branch → Prop)
    (event : Branch → Workspace → Database Input Output → Prop) :
    outcomeEventMass (originalOutcomeWeight states)
      (fun outcome => accepted outcome.1 ∧
        event outcome.1 outcome.2.workspace outcome.2.database) =
      ∑ branch, if accepted branch then
        normSquared (workspaceEventProjection (event branch) (states branch))
      else 0 := by
  classical
  rw [original_event_mass_eq_projection_sum states
    (fun branch workspace database => accepted branch ∧
      event branch workspace database)]
  apply Finset.sum_congr rfl
  intro branch _
  by_cases branchAccepted : accepted branch
  · simp [branchAccepted]
  · simp [branchAccepted, workspaceEventProjection, normSquared]

end
end HegemonCrypto.SmallWood.SmzaRp05OriginalBornOutcomeMass
