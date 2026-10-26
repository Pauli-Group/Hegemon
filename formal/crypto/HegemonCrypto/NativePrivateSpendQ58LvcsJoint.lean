import HegemonCrypto.NativePrivateSpendQ58SimulationAlgebra
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator
import HegemonCrypto.SmallWoodV8Smz9HonestOpeningSchedule

/-!
Exact q58 LVCS algebra at fixed six PIOP points and committed heads.
First invert the source's selected/subset row observation independently for
all58 tail columns, then invert each subset row's58-target interpolation.
No arbitrary coefficient matrix is assumed full rank. Later targets may
feed back from the same tails' retained696-word prefix; sampler failure is
retained explicitly. This is not the complete PIOP/DECS/oracle privacy game.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58LvcsJoint

open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9EagerSimulator V8Smz9HonestOpeningSchedule V8Smz9TriangularAlgebraicLaw
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

abbrev Heads := Fin 140 → Fin 13112 → Goldilocks
abbrev Tails := Fin 140 → Fin 58 → Goldilocks
abbrev Earlier := Fin 12 → Fin 58 → Goldilocks
abbrev SubsetTails := Fin 128 → Fin 58 → Goldilocks
abbrev Later := Fin 58 → Fin 128 → Goldilocks
abbrev Targets := { targets : Fin 58 → Goldilocks //
  Function.Injective targets ∧
    ∀ opening (node : Fin 13170), targets opening ≠ (node.val : Goldilocks) }

/-- Literal engine C-times-tail matrix product, in combination-major order. -/
def earlier (points : Fin 6 → Goldilocks) (tails : Tails) : Earlier :=
  fun combination tail => rowCombination points (fun row => tails row tail) combination

/-- Invert the actual two interleaved Vandermonde selected blocks. The
complement rows are carried jointly, so their correlations are not erased. -/
def rowSplitEquiv (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) : Tails ≃ (Earlier × SubsetTails) where
  toFun tails := (earlier points tails,
    fun subset tail => tails (smz9LvcsSubsetRow subset) tail)
  invFun view := fun row tail =>
    (rowObservationEquiv points (actual_selected_block_injective distinct)).symm
      (fun combination => view.1 combination tail, fun subset => view.2 subset tail) row
  left_inv tails := by
    funext row tail
    exact congrFun
      ((rowObservationEquiv points (actual_selected_block_injective distinct)).symm_apply_apply
        (fun row => tails row tail)) row
  right_inv view := by
    apply Prod.ext
    · funext combination tail
      exact congrFun (congrArg Prod.fst
        ((rowObservationEquiv points (actual_selected_block_injective distinct)).apply_symm_apply
          (fun combination => view.1 combination tail, fun subset => view.2 subset tail))) combination
    · funext subset tail
      exact congrFun (congrArg Prod.snd
        ((rowObservationEquiv points (actual_selected_block_injective distinct)).apply_symm_apply
          (fun combination => view.1 combination tail, fun subset => view.2 subset tail))) subset

def headContribution (heads : Heads) (targets : Fin 58 → Goldilocks) : Later :=
  fun opening subset => ∑ column : Fin 13112,
    heads (smz9LvcsSubsetRow subset) column *
      (Lagrange.basis (Finset.univ : Finset (Fin 13170))
        (fun node => (node.val : Goldilocks)) (Fin.natAdd 58 column)).eval (targets opening)

def fullSubset (heads : Heads) (targets : Fin 58 → Goldilocks) (tails : Tails) : Later :=
  fun opening subset => headContribution heads targets opening subset +
    NativePrivateSpendQ58SimulationAlgebra.tailEvaluationMap 13112 targets
      (fun tail => tails (smz9LvcsSubsetRow subset) tail) opening

/-- This is exactly evaluation of the rotated58-tail/13112-head row. -/
theorem full_subset_is_rotated_interpolation (heads : Heads)
    (targets : Fin 58 → Goldilocks) (tails : Tails) (opening : Fin 58) (subset : Fin 128) :
    fullSubset heads targets tails opening subset =
      (Lagrange.interpolate (Finset.univ : Finset (Fin 13170))
        (fun node => (node.val : Goldilocks))
        (Fin.append (tails (smz9LvcsSubsetRow subset))
          (heads (smz9LvcsSubsetRow subset)))).eval (targets opening) := by
  symm
  simp only [Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C]
  change (∑ node : Fin (58 + 13112), _) = _
  rw [Fin.sum_univ_add]
  simp only [Fin.append_left, Fin.append_right]
  simp [fullSubset, headContribution,
    NativePrivateSpendQ58SimulationAlgebra.tailEvaluationMap, mul_comm, add_comm]

def shiftEquiv (offset : Fin 58 → Goldilocks) :
    (Fin 58 → Goldilocks) ≃ (Fin 58 → Goldilocks) where
  toFun value := offset + value
  invFun value := value - offset
  left_inv value := by
    funext i
    change offset i + value i - offset i = value i
    ring
  right_inv value := by
    funext i
    change offset i + (value i - offset i) = value i
    ring

/-- Each subset row is inverted using the proved58-target interpolation rank.
Targets supply only data-level distinctness/outside-domain conditions. -/
def subsetRowEquiv (heads : Heads) (targets : Targets) (subset : Fin 128) :
    (Fin 58 → Goldilocks) ≃ (Fin 58 → Goldilocks) :=
  (NativePrivateSpendQ58SimulationAlgebra.tailEvaluationEquiv (q := 58) (h := 13112)
    NativePrivateSpendQ58SimulationAlgebra.q58_nodes_distinct
    targets.val targets.property.1 targets.property.2).trans
      (shiftEquiv (fun opening => headContribution heads targets.val opening subset))

def subsetOutputsEquiv (heads : Heads) (targets : Targets) : SubsetTails ≃ Later where
  toFun tails := fun opening subset => subsetRowEquiv heads targets subset (tails subset) opening
  invFun output := fun subset =>
    (subsetRowEquiv heads targets subset).symm (fun opening => output opening subset)
  left_inv tails := by
    funext subset
    exact (subsetRowEquiv heads targets subset).symm_apply_apply (tails subset)
  right_inv output := by
    funext opening subset
    exact congrFun ((subsetRowEquiv heads targets subset).apply_symm_apply
      (fun opening => output opening subset)) opening

/-- Exact affine bijection:140x58 fresh tails ->12x58 published tails and
58x128 opened subset values. All8120 field coordinates are retained. -/
def jointViewEquiv (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : Heads) (targets : Targets) : Tails ≃ (Earlier × Later) :=
  (rowSplitEquiv points distinct).trans
    (Equiv.prodCongr (Equiv.refl Earlier) (subsetOutputsEquiv heads targets))

theorem joint_view_exact (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : Heads) (targets : Targets) (tails : Tails) :
    jointViewEquiv points distinct heads targets tails =
      (earlier points tails, fullSubset heads targets.val tails) := rfl

theorem joint_view_retains_prefix (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : Heads) (targets : Targets) (tails : Tails) :
    (jointViewEquiv points distinct heads targets tails).1 = earlier points tails := rfl

/-- Fixed challenges: the entire published/opened vector is uniform jointly. -/
theorem fixed_joint_uniform (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : Heads) (targets : Targets) :
    pmfMap (uniformFintypePMF Tails)
      (fun tails => (earlier points tails, fullSubset heads targets.val tails)) =
      uniformFintypePMF (Earlier × Later) :=
  uniform_pmf_map_equiv (jointViewEquiv points distinct heads targets)

/-- Same-tail feedback is justified by retaining precisely the prefix used
by the selector; its inverse chooses targets from the supplied output prefix. -/
def feedbackEquiv (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : Heads) (choose : Earlier → Targets) : Tails ≃ (Earlier × Later) :=
  triangularChallengeEquiv (jointViewEquiv points distinct heads)
    (earlier points) (joint_view_retains_prefix points distinct heads) choose

theorem feedback_exact (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (heads : Heads) (choose : Earlier → Targets) (tails : Tails) :
    feedbackEquiv points distinct heads choose tails =
      (earlier points tails, fullSubset heads (choose (earlier points tails)).val tails) := rfl

theorem feedback_joint_uniform (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : Heads) (choose : Earlier → Targets) :
    pmfMap (uniformFintypePMF Tails)
      (fun tails => (earlier points tails,
        fullSubset heads (choose (earlier points tails)).val tails)) =
      uniformFintypePMF (Earlier × Later) :=
  uniform_pmf_map_equiv (feedbackEquiv points distinct heads choose)

/-- Abort is an output, not an unpriced conditioning operation. -/
def partialOutput (points : Fin 6 → Goldilocks) (heads : Heads)
    (choose : Earlier → Option Targets) (tails : Tails) : Earlier × Option Later :=
  let early := earlier points tails
  (early, (choose early).map fun targets => fullSubset heads targets.val tails)

theorem partial_feedback_joint_law (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (heads : Heads) (fallback : Targets)
    (choose : Earlier → Option Targets) :
    pmfMap (uniformFintypePMF Tails) (partialOutput points heads choose) =
      pmfMap (uniformFintypePMF (Earlier × Later))
        (fun view => (view.1, (choose view.1).map fun _ => view.2)) := by
  let totalChoose : Earlier → Targets := fun early => (choose early).getD fallback
  let observe : Earlier × Later → Earlier × Option Later :=
    fun view => (view.1, (choose view.1).map fun _ => view.2)
  have uniform := feedback_joint_uniform points distinct heads totalChoose
  have pushed := congrArg (fun law => pmfMap law observe) uniform
  rw [pmfMap_comp] at pushed
  have sameFunction :
      observe ∘ (fun tails => (earlier points tails,
        fullSubset heads (totalChoose (earlier points tails)).val tails)) =
        partialOutput points heads choose := by
    funext tails
    cases selected : choose (earlier points tails) with
    | none => simp [observe, partialOutput, selected]
    | some targets => simp [observe, partialOutput, totalChoose, selected]
  rw [sameFunction] at pushed
  exact pushed

/-- Head offsets cannot distinguish the joint view when the public selection
rule is the same; failed selections remain visible on both sides. -/
theorem partial_head_independence (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (left right : Heads) (fallback : Targets)
    (choose : Earlier → Option Targets) :
    pmfMap (uniformFintypePMF Tails) (partialOutput points left choose) =
      pmfMap (uniformFintypePMF Tails) (partialOutput points right choose) := by
  rw [partial_feedback_joint_law points distinct left fallback choose,
    partial_feedback_joint_law points distinct right fallback choose]

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58LvcsJoint
