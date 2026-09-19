import HegemonCrypto.SmallWoodV8Smz9SourceIndexSampler
import Q38FieldAllocation
/- Fresh q38 mathematical maps and rank proofs. Shared 6-opening selected row
matrix is unchanged; tail nodes and interpolation cardinality are38/406.
No q20 tail admissibility/rank instance is reused. -/
namespace HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9HonestOpeningSchedule
open V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open Polynomial
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
def q38Openings : Nat := 38
def q38Coefficients : Nat := 406
abbrev Tails (F : Type*) := Fin 140 → Fin 38 → F
abbrev TailView (F : Type*) :=
  (Fin 12 → Fin 38 → F) × (Fin 38 → Fin 128 → F)
/-- The random tails occupy interpolation nodes 0 through 37 after Rust's left rotation. -/
def tailNode
    (tail : Fin q38Openings) : Fin q38Coefficients :=
  ⟨tail.val, by
    have tailBound := tail.isLt
    change tail.val < 38 at tailBound
    change tail.val < 406
    omega⟩

/-- One exact Lagrange coefficient in the complete 406-node rotated LVCS polynomial. -/
noncomputable def tailLagrangeCoefficient
    {F : Type*} [Field F]
    (target : F)
    (tail : Fin q38Openings) : F :=
  (Lagrange.basis
    (Finset.univ : Finset (Fin q38Coefficients))
    (fun source => (source.val : F))
    (tailNode tail)).eval target

/-- Exact 38-by-38 tail-evaluation map for one row. -/
noncomputable def tailEvaluationMap
    {F : Type*} [Field F]
    (targets : Fin q38Openings → F)
    (tail : Fin q38Openings → F) : Fin q38Openings → F :=
  fun opening =>
    ∑ coordinate : Fin q38Openings,
      tailLagrangeCoefficient (targets opening) coordinate *
        tail coordinate

def selectedTailMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (tails : Tails F) :
    Fin lvcsOpenedCombinationCount → Fin q38Openings → F :=
  fun combination tail =>
    smz9LvcsSelectedBlockMap points
      (fun selected => tails (smz9LvcsSelectedRow selected) tail) combination

def subsetContribution
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (tails : Tails F) :
    Fin lvcsOpenedCombinationCount → Fin q38Openings → F :=
  fun combination tail =>
    ∑ subset : Fin lvcsSubsetRowCount,
      smz9LvcsCombinationCoefficient points combination
          (smz9LvcsSubsetRow subset) *
        tails (smz9LvcsSubsetRow subset) tail

/--
Exact joint Rust wire order: twelve combination tails first, then thirty-eight opening-major
evaluations for the 128 nonselected rows.
-/
noncomputable def jointTailMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin q38Openings → F)
    (tails : Tails F) : TailView F :=
  (
    fun combination tail =>
      selectedTailMap points tails combination tail +
        subsetContribution points tails combination tail,
    fun opening subset =>
      tailEvaluationMap targets
        (fun tail => tails (smz9LvcsSubsetRow subset) tail) opening
  )

structure TailAdmissible
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin q38Openings → F) : Prop where
  pointsInjective : Function.Injective points
  targetsInjective : Function.Injective targets
  targetsOutsideInterpolationDomain :
    ∀ (opening : Fin q38Openings)
      (source : Fin q38Coefficients),
      targets opening ≠ (source.val : F)
  exactSelectedBlockInjective :
    Function.Injective (smz9LvcsSelectedBlockMap points)
  exactTailEvaluationInjective :
    Function.Injective (tailEvaluationMap targets)

theorem joint_tail_map_injective
    {F : Type*} [Field F]
    {points : Fin piopOpeningCount → F}
    {targets : Fin q38Openings → F}
    (admissible : TailAdmissible points targets) :
    Function.Injective (jointTailMap points targets) := by
  intro left right sameView
  have sameSubsetView := congrArg Prod.snd sameView
  have sameSubsetRows :
      ∀ subset : Fin lvcsSubsetRowCount,
        (fun tail => left (smz9LvcsSubsetRow subset) tail) =
          (fun tail => right (smz9LvcsSubsetRow subset) tail) := by
    intro subset
    apply admissible.exactTailEvaluationInjective
    funext opening
    exact congrFun (congrFun sameSubsetView opening) subset
  have sameCombinationView := congrArg Prod.fst sameView
  have sameSelectedTailMap :
      selectedTailMap points left =
        selectedTailMap points right := by
    funext combination tail
    have entry := congrFun (congrFun sameCombinationView combination) tail
    change
      selectedTailMap points left combination tail +
          subsetContribution points left combination tail =
        selectedTailMap points right combination tail +
          subsetContribution points right combination tail at entry
    have sameSubsetContribution :
        subsetContribution points left combination tail =
          subsetContribution points right combination tail := by
      apply Finset.sum_congr rfl
      intro subset _
      rw [congrFun (sameSubsetRows subset) tail]
    rw [sameSubsetContribution] at entry
    exact add_right_cancel entry
  have sameSelectedRows :
      ∀ selected : Fin lvcsOpenedCombinationCount,
        (fun tail => left (smz9LvcsSelectedRow selected) tail) =
          (fun tail => right (smz9LvcsSelectedRow selected) tail) := by
    intro selected
    funext tail
    have sameBlock :
        smz9LvcsSelectedBlockMap points
            (fun index => left (smz9LvcsSelectedRow index) tail) =
          smz9LvcsSelectedBlockMap points
            (fun index => right (smz9LvcsSelectedRow index) tail) := by
      funext combination
      exact congrFun (congrFun sameSelectedTailMap combination) tail
    exact congrFun (admissible.exactSelectedBlockInjective sameBlock) selected
  funext row tail
  rcases every_lvcs_row_is_selected_or_subset row with
    ⟨selected, selectedExact⟩ | ⟨subset, subsetExact⟩
  · rw [← selectedExact]
    exact congrFun (sameSelectedRows selected) tail
  · rw [← subsetExact]
    exact congrFun (sameSubsetRows subset) tail

noncomputable def jointTailLinearMap
    {F : Type*} [Field F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin q38Openings → F) :
    Tails F →ₗ[F] TailView F where
  toFun := jointTailMap points targets
  map_add' := by
    intro left right
    apply Prod.ext
    · funext combination tail
      simp [jointTailMap, selectedTailMap,
        smz9LvcsSelectedBlockMap, subsetContribution,
        mul_add, Finset.sum_add_distrib]
      abel
    · funext opening subset
      simp [jointTailMap, tailEvaluationMap,
        mul_add, Finset.sum_add_distrib]
  map_smul' := by
    intro scalar tails
    apply Prod.ext
    · funext combination tail
      simp [jointTailMap, selectedTailMap,
        smz9LvcsSelectedBlockMap, subsetContribution]
      rw [mul_add, Finset.mul_sum, Finset.mul_sum]
      apply congrArg₂ (· + ·) <;>
        apply Finset.sum_congr rfl <;> intro index _ <;> ring
    · funext opening subset
      simp [jointTailMap, tailEvaluationMap]
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro index _
      ring

theorem tail_view_cardinality_equal
    {F : Type*} [Fintype F] :
    Fintype.card (Tails F) =
      Fintype.card (TailView F) := by
  simp only [Tails, TailView]
  simp_rw [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin]
  simp_rw [Fintype.card_fun, Fintype.card_fin]
  rw [← pow_mul, ← pow_mul, ← pow_mul, ← pow_add]

noncomputable def jointTailAddEquiv
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin q38Openings → F)
    (admissible : TailAdmissible points targets) :
    Tails F ≃+ TailView F :=
  (LinearEquiv.ofBijective (jointTailLinearMap points targets)
    ((Fintype.bijective_iff_injective_and_card
      (jointTailLinearMap points targets)).2
      ⟨joint_tail_map_injective admissible,
        tail_view_cardinality_equal⟩)).toAddEquiv

theorem joint_tail_add_equiv_apply
    {F : Type*} [Field F] [Fintype F]
    (points : Fin piopOpeningCount → F)
    (targets : Fin q38Openings → F)
    (admissible : TailAdmissible points targets)
    (tails : Tails F) :
    jointTailAddEquiv points targets admissible tails =
      jointTailMap points targets tails := by
  change (jointTailLinearMap points targets) tails =
    jointTailMap points targets tails
  rfl


def tailPolynomial {F : Type*} [Field F] (tail : Fin 38 → F) : F[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin 406)) (fun node => (node.val : F))
    (Fin.append tail (fun _ : Fin 368 => 0))

theorem tail_polynomial_evaluation {F : Type*} [Field F]
    (targets : Fin 38 → F) (tail : Fin 38 → F) (opening : Fin 38) :
    (tailPolynomial tail).eval (targets opening) = tailEvaluationMap targets tail opening := by
  simp only [tailPolynomial, Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C]
  change (∑ node : Fin (38 + 368), _) = _
  rw [Fin.sum_univ_add]
  simp only [Fin.append_left, Fin.append_right, zero_mul, Finset.sum_const_zero, add_zero]
  unfold tailEvaluationMap tailLagrangeCoefficient tailNode
  apply Finset.sum_congr rfl
  intro index _
  exact mul_comm _ _

/-- There are 368 fixed zero head nodes and thirty-eight new distinct targets.
Consequently equality at the targets determines all thirty-eight tail values. -/
theorem actual_tail_evaluation_injective {F : Type*} [Field F]
    (nodesDistinct : Function.Injective (fun node : Fin 406 => (node.val : F)))
    (targets : Fin 38 → F) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 406), targets opening ≠ (node.val : F)) :
    Function.Injective (tailEvaluationMap targets) := by
  let combined : Fin 368 ⊕ Fin 38 → F :=
    Sum.elim (fun head => ((38 + head.val : Nat) : F)) targets
  have combinedDistinct : Function.Injective combined := by
    intro left right same
    cases left with
    | inl left =>
        cases right with
        | inl right =>
            have equal : (⟨38 + left.val, by omega⟩ : Fin 406) = ⟨38 + right.val, by omega⟩ :=
              nodesDistinct same
            have indices := congrArg Fin.val equal
            exact congrArg Sum.inl (Fin.ext (by simpa using indices))
        | inr right => exact (outside right ⟨38 + left.val, by omega⟩ same.symm).elim
    | inr left =>
        cases right with
        | inl right => exact (outside left ⟨38 + right.val, by omega⟩ same).elim
        | inr right => exact congrArg Sum.inr (targetsDistinct same)
  refine fun (left : Fin 38 → F) (right : Fin 38 → F) same => ?_
  have polynomials : tailPolynomial left = tailPolynomial right := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
      (Finset.univ : Finset (Fin 368 ⊕ Fin 38)) combinedDistinct.injOn
    · have degree := Lagrange.degree_interpolate_lt (s := (Finset.univ : Finset (Fin 406)))
        (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
      simpa only [tailPolynomial, Finset.card_univ, Fintype.card_sum, Fintype.card_fin, Nat.reduceAdd] using degree
    · have degree := Lagrange.degree_interpolate_lt (s := (Finset.univ : Finset (Fin 406)))
        (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
      simpa only [tailPolynomial, Finset.card_univ, Fintype.card_sum, Fintype.card_fin, Nat.reduceAdd] using degree
    · intro index _
      cases index with
      | inl head =>
          change (tailPolynomial left).eval ((38 + head.val : Nat) : F) =
            (tailPolynomial right).eval ((38 + head.val : Nat) : F)
          have leftEval := Lagrange.eval_interpolate_at_node
            (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd 38 head))
          have rightEval := Lagrange.eval_interpolate_at_node
            (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd 38 head))
          simp only [Fin.append_right] at leftEval rightEval
          exact leftEval.trans rightEval.symm
      | inr opening =>
          change (tailPolynomial left).eval (targets opening) = (tailPolynomial right).eval (targets opening)
          rw [tail_polynomial_evaluation, tail_polynomial_evaluation, same]
  funext index
  have leftEval := Lagrange.eval_interpolate_at_node
    (Fin.append left (fun _ : Fin 368 => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd 368 index))
  have rightEval := Lagrange.eval_interpolate_at_node
    (Fin.append right (fun _ : Fin 368 => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd 368 index))
  simp only [Fin.append_left] at leftEval rightEval
  have evals := congrArg (fun p : F[X] => p.eval (index.val : F)) polynomials
  exact leftEval.symm.trans (evals.trans rightEval)

theorem actual_interpolation_nodes_distinct :
    Function.Injective (fun node : Fin 406 => (node.val : Goldilocks)) := by
  intro left right same
  have leftBound : left.val < goldilocksModulus := left.isLt.trans_le (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans_le (by decide)
  have values := congrArg ZMod.val same
  simp only [ZMod.val_natCast, Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] at values
  exact Fin.ext values


/-- Rank is derived from distinct/outside points, not supplied as a simulator law. -/
theorem admissibleOfDistinct
    (points : Fin 6 → Goldilocks) (pointsDistinct : Function.Injective points)
    (targets : Fin 38 → Goldilocks) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 406), targets opening ≠ (node.val : Goldilocks)) :
    TailAdmissible points targets :=
  ⟨pointsDistinct, targetsDistinct, outside,
    actual_selected_block_injective pointsDistinct,
    actual_tail_evaluation_injective actual_interpolation_nodes_distinct
      targets targetsDistinct outside⟩
theorem q38_exact_counts :
    140 * 38 = 5320 ∧ 12 * 38 + 38 * 128 = 5320 ∧ 5 * 406 = 2030 := by decide
end
end HegemonCrypto.SmallWood.V8SmzaMathPrivacy
