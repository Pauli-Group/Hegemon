import HegemonCrypto.SmallWoodV8Smz9JointAlgebraicLaw
import HegemonCrypto.SmallWoodV8Smz9TriangularAlgebraicLaw

/-!
A q58 simulation component, not a complete SMZD zero-knowledge endpoint.
The tail rank proof below is generic in both tail and head count. It uses
polynomial root uniqueness, not an assumed rank or simulated distribution.
The DECS law instantiates the existing dimension-generic evaluation/high map
at the actual 5 x (58 + 13112) dimensions. Challenges and head offsets are
fixed independently of these fresh ideal coins, except for the explicitly
proved feedback from published DECS highs below. Full adaptive conditioning and
Rust/oracle refinement remain separate obligations.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58SimulationAlgebra

open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9JointAlgebraicLaw V8Smz9TriangularAlgebraicLaw
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

/-- Rust rotates tails to the first q nodes and heads to the remaining h nodes. -/
def tailPolynomial {F : Type*} [Field F] {q : Nat}
    (h : Nat) (tail : Fin q → F) : F[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin (q + h)))
    (fun node => (node.val : F)) (Fin.append tail (fun _ : Fin h => 0))

def tailEvaluationMap {F : Type*} [Field F] {q : Nat}
    (h : Nat) (targets : Fin q → F) (tail : Fin q → F) : Fin q → F :=
  fun opening => ∑ coordinate : Fin q,
    (Lagrange.basis (Finset.univ : Finset (Fin (q + h)))
      (fun node => (node.val : F)) (Fin.castAdd h coordinate)).eval
        (targets opening) * tail coordinate

theorem tail_polynomial_evaluation {F : Type*} [Field F] {q : Nat}
    (h : Nat) (targets : Fin q → F) (tail : Fin q → F) (opening : Fin q) :
    (tailPolynomial h tail).eval (targets opening) =
      tailEvaluationMap h targets tail opening := by
  simp only [tailPolynomial, Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C]
  rw [Fin.sum_univ_add]
  simp only [Fin.append_left, Fin.append_right, zero_mul, Finset.sum_const_zero, add_zero]
  unfold tailEvaluationMap
  apply Finset.sum_congr rfl
  intro index _
  exact mul_comm _ _

/-- h prescribed zero nodes plus q distinct outside targets determine a
polynomial of degree < q+h. This proves rank without a rank hypothesis. -/
theorem tail_evaluation_injective {F : Type*} [Field F] {q h : Nat}
    (nodesDistinct : Function.Injective (fun node : Fin (q + h) => (node.val : F)))
    (targets : Fin q → F) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin (q + h)), targets opening ≠ (node.val : F)) :
    Function.Injective (tailEvaluationMap h targets) := by
  let combined : Fin h ⊕ Fin q → F :=
    Sum.elim (fun head => ((q + head.val : Nat) : F)) targets
  have combinedDistinct : Function.Injective combined := by
    intro left right same
    cases left with
    | inl left =>
        cases right with
        | inl right =>
            have equal : (⟨q + left.val, by omega⟩ : Fin (q + h)) =
                ⟨q + right.val, by omega⟩ := nodesDistinct same
            have indices := congrArg Fin.val equal
            exact congrArg Sum.inl (Fin.ext (by simpa using indices))
        | inr right => exact (outside right ⟨q + left.val, by omega⟩ same.symm).elim
    | inr left =>
        cases right with
        | inl right => exact (outside left ⟨q + right.val, by omega⟩ same).elim
        | inr right => exact congrArg Sum.inr (targetsDistinct same)
  intro left right same
  have polynomials : tailPolynomial h left = tailPolynomial h right := by
    apply Polynomial.eq_of_degrees_lt_of_eval_index_eq
      (Finset.univ : Finset (Fin h ⊕ Fin q)) combinedDistinct.injOn
    · have degree := Lagrange.degree_interpolate_lt
        (s := (Finset.univ : Finset (Fin (q + h))))
        (Fin.append left (fun _ : Fin h => 0)) nodesDistinct.injOn
      simpa [tailPolynomial, Nat.add_comm] using degree
    · have degree := Lagrange.degree_interpolate_lt
        (s := (Finset.univ : Finset (Fin (q + h))))
        (Fin.append right (fun _ : Fin h => 0)) nodesDistinct.injOn
      simpa [tailPolynomial, Nat.add_comm] using degree
    · intro index _
      cases index with
      | inl head =>
          change (tailPolynomial h left).eval ((q + head.val : Nat) : F) =
            (tailPolynomial h right).eval ((q + head.val : Nat) : F)
          have leftEval := Lagrange.eval_interpolate_at_node
            (Fin.append left (fun _ : Fin h => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd q head))
          have rightEval := Lagrange.eval_interpolate_at_node
            (Fin.append right (fun _ : Fin h => 0)) nodesDistinct.injOn
            (Finset.mem_univ (Fin.natAdd q head))
          simp only [Fin.append_right] at leftEval rightEval
          exact leftEval.trans rightEval.symm
      | inr opening =>
          change (tailPolynomial h left).eval (targets opening) =
            (tailPolynomial h right).eval (targets opening)
          rw [tail_polynomial_evaluation, tail_polynomial_evaluation, same]
  funext index
  have leftEval := Lagrange.eval_interpolate_at_node
    (Fin.append left (fun _ : Fin h => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd h index))
  have rightEval := Lagrange.eval_interpolate_at_node
    (Fin.append right (fun _ : Fin h => 0)) nodesDistinct.injOn
    (Finset.mem_univ (Fin.castAdd h index))
  simp only [Fin.append_left] at leftEval rightEval
  have evals := congrArg (fun p : F[X] => p.eval (index.val : F)) polynomials
  exact leftEval.symm.trans (evals.trans rightEval)

/-- Finite-field bijection derived from the proved injectivity. -/
def tailEvaluationEquiv {F : Type*} [Field F] [Fintype F] {q h : Nat}
    (nodesDistinct : Function.Injective (fun node : Fin (q + h) => (node.val : F)))
    (targets : Fin q → F) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin (q + h)), targets opening ≠ (node.val : F)) :
    (Fin q → F) ≃ (Fin q → F) :=
  Equiv.ofBijective (tailEvaluationMap h targets)
    ((Fintype.bijective_iff_injective_and_card (tailEvaluationMap h targets)).2
      ⟨tail_evaluation_injective nodesDistinct targets targetsDistinct outside, rfl⟩)

theorem tail_evaluation_uniform {F : Type*} [Field F] [Fintype F] {q h : Nat}
    (nodesDistinct : Function.Injective (fun node : Fin (q + h) => (node.val : F)))
    (targets : Fin q → F) (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin (q + h)), targets opening ≠ (node.val : F)) :
    pmfMap (uniformFintypePMF (Fin q → F)) (tailEvaluationMap h targets) =
      uniformFintypePMF (Fin q → F) :=
  uniform_pmf_map_equiv (tailEvaluationEquiv nodesDistinct targets targetsDistinct outside)

abbrev Heads (F : Type*) := Fin 140 → Fin 13112 → F
abbrev Tails (F : Type*) := Fin 140 → Fin 58 → F
abbrev PublishedTails (F : Type*) := Fin 12 → Fin 58 → F
abbrev SubsetView (F : Type*) := Fin 58 → Fin 128 → F
abbrev RowOpenings (F : Type*) := Fin 6 → Fin 26213 → F
abbrev DecsCoordinates (F : Type*) := EvaluationHighCoordinates F 5 58 13112

/-- The new 13170-node domain is injective in Goldilocks. -/
theorem q58_nodes_distinct :
    Function.Injective (fun node : Fin 13170 => (node.val : Goldilocks)) := by
  intro left right same
  have leftBound : left.val < goldilocksModulus := left.isLt.trans_le (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans_le (by decide)
  have values := congrArg ZMod.val same
  simp only [ZMod.val_natCast, Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] at values
  exact Fin.ext values

/-- Exact 58-target rank for the source's rotated row polynomial. -/
theorem q58_tail_rank (targets : Fin 58 → Goldilocks)
    (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 13170), targets opening ≠ (node.val : Goldilocks)) :
    Function.Injective (tailEvaluationMap 13112 targets) :=
  tail_evaluation_injective (q := 58) (h := 13112) q58_nodes_distinct targets targetsDistinct outside

/-- Simultaneous evaluation of all 140 independent rows, before exposing
selected combinations. This is a component, not the 12+128 joint tail law. -/
def q58AllRowTailEquiv (targets : Fin 58 → Goldilocks)
    (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 13170), targets opening ≠ (node.val : Goldilocks)) :
    Tails Goldilocks ≃ Tails Goldilocks :=
  Equiv.piCongrRight fun _ : Fin 140 =>
    tailEvaluationEquiv (q := 58) (h := 13112) q58_nodes_distinct targets targetsDistinct outside

theorem q58_all_row_tail_uniform (targets : Fin 58 → Goldilocks)
    (targetsDistinct : Function.Injective targets)
    (outside : ∀ opening (node : Fin 13170), targets opening ≠ (node.val : Goldilocks)) :
    pmfMap (uniformFintypePMF (Tails Goldilocks))
        (fun tails row => tailEvaluationMap 13112 targets (tails row)) =
      uniformFintypePMF (Tails Goldilocks) :=
  uniform_pmf_map_equiv (q58AllRowTailEquiv targets targetsDistinct outside)

/-- DECS wire order is opened mask evaluations plus high coefficients of
mask+data. The fixed data offset contributes only to the high coordinates. -/
def decsWireOffset {F : Type*} [Field F] (dataHigh : Fin 5 → Fin 13112 → F) :
    DecsCoordinates F := fun polynomial => (0, dataHigh polynomial)

def decsWireView {F : Type*} [Field F] (targets : Fin 58 → F)
    (dataHigh : Fin 5 → Fin 13112 → F) (mask : DecsCoordinates F) : DecsCoordinates F :=
  decsWireOffset dataHigh + evaluationHighMap targets mask

def decsWireEquiv {F : Type*} [Field F] [Fintype F]
    (targets : Fin 58 → F) (targetsDistinct : Function.Injective targets)
    (dataHigh : Fin 5 → Fin 13112 → F) : DecsCoordinates F ≃ DecsCoordinates F :=
  affineOutputEquiv (evaluationHighAddEquiv targets targetsDistinct) (decsWireOffset dataHigh)

theorem decs_wire_evaluation {F : Type*} [Field F]
    (targets : Fin 58 → F) (dataHigh : Fin 5 → Fin 13112 → F)
    (mask : DecsCoordinates F) (polynomial : Fin 5) (opening : Fin 58) :
    (decsWireView targets dataHigh mask polynomial).1 opening =
      (∑ low : Fin 58, (mask polynomial).1 low * targets opening ^ low.val) +
      ∑ high : Fin 13112,
        (mask polynomial).2 high * targets opening ^ (58 + high.val) := by
  simp [decsWireView, decsWireOffset, evaluationHighMap]

theorem decs_wire_high {F : Type*} [Field F]
    (targets : Fin 58 → F) (dataHigh : Fin 5 → Fin 13112 → F)
    (mask : DecsCoordinates F) (polynomial : Fin 5) :
    (decsWireView targets dataHigh mask polynomial).2 =
      dataHigh polynomial + (mask polynomial).2 := rfl

/-- Joint uniformity of all 5*(58+13112) coordinates, not only marginals.
No equality-of-distributions or extracted-mask-output premise is supplied. -/
theorem q58_decs_mask_joint_uniform {F : Type*} [Field F] [Fintype F]
    (targets : Fin 58 → F) (targetsDistinct : Function.Injective targets)
    (dataHigh : Fin 5 → Fin 13112 → F) :
    pmfMap (uniformFintypePMF (DecsCoordinates F)) (decsWireView targets dataHigh) =
      uniformFintypePMF (DecsCoordinates F) :=
  uniform_pmf_map_equiv (decsWireEquiv targets targetsDistinct dataHigh)

/-- Two fixed data-high offsets induce the same complete DECS view law. -/
theorem q58_decs_mask_offset_independent {F : Type*} [Field F] [Fintype F]
    (targets : Fin 58 → F) (targetsDistinct : Function.Injective targets)
    (left right : Fin 5 → Fin 13112 → F) :
    pmfMap (uniformFintypePMF (DecsCoordinates F)) (decsWireView targets left) =
      pmfMap (uniformFintypePMF (DecsCoordinates F)) (decsWireView targets right) := by
  rw [q58_decs_mask_joint_uniform targets targetsDistinct,
    q58_decs_mask_joint_uniform targets targetsDistinct]

/-- Reorder the exact DECS view to its source chronology: highs before
opened mask evaluations. All coordinates are retained. -/
abbrev DecsHigh (F : Type*) := Fin 5 → Fin 13112 → F
abbrev DecsOpened (F : Type*) := Fin 5 → Fin 58 → F
abbrev DistinctTargets (F : Type*) := { targets : Fin 58 → F // Function.Injective targets }

def decsPublishedHigh {F : Type*} [Field F]
    (dataHigh : DecsHigh F) (mask : DecsCoordinates F) : DecsHigh F :=
  fun polynomial => dataHigh polynomial + (mask polynomial).2

def decsChronologicalEquiv {F : Type*} [Field F] [Fintype F]
    (targets : DistinctTargets F) (dataHigh : DecsHigh F) :
    DecsCoordinates F ≃ (DecsHigh F × DecsOpened F) :=
  (decsWireEquiv targets.val targets.property dataHigh).trans
    ((Equiv.arrowProdEquivProdArrow (Fin 5)
      (fun _ => Fin 58 → F) (fun _ => Fin 13112 → F)).trans
        (Equiv.prodComm _ _))

theorem decs_chronological_retains_high {F : Type*} [Field F] [Fintype F]
    (dataHigh : DecsHigh F) (targets : DistinctTargets F) (mask : DecsCoordinates F) :
    (decsChronologicalEquiv targets dataHigh mask).1 = decsPublishedHigh dataHigh mask := rfl

/-- Later points may be selected from the SAME coins' published high vector.
No conditional-uniformity premise is asserted: triangular inversion proves it.
The selector may capture arbitrary fixed prior public history, but must not
read another hidden function of these fresh mask coins. -/
theorem q58_decs_high_feedback_joint_uniform {F : Type*} [Field F] [Fintype F]
    (dataHigh : DecsHigh F) (choose : DecsHigh F → DistinctTargets F) :
    pmfMap (uniformFintypePMF (DecsCoordinates F))
        (fun mask => decsChronologicalEquiv
          (choose (decsPublishedHigh dataHigh mask)) dataHigh mask) =
      uniformFintypePMF (DecsHigh F × DecsOpened F) :=
  triangular_challenge_joint_uniform_law
    (fun targets => decsChronologicalEquiv targets dataHigh)
    (decsPublishedHigh dataHigh) (decs_chronological_retains_high dataHigh) choose

theorem q58_coordinate_counts :
    140 * 58 = 8120 ∧ 12 * 58 = 696 ∧ 58 * 128 = 7424 ∧
      696 + 7424 = 8120 ∧ 58 + 13112 = 13170 ∧
      5 * 13170 = 65850 ∧ 6 * 26213 = 157278 := by decide

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58SimulationAlgebra
