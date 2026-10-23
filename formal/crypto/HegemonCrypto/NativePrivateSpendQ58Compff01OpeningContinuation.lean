import HegemonCrypto.NativePrivateSpendQ58SimulationAlgebra
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator
import HegemonCrypto.SmallWoodV8Smz9HonestOpeningSchedule

/-!
Current COMPFF01 q58 LVCS algebra at six PIOP points and 13115-wide heads.
First invert the source's selected/subset row observation independently for
all58 tail columns, then invert each subset row's58-target interpolation.
No arbitrary coefficient matrix is assumed full rank. Later targets may
feed back from the same tails' retained696-word prefix; sampler failure is
retained explicitly. This is not the complete PIOP/DECS/oracle privacy game.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01OpeningContinuation

open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9RuntimeFieldLayout
open V8Smz9EagerSimulator V8Smz9HonestOpeningSchedule V8Smz9TriangularAlgebraicLaw
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev Heads := Fin 140 → Fin 13115 → Goldilocks
abbrev Tails := Fin 140 → Fin 58 → Goldilocks
abbrev Earlier := Fin 12 → Fin 58 → Goldilocks
abbrev SubsetTails := Fin 128 → Fin 58 → Goldilocks
abbrev Later := Fin 58 → Fin 128 → Goldilocks
abbrev Targets := { targets : Fin 58 → Goldilocks //
  Function.Injective targets ∧
    ∀ opening (node : Fin 13173), targets opening ≠ (node.val : Goldilocks) }

/-- Current 58+13115 interpolation coordinates embed injectively in Goldilocks.
This is a new bound, not an alias to the old 13170-node theorem. -/
theorem current_nodes_distinct :
    Function.Injective (fun node : Fin 13173 => (node.val : Goldilocks)) := by
  intro left right same
  have leftBound : left.val < goldilocksModulus := left.isLt.trans_le (by decide)
  have rightBound : right.val < goldilocksModulus := right.isLt.trans_le (by decide)
  have values := congrArg ZMod.val same
  simp only [ZMod.val_natCast, Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound] at values
  exact Fin.ext values

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
  fun opening subset => ∑ column : Fin 13115,
    heads (smz9LvcsSubsetRow subset) column *
      (Lagrange.basis (Finset.univ : Finset (Fin 13173))
        (fun node => (node.val : Goldilocks)) (Fin.natAdd 58 column)).eval (targets opening)

def fullSubset (heads : Heads) (targets : Fin 58 → Goldilocks) (tails : Tails) : Later :=
  fun opening subset => headContribution heads targets opening subset +
    NativePrivateSpendQ58SimulationAlgebra.tailEvaluationMap 13115 targets
      (fun tail => tails (smz9LvcsSubsetRow subset) tail) opening

/-- This is exactly evaluation of the rotated58-tail/13115-head row. -/
theorem full_subset_is_rotated_interpolation (heads : Heads)
    (targets : Fin 58 → Goldilocks) (tails : Tails) (opening : Fin 58) (subset : Fin 128) :
    fullSubset heads targets tails opening subset =
      (Lagrange.interpolate (Finset.univ : Finset (Fin 13173))
        (fun node => (node.val : Goldilocks))
        (Fin.append (tails (smz9LvcsSubsetRow subset))
          (heads (smz9LvcsSubsetRow subset)))).eval (targets opening) := by
  symm
  simp only [Lagrange.interpolate_apply, eval_finsetSum, eval_mul, eval_C]
  change (∑ node : Fin (58 + 13115), _) = _
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
  (NativePrivateSpendQ58SimulationAlgebra.tailEvaluationEquiv (q := 58) (h := 13115)
    current_nodes_distinct
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


/-! The exact current pcs_commit -> pcs_build_coefficients -> lvcs_open head
identity. Coefficient vectors are the actual input of the matrix operation;
no claimed source/public factorization equality is accepted as a premise. -/
open V8Smz9EagerPrivacy
abbrev CurrentColumns := Fin 26230 → Fin 70 → Goldilocks

def stackedHeads (columns : CurrentColumns) : Heads := fun row column =>
  let position := (finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).symm row
  columns (finProdFinEquiv (position.1, column)) position.2

/-- Literal Rust offsets i%70 and (i/70)*13115; both blocks are complete. -/
theorem stacked_head_source_offsets (columns : CurrentColumns)
    (row : Fin 140) (column : Fin 13115) :
    stackedHeads columns row column = columns
      ⟨(row.val / 70) * 13115 + column.val, by
        have hr := row.isLt
        have hc := column.isLt
        omega⟩
      ⟨row.val % 70, Nat.mod_lt _ (by decide)⟩ := by
  dsimp only [stackedHeads]
  apply congrArg₂ columns
  · apply Fin.ext
    change column.val + 13115 * (row.val / 70) = (row.val / 70) * 13115 + column.val
    ac_rfl
  · rfl

def combinationHeads (points : Fin 6 → Goldilocks) (heads : Heads) :
    Fin 12 → Fin 13115 → Goldilocks :=
  fun combination column => rowCombination points (fun row => heads row column) combination

def evaluationHeads (points : Fin 6 → Goldilocks) (columns : CurrentColumns) :
    Fin 12 → Fin 13115 → Goldilocks := fun combination column =>
  let position := (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).symm combination
  (coefficientPolynomial (columns (finProdFinEquiv (position.2, column)))).eval
    (points position.1)

/-- Current 12x140 by 140x13115 matrix product equals the exact evaluations.
The proof uses the source's two 70-coefficient blocks, not a full-rank assumption. -/
theorem combination_head_is_evaluation (points : Fin 6 → Goldilocks)
    (columns : CurrentColumns) (opening : Fin 6) (block : Fin 2)
    (column : Fin 13115) :
    combinationHeads points (stackedHeads columns)
      (finProdFinEquiv (opening, block)) column =
      (coefficientPolynomial (columns (finProdFinEquiv (block, column)))).eval
        (points opening) := by
  unfold combinationHeads rowCombination
  calc
    _ = ∑ position : Fin 2 × Fin 70,
        smz9LvcsCombinationCoefficient points (finProdFinEquiv (opening, block))
          (finProdFinEquiv position) *
        stackedHeads columns (finProdFinEquiv position) column :=
      ((finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).sum_comp
        (fun row : Fin 140 =>
          smz9LvcsCombinationCoefficient points (finProdFinEquiv (opening, block)) row *
            stackedHeads columns row column)).symm
    _ = _ := by
      rw [Fintype.sum_prod_type]
      simp_rw [source_combination_matrix_at_row_major_index]
      simp [stackedHeads, coefficient_polynomial_evaluation]

theorem combination_heads_exact (points : Fin 6 → Goldilocks) (columns : CurrentColumns) :
    combinationHeads points (stackedHeads columns) = evaluationHeads points columns := by
  funext combination column
  obtain ⟨⟨opening, block⟩, rfl⟩ :=
    (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).surjective combination
  simpa only [evaluationHeads, Equiv.symm_apply_apply] using
    combination_head_is_evaluation points columns opening block column

/-- Honest source polynomials need only their independently checkable degree
bound. This is not an equality-to-public-view certificate. The coefficient
vector theorem above has no such hypothesis. -/
theorem polynomial_head_is_evaluation (points : Fin 6 → Goldilocks)
    (polynomials : Fin 26230 → Goldilocks[X])
    (degree : ∀ column, (polynomials column).natDegree < 70)
    (opening : Fin 6) (block : Fin 2) (column : Fin 13115) :
    combinationHeads points
      (stackedHeads (fun index coefficient => (polynomials index).coeff coefficient.val))
      (finProdFinEquiv (opening, block)) column =
      (polynomials (finProdFinEquiv (block, column))).eval (points opening) := by
  rw [combination_head_is_evaluation, coefficient_polynomial_of_coefficients _ (degree _)]

/-- Raw digest limbs remain Nat: reducing SHA-512 words modulo Goldilocks
would change actual oracle addresses. Field words alone use canonical val. -/
def openingChallengeWords (digest : Fin 8 → Nat)
    (heads : Fin 12 → Fin 13115 → Goldilocks) (tails : Earlier) : List Nat :=
  List.ofFn digest ++ (List.ofFn fun combination : Fin 12 =>
    (List.ofFn fun column : Fin 13115 => (heads combination column).val) ++
      List.ofFn fun tail : Fin 58 => (tails combination tail).val).flatten

theorem current_challenge_word_count (digest : Fin 8 → Nat)
    (heads : Fin 12 → Fin 13115 → Goldilocks) (tails : Earlier) :
    (openingChallengeWords digest heads tails).length = 158084 := by
  simp only [openingChallengeWords, List.length_append, List.length_ofFn,
    List.length_flatten, List.map_ofFn, Function.comp_def, List.sum_ofFn,
    Finset.sum_const, Finset.card_univ, Fintype.card_fin, smul_eq_mul]

/-- This replaces the actual DECS hash input after hPiop, including all 696
same-tail prefix words. It does not replace the later authentication nodes. -/
theorem challenge_matrix_product_eliminated (digest : Fin 8 → Nat)
    (points : Fin 6 → Goldilocks) (columns : CurrentColumns) (tails : Earlier) :
    openingChallengeWords digest (combinationHeads points (stackedHeads columns)) tails =
      openingChallengeWords digest (evaluationHeads points columns) tails := by
  rw [combination_heads_exact]

/-- Any actual deterministic challenge/selector implementation sees the same
literal words. No assumption concerning its output, success, or view is needed. -/
theorem selector_matrix_product_eliminated {Result : Type*}
    (selector : List Nat → Result) (digest : Fin 8 → Nat)
    (points : Fin 6 → Goldilocks) (columns : CurrentColumns) (tails : Earlier) :
    selector (openingChallengeWords digest (combinationHeads points (stackedHeads columns)) tails) =
      selector (openingChallengeWords digest (evaluationHeads points columns) tails) := by
  rw [challenge_matrix_product_eliminated]

theorem current_geometry : 26210 + 20 = 26230 ∧ 2 * 13115 = 26230 ∧
    58 + 13115 = 13173 ∧ 140 * 58 = 12 * 58 + 58 * 128 := by decide

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58Compff01OpeningContinuation
