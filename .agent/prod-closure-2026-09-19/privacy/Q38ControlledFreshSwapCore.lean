import Q38FreshSwapIsometry
import HegemonCrypto.CmsKernelBounds

/-! Actual branch-controlled database/fresh-label swaps. The chosen raw key
depends on the measured branch, while each site has its own fresh label.
The operator is a finite composition of the explicit CMS D·swap·D isometry. -/
namespace HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.SmallWood.V8SmzaFreshSwapFiber
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false
set_option linter.unusedVariables false
set_option linter.unusedSimpArgs false

variable {Key Index Branch Work Output : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Index] [DecidableEq Index]
variable [Fintype Branch] [Fintype Work]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]

abbrev Basis (Key Index Branch Work Output : Type) :=
  Branch × (Key → Option Output) × (Index → Output) × Work

abbrev Space := EuclideanSpace ℂ (Basis Key Index Branch Work Output)

def Rest (selected : Branch → Index → Key) (index : Index) :=
  (branch : Branch) ×
    ({ key : Key // key ≠ selected branch index } → Option Output) ×
    ({ site : Index // site ≠ index } → Output) × Work

noncomputable instance restKeyFintype (selected : Branch → Index → Key) (index : Index)
    (branch : Branch) :
    Fintype { key : Key // key ≠ selected branch index } :=
  Fintype.subtype (Finset.univ.filter fun key => key ≠ selected branch index) (by simp)

noncomputable instance restSiteFintype (index : Index) :
    Fintype { site : Index // site ≠ index } :=
  Fintype.subtype (Finset.univ.filter fun site => site ≠ index) (by simp)

noncomputable instance restFintype (selected : Branch → Index → Key) (index : Index) :
    Fintype (Rest (Work := Work) (Output := Output) selected index) := by
  unfold Rest
  infer_instance

/-- Exact isolation of the branch-selected database cell and matching fresh
label. Complementary database/label coordinates and workspace are retained. -/
def isolate (selected : Branch → Index → Key) (index : Index) :
    Basis Key Index Branch Work Output ≃
      (Rest (Work := Work) (Output := Output) selected index × (Option Output × Output)) where
  toFun basis :=
    ⟨⟨basis.1, (fun key => basis.2.1 key), (fun site => basis.2.2.1 site), basis.2.2.2⟩,
      basis.2.1 (selected basis.1 index), basis.2.2.1 index⟩
  invFun pair :=
    (pair.1.1,
      (fun key => if h : key = selected pair.1.1 index then pair.2.1 else pair.1.2.1 ⟨key, h⟩),
      (fun site => if h : site = index then pair.2.2 else pair.1.2.2.1 ⟨site, h⟩),
      pair.1.2.2.2)
  left_inv basis := by
    rcases basis with ⟨branch, database, labels, workspace⟩
    apply Prod.ext
    · rfl
    · apply Prod.ext
      · funext key
        by_cases h : key = selected branch index <;> simp [h]
      · apply Prod.ext
        · funext site
          by_cases h : site = index <;> simp [h]
        · rfl
  right_inv pair := by
    rcases pair with ⟨rest, cell, label⟩
    rcases rest with ⟨branch, database, labels, workspace⟩
    ext <;> simp [Rest]
    constructor
    · funext key
      simp [key.property]
    · funext site
      simp [site.property]

def fiber (selected : Branch → Index → Key) (index : Index)
    (state : Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output))
    (rest : Rest (Work := Work) (Output := Output) selected index) : Joint (Output := Output) :=
  WithLp.toLp 2 (fun cell => state ((isolate selected index).symm ⟨rest, cell⟩))

def exchangeAt (selected : Branch → Index → Key) (index : Index) :
    Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output) ≃ₗᵢ[ℂ]
      Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output) :=
  let split := LinearIsometryEquiv.piLpCongrLeft 2 ℂ ℂ
    ((isolate selected index).trans
      (Equiv.sigmaEquivProd (Rest (Work := Work) (Output := Output) selected index) (Option Output × Output)).symm)
  let curry := LinearIsometryEquiv.piLpCurry ℂ 2
    (fun (_ : Rest (Work := Work) (Output := Output) selected index) (_ : Option Output × Output) => ℂ)
  split.trans (curry.trans ((LinearIsometryEquiv.piLpCongrRight 2
    (fun _ : Rest (Work := Work) (Output := Output) selected index => compressedExchangeIsometry)).trans
      (curry.symm.trans split.symm)))

theorem exchange_at_apply (selected : Branch → Index → Key) (index : Index)
    (state : Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output))
    (basis : Basis Key Index Branch Work Output) :
    exchangeAt selected index state basis =
      compressedExchange (fiber selected index state ((isolate selected index basis).1))
        ((isolate selected index basis).2) := by
  rw [← compressed_exchange_is_actual_isometry]
  simp [exchangeAt, fiber, LinearIsometryEquiv.trans_apply,
    LinearIsometryEquiv.piLpCongrLeft_apply,
    LinearIsometryEquiv.piLpCurry_apply,
    LinearIsometryEquiv.piLpCongrRight_apply,
    Equiv.piCongrLeft', Equiv.sigmaEquivProd, Equiv.trans_apply,
    Equiv.symm_apply_apply, Sigma.curry, Sigma.uncurry]
  apply congrArg (fun x : Joint (Output := Output) =>
    compressedExchangeIsometry x ((isolate selected index basis).2))
  ext cell
  rfl

theorem exchange_at_fixes_of_fibers (selected : Branch → Index → Key) (index : Index)
    (state : Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output))
    (fixed : ∀ rest, compressedExchange (fiber selected index state rest) = fiber selected index state rest) :
    exchangeAt selected index state = state := by
  ext basis
  rw [exchange_at_apply, fixed]
  exact congrArg state ((isolate selected index).symm_apply_apply basis)

def exchangeMany (selected : Branch → Index → Key) : List Index →
    Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output) ≃ₗᵢ[ℂ]
      Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output)
  | [] => LinearIsometryEquiv.refl ℂ _
  | index :: tail => (exchangeAt selected index).trans (exchangeMany selected tail)

theorem exchange_many_fixes (selected : Branch → Index → Key) (indices : List Index)
    (state : Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output))
    (fixed : ∀ index ∈ indices, exchangeAt selected index state = state) :
    exchangeMany selected indices state = state := by
  induction indices with
  | nil => rfl
  | cons index tail ih =>
    change exchangeMany selected tail (exchangeAt selected index state) = state
    rw [fixed index (List.mem_cons_self)]
    exact ih (fun site member => fixed site (List.mem_cons_of_mem index member))

def flatAbsent (amplitude : ℂ) : Joint (Output := Output) :=
  WithLp.toLp 2 (fun cell => if cell.1 = none then amplitude else 0)

theorem compressed_exchange_fixes_flat_absent (amplitude : ℂ) :
    compressedExchange (flatAbsent (Output := Output) amplitude) = flatAbsent amplitude := by
  have nonzero : inverseSqrtOutputCard (Output := Output) ≠ 0 := by
    unfold inverseSqrtOutputCard
    apply inv_ne_zero
    exact_mod_cast (ne_of_gt (Real.sqrt_pos.2 (show (0 : ℝ) < Fintype.card Output by positivity)))
  have scalar : flatAbsent (Output := Output) amplitude =
      (amplitude / inverseSqrtOutputCard (Output := Output)) • tensorUniform (absentKet (Output := Output)) := by
    ext cell
    rcases cell with ⟨slot, label⟩
    cases slot with
    | none =>
      change amplitude = amplitude / inverseSqrtOutputCard * (absentKet (Output := Output) none * inverseSqrtOutputCard)
      rw [absent_ket_apply_none, one_mul, div_mul_cancel₀ _ nonzero]
    | some answer =>
      change 0 = amplitude / inverseSqrtOutputCard * (absentKet (Output := Output) (some answer) * inverseSqrtOutputCard)
      rw [absent_ket_apply_some, zero_mul, mul_zero]
  rw [scalar, ← compressed_exchange_is_actual_isometry, map_smul,
    compressed_exchange_is_actual_isometry, compressed_exchange_fixes_absent]

abbrev Core (Key Branch Work Output : Type) := Branch × (Key → Option Output) × Work

/-- Fresh label registers are independent uniform amplitudes. The arbitrary
core may entangle measured branch, compressed database and workspace. -/
def freshLabels (core : Core Key Branch Work Output → ℂ) :
    Space (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output) :=
  WithLp.toLp 2 (fun basis => core (basis.1, basis.2.1, basis.2.2.2) *
    ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹))

def restoredCore (selected : Branch → Index → Key) (index : Index)
    (rest : Rest (Work := Work) (Output := Output) selected index) (cell : Option Output) :
    Core Key Branch Work Output :=
  (rest.1, (fun key => if h : key = selected rest.1 index then cell else rest.2.1 ⟨key, h⟩), rest.2.2.2)

theorem empty_core_fiber (selected : Branch → Index → Key) (index : Index)
    (core : Core Key Branch Work Output → ℂ)
    (empty : ∀ branch database workspace, database (selected branch index) ≠ none →
      core (branch, database, workspace) = 0)
    (rest : Rest (Work := Work) (Output := Output) selected index) :
    fiber selected index (freshLabels (Index := Index) core) rest =
      flatAbsent (core (restoredCore selected index rest none) *
        ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹)) := by
  ext cell
  rcases cell with ⟨slot, label⟩
  cases slot with
  | none => rfl
  | some answer =>
    change core (restoredCore selected index rest (some answer)) * _ = 0
    have zero : core (restoredCore selected index rest (some answer)) = 0 :=
      empty rest.1 _ rest.2.2.2 (by simp)
    rw [zero, zero_mul]

/-- An actual controlled swap fixes an empty selected database coordinate
with fresh uniform labels, even when the selected key depends on the branch. -/
theorem exchange_at_fixes_empty_core (selected : Branch → Index → Key) (index : Index)
    (core : Core Key Branch Work Output → ℂ)
    (empty : ∀ branch database workspace, database (selected branch index) ≠ none →
      core (branch, database, workspace) = 0) :
    exchangeAt selected index (freshLabels (Index := Index) core) = freshLabels core := by
  apply exchange_at_fixes_of_fibers
  intro rest
  rw [empty_core_fiber selected index core empty rest]
  exact compressed_exchange_fixes_flat_absent _

/-- The simultaneous all-leaf compressed resampling fixes the whole
empty-on-patch sector exactly. No number-of-leaves loss is introduced. -/
theorem exchange_many_fixes_empty_patch (selected : Branch → Index → Key) (indices : List Index)
    (core : Core Key Branch Work Output → ℂ)
    (empty : ∀ index ∈ indices, ∀ branch database workspace,
      database (selected branch index) ≠ none → core (branch, database, workspace) = 0) :
    exchangeMany selected indices (freshLabels (Index := Index) core) = freshLabels core :=
  exchange_many_fixes selected indices _ (fun index member => exchange_at_fixes_empty_core selected index core (empty index member))

def badCore (selected : Branch → Index → Key) (indices : List Index)
    (core : Core Key Branch Work Output → ℂ) : Core Key Branch Work Output → ℂ :=
  fun basis => if ∃ index ∈ indices, basis.2.1 (selected basis.1 index) ≠ none then core basis else 0

theorem good_core_is_empty (selected : Branch → Index → Key) (indices : List Index)
    (core : Core Key Branch Work Output → ℂ) (index : Index) (member : index ∈ indices)
    (branch : Branch) (database : Key → Option Output) (workspace : Work)
    (hit : database (selected branch index) ≠ none) :
    (core - badCore selected indices core) (branch, database, workspace) = 0 := by
    have hit' : ∃ site ∈ indices, database (selected branch site) ≠ none :=
      ⟨index, member, hit⟩
    simp [Pi.sub_apply, badCore, hit']

theorem fresh_labels_sub (left right : Core Key Branch Work Output → ℂ) :
    freshLabels (Index := Index) (left - right) = freshLabels left - freshLabels right := by
  ext basis
  exact sub_mul _ _ _

/-- The real simultaneous controlled resampling operator's disturbance is
bounded by its bad-record sector. The fixing premise is discharged by the
actual D·swap·D construction, not supplied as an abstract coupling premise. -/
theorem controlled_swap_disturbance (selected : Branch → Index → Key) (indices : List Index)
    (core : Core Key Branch Work Output → ℂ) :
    ‖exchangeMany selected indices (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2 ≤
      4 * ‖freshLabels (Index := Index) (badCore selected indices core)‖ ^ 2 := by
  have fixed := exchange_many_fixes_empty_patch selected indices (core - badCore selected indices core)
    (fun index member branch database workspace hit => good_core_is_empty selected indices core index member branch database workspace hit)
  rw [fresh_labels_sub, map_sub] at fixed
  have difference :
      exchangeMany selected indices (freshLabels (Index := Index) core) - freshLabels core =
        exchangeMany selected indices (freshLabels (Index := Index) (badCore selected indices core)) -
          freshLabels (Index := Index) (badCore selected indices core) := by
    exact sub_eq_sub_iff_sub_eq_sub.mp fixed
  rw [difference]
  have triangle := norm_sub_le
    (exchangeMany selected indices (freshLabels (Index := Index) (badCore selected indices core)))
    (freshLabels (Index := Index) (badCore selected indices core))
  rw [(exchangeMany selected indices).norm_map] at triangle
  nlinarith [norm_nonneg (exchangeMany selected indices (freshLabels (Index := Index) (badCore selected indices core)) -
    freshLabels (Index := Index) (badCore selected indices core)),
    norm_nonneg (freshLabels (Index := Index) (badCore selected indices core))]

def basisToCoreLabels : Basis Key Index Branch Work Output ≃ (Core Key Branch Work Output × (Index → Output)) where
  toFun basis := ((basis.1, basis.2.1, basis.2.2.2), basis.2.2.1)
  invFun pair := (pair.1.1, pair.1.2.1, pair.2, pair.1.2.2)
  left_inv basis := rfl
  right_inv pair := rfl

theorem fresh_labels_norm_sq (core : Core Key Branch Work Output → ℂ) :
    ‖freshLabels (Index := Index) core‖ ^ 2 = ∑ basis : Core Key Branch Work Output, ‖core basis‖ ^ 2 := by
  let c : ℂ := ((Real.sqrt (Fintype.card (Index → Output) : ℝ) : ℂ)⁻¹)
  have constant : ‖c‖ ^ 2 = 1 / (Fintype.card (Index → Output) : ℝ) := by
    rw [Complex.sq_norm]
    exact HegemonCrypto.CmsKernelBounds.normSq_inverseSqrtOutputCard (Output := Index → Output)
  rw [EuclideanSpace.norm_sq_eq]
  change (∑ basis : Basis Key Index Branch Work Output, ‖core (basis.1, basis.2.1, basis.2.2.2) * c‖ ^ 2) = _
  calc
    _ = ∑ pair : Core Key Branch Work Output × (Index → Output), ‖core pair.1 * c‖ ^ 2 :=
      (basisToCoreLabels (Key := Key) (Index := Index) (Branch := Branch) (Work := Work) (Output := Output)).sum_comp _
    _ = _ := by
      simp only [Fintype.sum_prod_type, norm_mul, mul_pow, constant]
      apply Finset.sum_congr rfl
      intro basis _
      have positive : (0 : ℝ) < Fintype.card (Index → Output) := by positivity
      simp only [Finset.sum_const, Finset.card_univ, nsmul_eq_mul]
      field_simp [ne_of_gt positive]

theorem controlled_swap_disturbance_mass (selected : Branch → Index → Key) (indices : List Index)
    (core : Core Key Branch Work Output → ℂ) :
    ‖exchangeMany selected indices (freshLabels (Index := Index) core) - freshLabels core‖ ^ 2 ≤
      4 * ∑ basis : Core Key Branch Work Output,
        if ∃ index ∈ indices, basis.2.1 (selected basis.1 index) ≠ none then ‖core basis‖ ^ 2 else 0 := by
  have bound := controlled_swap_disturbance selected indices core
  rw [fresh_labels_norm_sq] at bound
  have sumEq :
      (∑ basis : Core Key Branch Work Output,
        (if ∃ index ∈ indices, basis.2.1 (selected basis.1 index) ≠ none
          then ‖core basis‖ else 0) ^ 2) =
        ∑ basis : Core Key Branch Work Output,
          if ∃ index ∈ indices, basis.2.1 (selected basis.1 index) ≠ none
            then ‖core basis‖ ^ 2 else 0 := by
    apply Finset.sum_congr rfl
    intro basis _
    by_cases hit : ∃ index ∈ indices, basis.2.1 (selected basis.1 index) ≠ none <;>
      simp [hit]
  simpa only [badCore, apply_ite, norm_zero, zero_pow (by decide : 2 ≠ 0), sumEq] using bound

end
