import Q38Rp05ExecutionBridgeBase
import HegemonCrypto.CmsOracleDatabaseBridge

namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

section UniformEnvironmentFamily

variable {Input Work Environment : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work] [Fintype Environment]

def appendUniformEnvironmentState
    (state : ResponseCmsState Input Work) :
    ResponseCmsState Input ((Environment → DigestRegister) × Work) :=
  fun basis =>
    state
      { input := basis.input
        phase := basis.phase
        workspace := basis.workspace.2
        database := basis.database } *
      ((Real.sqrt (Fintype.card (Environment → DigestRegister) : ℝ) : ℂ)⁻¹)

def uniformEnvironmentFamily
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work) :=
  fun oracle register =>
    family oracle (register.1, register.2.1, register.2.2.2) *
      ((Real.sqrt
        (Fintype.card (Environment → DigestRegister) : ℝ) : ℂ)⁻¹)

private theorem sum_if_mul_right {α : Type} [Fintype α]
    (predicate : α → Prop) [DecidablePred predicate]
    (f : α → ℂ) (scalar : ℂ) :
    (∑ x, if predicate x then f x * scalar else 0) =
      (∑ x, if predicate x then f x else 0) * scalar := by
  calc
    (∑ x, if predicate x then f x * scalar else 0) =
        ∑ x, (if predicate x then f x else 0) * scalar := by
      apply Finset.sum_congr rfl
      intro x _
      by_cases h : predicate x <;> simp [h]
    _ = (∑ x, if predicate x then f x else 0) * scalar :=
      (Finset.sum_mul _ _ _).symm

omit [Fintype Work] [DecidableEq Work] in
/-- Appending a flat environment to the database state is exactly appending
it inside every member of the same canonical oracle family. -/
theorem append_uniform_environment_total_family
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    appendUniformEnvironmentState
        (totalOracleFamilyState family) =
      totalOracleFamilyState
        (Input := Input) (Output := DigestRegister)
        (Phase := DigestRegister)
        (Workspace := (Environment → DigestRegister) × Work)
        (uniformEnvironmentFamily
          (Input := Input) (Work := Work) (Environment := Environment) family) := by
  funext basis
  simp only [appendUniformEnvironmentState, uniformEnvironmentFamily,
    totalOracleFamilyState, basisRegisters]
  rw [sum_if_mul_right]
  ac_rfl

def inverseIndexedSwapFamily
    (key : Input) (index : Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work) :=
  fun oracle register =>
    let old := swapOracleLabels key index (oracle, register.2.2.1)
    family old.1 (register.1, register.2.1, register.2.2.2) *
      ((Real.sqrt
        (Fintype.card (Environment → DigestRegister) : ℝ) : ℂ)⁻¹)

def inverseIndexedEnvironmentFamily
    (key : Input) (index : Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work)) :
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work) :=
  fun oracle register =>
    let old := swapOracleLabels key index (oracle, register.2.2.1)
    family old.1
      (register.1, register.2.1, old.2, register.2.2.2)

omit [Fintype Input] in
private theorem set_total_database_coordinate
    (oracle : Input → DigestRegister) (key : Input)
    (answer : DigestRegister) :
    setDatabaseCoordinate (totalDatabase oracle) key (some answer) =
      totalDatabase (Function.update oracle key answer) := by
  funext input
  by_cases same : input = key
  · subst input
    simp [setDatabaseCoordinate, totalDatabase]
  · simp [setDatabaseCoordinate, totalDatabase, same,
      Function.update]

omit [Fintype Environment] in
private theorem split_label_update
    (labels : Environment → DigestRegister) (index : Environment)
    (answer : DigestRegister) :
    (fun site => if site = index then answer else labels site) =
      Function.update labels index answer := by
  funext site
  by_cases same : site = index
  · subst site
    simp [Function.update]
  · simp [Function.update, same]

theorem indexed_raw_swap_environment_family_at_total
    (key : Input) (index : Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work))
    (oracle : Input → DigestRegister)
    (registerInput : Input) (phase : DigestRegister)
    (labels : Environment → DigestRegister) (work : Work) :
    indexedRawSwap key index (totalOracleFamilyState family)
        { input := registerInput
          phase := phase
          workspace := (labels, work)
          database := totalDatabase oracle } =
      totalOracleFamilyState
        (inverseIndexedEnvironmentFamily key index family)
        { input := registerInput
          phase := phase
          workspace := (labels, work)
          database := totalDatabase oracle } := by
  simp [indexedRawSwap, transportWorkspace, labelSplit, rawSwap, swapBasis,
    totalDatabase, total_oracle_family_state_apply,
    inverseIndexedEnvironmentFamily, swapOracleLabels,
    Equiv.funSplitAt, Equiv.piSplitAt, split_label_update,
    set_total_database_coordinate]

theorem indexed_raw_swap_environment_family
    (key : Input) (index : Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work)) :
    indexedRawSwap key index (totalOracleFamilyState family) =
      totalOracleFamilyState
        (inverseIndexedEnvironmentFamily key index family) := by
  have supported : TotalDatabaseSupport
      (indexedRawSwap key index (totalOracleFamilyState family)) :=
    total_database_support_indexed_raw_swap key index _
      (total_oracle_family_has_total_database_support family)
  funext basis
  by_cases matched : ∃ oracle : Input → DigestRegister,
      basis.database = totalDatabase oracle
  · obtain ⟨oracle, databaseEq⟩ := matched
    rcases basis with ⟨registerInput, phase, labels, database⟩
    dsimp at databaseEq ⊢
    subst database
    exact indexed_raw_swap_environment_family_at_total key index family oracle
      registerInput phase labels.1 labels.2
  · rw [supported basis matched,
      total_oracle_family_state_eq_zero_of_no_match _ basis matched]

def inverseSwapListFamily (keys : Environment → Input) : List Environment →
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work) →
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work)
  | [], family => family
  | index :: remaining, family =>
      inverseSwapListFamily keys remaining
        (inverseIndexedEnvironmentFamily (keys index) index family)

def undoSwapOracleLabelsList (keys : Environment → Input)
    (indices : List Environment)
    (pair : (Input → DigestRegister) ×
      (Environment → DigestRegister)) :=
  swapOracleLabelsList keys indices.reverse pair

def swapOracleLabelsEquiv (key : Input) (index : Environment) :
    ((Input → DigestRegister) × (Environment → DigestRegister)) ≃
      ((Input → DigestRegister) × (Environment → DigestRegister)) where
  toFun := swapOracleLabels key index
  invFun := swapOracleLabels key index
  left_inv pair := by
    rcases pair with ⟨oracle, labels⟩
    apply Prod.ext
    · funext input
      by_cases same : input = key
      · subst input
        simp [swapOracleLabels]
      · simp [swapOracleLabels]
    · funext site
      by_cases same : site = index
      · subst site
        simp [swapOracleLabels]
      · simp [swapOracleLabels]
  right_inv pair := by
    rcases pair with ⟨oracle, labels⟩
    apply Prod.ext
    · funext input
      by_cases same : input = key
      · subst input
        simp [swapOracleLabels]
      · simp [swapOracleLabels]
    · funext site
      by_cases same : site = index
      · subst site
        simp [swapOracleLabels]
      · simp [swapOracleLabels]

def swapOracleLabelsListEquiv (keys : Environment → Input) :
    (indices : List Environment) →
      ((Input → DigestRegister) × (Environment → DigestRegister)) ≃
        ((Input → DigestRegister) × (Environment → DigestRegister))
  | [] => Equiv.refl _
  | index :: remaining =>
      (swapOracleLabelsEquiv (keys index) index).trans
        (swapOracleLabelsListEquiv keys remaining)

theorem equiv_trans_symm_apply {α β γ : Type}
    (first : α ≃ β) (second : β ≃ γ) (value : γ) :
    (first.trans second).symm value = first.symm (second.symm value) := rfl

omit [Fintype Input] [Fintype Environment] in
theorem swap_oracle_labels_equiv_symm_apply
    (key : Input) (index : Environment)
    (pair : (Input → DigestRegister) × (Environment → DigestRegister)) :
    (swapOracleLabelsEquiv key index).symm pair =
      swapOracleLabels key index pair := rfl

omit [Fintype Input] [Fintype Environment] in
@[simp]
theorem swap_oracle_labels_list_equiv_apply
    (keys : Environment → Input) (indices : List Environment)
    (pair : (Input → DigestRegister) ×
      (Environment → DigestRegister)) :
    swapOracleLabelsListEquiv keys indices pair =
      swapOracleLabelsList keys indices pair := by
  induction indices generalizing pair with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [swapOracleLabelsListEquiv, Equiv.trans_apply,
        swapOracleLabelsEquiv]
      exact inductionHypothesis (swapOracleLabels (keys index) index pair)

omit [Fintype Input] [Fintype Environment] in
theorem swap_oracle_labels_list_append
    (keys : Environment → Input) (left right : List Environment)
    (pair : (Input → DigestRegister) ×
      (Environment → DigestRegister)) :
    swapOracleLabelsList keys (left ++ right) pair =
      swapOracleLabelsList keys right
        (swapOracleLabelsList keys left pair) := by
  induction left generalizing pair with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [List.cons_append, swapOracleLabelsList]
      exact inductionHypothesis _

omit [Fintype Input] [Fintype Environment] in
@[simp]
theorem swap_oracle_labels_list_equiv_symm_apply
    (keys : Environment → Input) (indices : List Environment)
    (pair : (Input → DigestRegister) ×
      (Environment → DigestRegister)) :
    (swapOracleLabelsListEquiv keys indices).symm pair =
      undoSwapOracleLabelsList keys indices pair := by
  induction indices generalizing pair with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [swapOracleLabelsListEquiv, equiv_trans_symm_apply,
        swap_oracle_labels_equiv_symm_apply, undoSwapOracleLabelsList,
        List.reverse_cons]
      rw [swap_oracle_labels_list_append]
      rw [inductionHypothesis]
      rfl

omit [Fintype Input] [Fintype Environment] [Fintype Work]
  [DecidableEq Work] in
theorem inverse_swap_list_family_apply
    (keys : Environment → Input) (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work))
    (oracle : Input → DigestRegister)
    (registerInput : Input) (phase : DigestRegister)
    (labels : Environment → DigestRegister) (work : Work) :
    inverseSwapListFamily keys indices family oracle
        (registerInput, phase, labels, work) =
      let old := undoSwapOracleLabelsList keys indices (oracle, labels)
      family old.1 (registerInput, phase, old.2, work) := by
  induction indices generalizing family oracle labels with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [inverseSwapListFamily, undoSwapOracleLabelsList,
        List.reverse_cons]
      rw [inductionHypothesis]
      rw [swap_oracle_labels_list_append]
      rfl

theorem raw_swap_list_environment_family
    (keys : Environment → Input) (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister)
      (Workspace := (Environment → DigestRegister) × Work)) :
    rawSwapList keys indices (totalOracleFamilyState family) =
      totalOracleFamilyState (inverseSwapListFamily keys indices family) := by
  induction indices generalizing family with
  | nil => rfl
  | cons index remaining inductionHypothesis =>
      simp only [rawSwapList, inverseSwapListFamily]
      rw [indexed_raw_swap_environment_family, inductionHypothesis]

end UniformEnvironmentFamily
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
