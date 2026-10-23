import HegemonCrypto.NativeLaunchConstraintAdapterBridge

/-! Finite association-table accumulation matching the abstract operations of
HTLC linear(): lookup absent as zero, add coefficient, retain nonzero entries.
Entry order is intentionally immaterial to row evaluation. This is not binary
refinement of Rust BTreeMap, modular u64 arithmetic, CSR allocation or indexing.
No native security or production gate is closed by this component. -/
set_option autoImplicit false
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchSparseCoalescing
open HegemonCrypto.NativeLaunchConstraintAdapterBridge
noncomputable section
variable {F : Type*} [Field F]

/-- Update the first matching finite-table entry, inserting an absent key.
Starting from [] creates at most one entry per key; zero entries survive until
retainNonzero, just as in the native builder. -/
def accumulate (index : Nat) (coefficient : F) : List (Nat × F) → List (Nat × F)
  | [] => [(index, coefficient)]
  | (key, old) :: rest =>
      if index = key then (key, old + coefficient) :: rest
      else (key, old) :: accumulate index coefficient rest

def retainNonzero (table : List (Nat × F)) : List (Nat × F) := by
  classical
  exact table.filter (fun entry => decide (entry.2 ≠ 0))

def coalesce (terms : List (Nat × F)) : List (Nat × F) :=
  retainNonzero (terms.foldl (fun table term => accumulate term.1 term.2 table) [])

theorem accumulate_eval (assignment : Nat → F) (index : Nat) (coefficient : F)
    (table : List (Nat × F)) :
    sparseEval assignment (accumulate index coefficient table) =
      sparseEval assignment table + coefficient * assignment index := by
  induction table with
  | nil => simp [accumulate, sparseEval]
  | cons entry rest ih =>
      rcases entry with ⟨key, old⟩
      by_cases h : index = key
      · subst index
        simp only [accumulate, ↓reduceIte, sparseEval, add_mul]
        ac_rfl
      · simp only [accumulate, if_neg h, sparseEval, ih]
        ac_rfl

theorem accumulation_fold_eval (assignment : Nat → F) (terms table : List (Nat × F)) :
    sparseEval assignment (terms.foldl (fun acc term => accumulate term.1 term.2 acc) table) =
      sparseEval assignment table + sparseEval assignment terms := by
  induction terms generalizing table with
  | nil => simp [sparseEval]
  | cons term rest ih =>
      rcases term with ⟨index, coefficient⟩
      simp only [List.foldl_cons, ih, accumulate_eval, sparseEval]
      ac_rfl

theorem retainNonzero_eval (assignment : Nat → F) (table : List (Nat × F)) :
    sparseEval assignment (retainNonzero table) = sparseEval assignment table := by
  classical
  induction table with
  | nil => simp [retainNonzero, sparseEval]
  | cons entry rest ih =>
      rcases entry with ⟨index, coefficient⟩
      by_cases h : coefficient = 0 <;> simp [retainNonzero, sparseEval, h] at ih ⊢ <;> exact ih

theorem coalesce_eval (assignment : Nat → F) (terms : List (Nat × F)) :
    sparseEval assignment (coalesce terms) = sparseEval assignment terms := by
  simp only [coalesce, retainNonzero_eval, accumulation_fold_eval, sparseEval, zero_add]

/-- Holds without distinct-wire assumptions: aliases accumulate and cancel. -/
theorem coalesce_coefficient (terms : List (Nat × F)) (index : Nat) :
    sparseEval (fun key => if key = index then (1 : F) else 0) (coalesce terms) =
      sparseEval (fun key => if key = index then (1 : F) else 0) terms :=
  coalesce_eval _ _

theorem sparseEval_permutation (assignment : Nat → F) {first second : List (Nat × F)}
    (permutation : first.Perm second) : sparseEval assignment first = sparseEval assignment second := by
  induction permutation with
  | nil => rfl
  | cons entry _ ih => simp only [sparseEval, ih]
  | swap a b rest => simp only [sparseEval]; ac_rfl
  | trans _ _ ih₁ ih₂ => exact ih₁.trans ih₂

theorem coalesce_order_irrelevant (assignment : Nat → F) {first second : List (Nat × F)}
    (permutation : first.Perm second) :
    sparseEval assignment (coalesce first) = sparseEval assignment (coalesce second) := by
  rw [coalesce_eval, coalesce_eval]
  exact sparseEval_permutation assignment permutation

def normalizedLower (terms : List (Word F × F)) : List (Nat × F) × F :=
  (coalesce (lower terms).1, (lower terms).2)

theorem constant_shift_unchanged (terms : List (Word F × F)) :
    (normalizedLower terms).2 = (lower terms).2 := rfl

def normalizedRow (assignment : Nat → F) (terms : List (Word F × F)) (target : F) : Prop :=
  sparseEval assignment (normalizedLower terms).1 = target - (normalizedLower terms).2

theorem normalized_row_iff (assignment : Nat → F) (terms : List (Word F × F)) (target : F) :
    normalizedRow assignment terms target ↔ rowSatisfied assignment terms target := by
  simp only [normalizedRow, normalizedLower, coalesce_eval, rowSatisfied]

/-- The builder retains this empty inconsistent row; packed-witness verification
rejects it by comparing its zero sum to the nonzero shifted target. -/
theorem empty_inconsistent_rejected (assignment : Nat → F) (terms : List (Word F × F))
    (target : F) (empty : (normalizedLower terms).1 = [])
    (inconsistent : target - (normalizedLower terms).2 ≠ 0) :
    ¬ normalizedRow assignment terms target := by
  unfold normalizedRow
  rw [empty, sparseEval]
  exact Ne.symm inconsistent

theorem normalized_copy_semantics (assignment : Nat → F) (left right : Word F) :
    normalizedRow assignment [(left, 1), (right, -1)] 0 ↔ read assignment left = read assignment right := by
  rw [normalized_row_iff, copy_row_semantics]

theorem normalized_add_semantics (assignment : Nat → F) (out left right : Word F) :
    normalizedRow assignment [(out, 1), (left, -1), (right, -1)] 0 ↔
      read assignment out = read assignment left + read assignment right := by
  rw [normalized_row_iff, add_row_semantics]

theorem normalized_sub_semantics (assignment : Nat → F) (out left right : Word F) :
    normalizedRow assignment [(out, 1), (left, -1), (right, 1)] 0 ↔
      read assignment out = read assignment left - read assignment right := by
  rw [normalized_row_iff, sub_row_semantics]

theorem normalized_product_semantics (assignment : Nat → F) (out left right : Word F)
    (outIndex leftIndex rightIndex : Nat)
    (copyOut : normalizedRow assignment [(.wire outIndex, 1), (out, -1)] 0)
    (copyLeft : normalizedRow assignment [(.wire leftIndex, 1), (left, -1)] 0)
    (copyRight : normalizedRow assignment [(.wire rightIndex, 1), (right, -1)] 0)
    (nonlinear : assignment outIndex - assignment leftIndex * assignment rightIndex = 0) :
    read assignment out = read assignment left * read assignment right := by
  exact copied_product_semantics assignment out left right outIndex leftIndex rightIndex
    ((normalized_row_iff _ _ _).mp copyOut) ((normalized_row_iff _ _ _).mp copyLeft)
    ((normalized_row_iff _ _ _).mp copyRight) nonlinear

end
end HegemonCrypto.NativeLaunchSparseCoalescing
