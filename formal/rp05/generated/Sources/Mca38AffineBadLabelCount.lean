import Mathlib.Algebra.Polynomial.Eval.Degree
import Mathlib.Data.Finset.Card
import Mathlib.Tactic.LinearCombination

/-! Affine bad-label charging.

The support selected for a label may depend arbitrarily on that label.  The
proof does not choose a global selector: a bad support supplies a mismatch
position, and the agreement equation makes the label equal to the charge of
that position.
-/
namespace HegemonCrypto.SmallWood.Mca38AffineBadLabelCount
noncomputable section
open scoped BigOperators Classical
set_option autoImplicit false

variable {K I : Type*} [Field K] [DecidableEq I]

def mismatchPositions (positions : Finset I) (point : I → K)
    (V : I → K) (v : Polynomial K) : Finset I :=
  positions.filter (fun a => V a ≠ v.eval (point a))

def affineCharge (u v : Polynomial K) (point U V : I → K) (a : I) : K :=
  (u.eval (point a) - U a) / (V a - v.eval (point a))

omit [DecidableEq I] in
theorem charge_eq_label
    (u v : Polynomial K) (point U V : I → K) (z : K) (a : I)
    (hden : V a ≠ v.eval (point a))
    (hagree : u.eval (point a) + z * v.eval (point a) = U a + z * V a) :
    affineCharge u v point U V a = z := by
  unfold affineCharge
  apply (div_eq_iff (sub_ne_zero.mpr hden)).2
  linear_combination hagree

omit [DecidableEq I] in
theorem card_labels_le_positions
    (d : ℕ) (positions : Finset I) (point U V : I → K)
    (u v : Polynomial K) (_hu : u.natDegree ≤ d) (hv : v.natDegree ≤ d)
    (labels : Finset K)
    (hsupport : ∀ z ∈ labels, ∃ S : Finset I,
      S ⊆ positions ∧
      (∀ a ∈ S,
        u.eval (point a) + z * v.eval (point a) = U a + z * V a) ∧
      (∀ q : Polynomial K, q.natDegree ≤ d →
        ¬ (∀ a ∈ S, q.eval (point a) = V a))) :
    labels.card ≤ positions.card := by
  classical
  let bad : Finset I := mismatchPositions positions point V v
  let charge : I → K := affineCharge u v point U V
  have hlabel_subset : labels ⊆ bad.image charge := by
    intro z hz
    obtain ⟨S, hSpos, hagree, hnoext⟩ := hsupport z hz
    have hex : ∃ a ∈ S, V a ≠ v.eval (point a) := by
      by_contra hnone
      push Not at hnone
      apply hnoext v hv
      intro a ha
      exact (hnone a ha).symm
    obtain ⟨a, haS, hden⟩ := hex
    have hcharge : charge a = z := charge_eq_label u v point U V z a hden
      (hagree a haS)
    have habad : a ∈ bad := by
      exact Finset.mem_filter.mpr ⟨hSpos haS, hden⟩
    exact Finset.mem_image.mpr ⟨a, habad, hcharge⟩
  calc
    labels.card ≤ (bad.image charge).card := Finset.card_le_card hlabel_subset
    _ ≤ bad.card := Finset.card_image_le
    _ ≤ positions.card := Finset.card_le_card (by
      intro a ha
      exact (Finset.mem_filter.mp ha).1)

end
end HegemonCrypto.SmallWood.Mca38AffineBadLabelCount
