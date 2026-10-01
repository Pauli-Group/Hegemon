import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Data.Finset.Card
import Mathlib.Tactic.GCongr
import Mathlib.Tactic.Ring

/-! Finite-union and ledger bookkeeping for the actual outer/inner factor
families.  These lemmas only consume additive degree ledgers; they do not
assume the desired global count or a factor partition.
-/
namespace HegemonCrypto.SmallWood.Mca38WeightedBranchUnions
open scoped BigOperators
noncomputable section
set_option autoImplicit false

theorem card_biUnion_le_sum_card {α β : Type*} [DecidableEq β]
    (s : Finset α) (t : α → Finset β) :
    (s.biUnion t).card ≤ ∑ a ∈ s, (t a).card := by
  exact Finset.card_biUnion_le

theorem card_filter_nonempty_le_sum_card {α β : Type*} [DecidableEq β]
    (labels : Finset α) (support : α → Finset β) :
    (labels.filter (fun a => (support a).Nonempty)).card ≤
      ∑ a ∈ labels, (support a).card := by
  calc
    (labels.filter (fun a => (support a).Nonempty)).card =
        ∑ a ∈ labels.filter (fun a => (support a).Nonempty), 1 := by simp
    _ ≤ ∑ a ∈ labels.filter (fun a => (support a).Nonempty), (support a).card := by
      apply Finset.sum_le_sum
      intro a ha
      exact Finset.card_pos.mpr (Finset.mem_filter.mp ha).2
    _ ≤ ∑ a ∈ labels, (support a).card := by
      exact Finset.sum_le_sum_of_subset_of_nonneg
        (Finset.filter_subset (p := fun a => (support a).Nonempty) labels)
        (fun _ _ _ => Nat.zero_le _)

theorem sum_pairwise_mul_le_product_sums {α : Type*}
    (s : Finset α) (a b : α → ℕ) :
    (∑ i ∈ s, a i * b i) ≤
      (∑ i ∈ s, a i) * (∑ i ∈ s, b i) := by
  calc
    (∑ i ∈ s, a i * b i) ≤ ∑ i ∈ s, a i * (∑ j ∈ s, b j) := by
      apply Finset.sum_le_sum
      intro i hi
      apply Nat.mul_le_mul_left
      exact Finset.single_le_sum (fun _ _ => Nat.zero_le _) hi
    _ = (∑ i ∈ s, a i) * (∑ j ∈ s, b j) := by
      rw [Finset.sum_mul]

theorem weighted_residual_budget
    {α : Type*} (s : Finset α) (m z innerM innerZ : α → ℕ)
    (Y Z : ℕ)
    (hm : (∑ i ∈ s, m i) ≤ Y)
    (hz : (∑ i ∈ s, z i) ≤ Z)
    (hinnerM : ∀ i ∈ s, innerM i ≤ m i)
    (hinnerZ : ∀ i ∈ s, innerZ i ≤ z i) :
    (∑ i ∈ s,
      (innerM i * (1 + 809 * m i) * z i +
        (1 + 809 * m i) * m i * innerZ i)) ≤
      2 * (1 + 809 * Y) * Y * Z := by
  have hprod : (∑ i ∈ s, m i * z i) ≤ Y * Z := by
    exact (sum_pairwise_mul_le_product_sums s m z).trans
      (Nat.mul_le_mul hm hz)
  have hfactor : ∀ i ∈ s, 1 + 809 * m i ≤ 1 + 809 * Y := by
    intro i hi
    have bound : m i ≤ Y :=
      (Finset.single_le_sum (fun _ _ => Nat.zero_le _) hi).trans hm
    exact Nat.add_le_add_left (Nat.mul_le_mul_left 809 bound) 1
  have hpoint : ∀ i ∈ s,
      innerM i * (1 + 809 * m i) * z i +
        (1 + 809 * m i) * m i * innerZ i ≤
      2 * (1 + 809 * Y) * (m i * z i) := by
    intro i hi
    have hmz : innerM i * (1 + 809 * m i) * z i ≤
        (1 + 809 * Y) * (m i * z i) := by
      calc
        innerM i * (1 + 809 * m i) * z i ≤
            m i * (1 + 809 * Y) * z i :=
          Nat.mul_le_mul_right (z i) (Nat.mul_le_mul (hinnerM i hi) (hfactor i hi))
        _ = (1 + 809 * Y) * (m i * z i) := by ring
    have hzg : (1 + 809 * m i) * m i * innerZ i ≤
        (1 + 809 * Y) * (m i * z i) := by
      calc
        (1 + 809 * m i) * m i * innerZ i ≤
            (1 + 809 * Y) * m i * z i :=
          Nat.mul_le_mul (Nat.mul_le_mul_right (m i) (hfactor i hi)) (hinnerZ i hi)
        _ = (1 + 809 * Y) * (m i * z i) := by ring
    exact (Nat.add_le_add hmz hzg).trans_eq (by ring)
  calc
    _ ≤ ∑ i ∈ s, 2 * (1 + 809 * Y) * (m i * z i) :=
      Finset.sum_le_sum (fun i hi => hpoint i hi)
    _ = 2 * (1 + 809 * Y) * (∑ i ∈ s, m i * z i) := by rw [Finset.mul_sum]
    _ ≤ 2 * (1 + 809 * Y) * (Y * Z) := Nat.mul_le_mul_left _ hprod
    _ = 2 * (1 + 809 * Y) * Y * Z := by ring

theorem weighted_incidence_budget
    {α : Type*} (s : Finset α) (m z innerM innerZ : α → ℕ)
    (Y Z : ℕ)
    (hm : (∑ i ∈ s, m i) ≤ Y)
    (hz : (∑ i ∈ s, z i) ≤ Z)
    (hinnerM : ∀ i ∈ s, innerM i ≤ m i)
    (hinnerZ : ∀ i ∈ s, innerZ i ≤ z i) :
    (∑ i ∈ s,
      (innerM i * (809 * z i + 1) + 809 * m i * innerZ i)) ≤
      1618 * Y * Z + Y := by
  have hprod : (∑ i ∈ s, m i * z i) ≤ Y * Z :=
    (sum_pairwise_mul_le_product_sums s m z).trans (Nat.mul_le_mul hm hz)
  have hpoint : ∀ i ∈ s,
      innerM i * (809 * z i + 1) + 809 * m i * innerZ i ≤
      1618 * (m i * z i) + m i := by
    intro i hi
    calc
      _ ≤ m i * (809 * z i + 1) + 809 * m i * z i :=
        Nat.add_le_add (Nat.mul_le_mul_right _ (hinnerM i hi))
          (Nat.mul_le_mul_left _ (hinnerZ i hi))
      _ = 1618 * (m i * z i) + m i := by ring
  calc
    _ ≤ ∑ i ∈ s, (1618 * (m i * z i) + m i) :=
      Finset.sum_le_sum (fun i hi => hpoint i hi)
    _ = 1618 * (∑ i ∈ s, m i * z i) + ∑ i ∈ s, m i := by
      rw [Finset.sum_add_distrib, Finset.mul_sum]
    _ ≤ 1618 * (Y * Z) + Y := Nat.add_le_add (Nat.mul_le_mul_left _ hprod) hm
    _ = 1618 * Y * Z + Y := by ring

end
end HegemonCrypto.SmallWood.Mca38WeightedBranchUnions
