import Hegemon.Consensus.Supply
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.BigOperators.Group.Finset.Sigma
import Lean.Elab.Tactic.Omega
import Mathlib.Algebra.BigOperators.Ring.Finset

set_option maxRecDepth 10000

open scoped BigOperators

namespace Hegemon.Consensus

theorem subsidy_epoch63_zero : initialSubsidy / pow2 63 = 0 := by decide

theorem subsidy_after_last_epoch {h : Nat}
    (late : 63 ≤ (h - 1) / halvingInterval) : blockSubsidy h = 0 := by
  by_cases hz : h = 0
  · simp [hz, blockSubsidy]
  · simp [blockSubsidy, hz, cappedHalvingEpoch, Nat.min_eq_right late,
      subsidy_epoch63_zero]

/-- Integer-floor halving buckets, evaluated in the kernel, not an assumed cap. -/
theorem halving_bucket_budget :
    halvingInterval * (∑ epoch ∈ Finset.range 63, initialSubsidy / pow2 epoch)
      ≤ maxMonetarySupply := by decide

/-- A finite set counts each height once; no schedule-supply bound is assumed. -/
theorem blockSubsidy_finset_sum_le (heights : Finset Nat) :
    (∑ height ∈ heights, blockSubsidy height) ≤ maxMonetarySupply := by
  classical
  let active := heights.filter (fun h => h ≠ 0 ∧ (h - 1) / halvingInterval < 63)
  let address := fun h : Nat => ((h - 1) / halvingInterval, (h - 1) % halvingInterval)
  have interval_pos : 0 < halvingInterval := by decide
  have hinj : Set.InjOn address (↑active : Set Nat) := by
    intro a ha b hb hab
    have ha0 := (Finset.mem_filter.mp ha).2.1
    have hb0 := (Finset.mem_filter.mp hb).2.1
    have hq : (a - 1) / halvingInterval = (b - 1) / halvingInterval := congrArg Prod.fst hab
    have hr : (a - 1) % halvingInterval = (b - 1) % halvingInterval := congrArg Prod.snd hab
    have ea := Nat.mod_add_div (a - 1) halvingInterval
    have eb := Nat.mod_add_div (b - 1) halvingInterval
    rw [hq, hr] at ea
    omega
  have subset : active.image address ⊆ (Finset.range 63).product (Finset.range halvingInterval) := by
    intro pair hp
    obtain ⟨h, hh, rfl⟩ := Finset.mem_image.mp hp
    exact Finset.mem_product.mpr ⟨Finset.mem_range.mpr (Finset.mem_filter.mp hh).2.2,
      Finset.mem_range.mpr (Nat.mod_lt _ interval_pos)⟩
  have reduce : (∑ h ∈ heights, blockSubsidy h) = ∑ h ∈ active, blockSubsidy h := by
    symm
    apply Finset.sum_subset (Finset.filter_subset _ _)
    intro h hh outside
    by_cases hz : h = 0
    · simp [hz, blockSubsidy]
    · apply subsidy_after_last_epoch
      have : ¬ (h - 1) / halvingInterval < 63 := by
        intro small
        exact outside (Finset.mem_filter.mpr ⟨hh,hz,small⟩)
      omega
  calc
    (∑ h ∈ heights, blockSubsidy h) = ∑ h ∈ active, blockSubsidy h := reduce
    _ = ∑ pair ∈ active.image address, initialSubsidy / pow2 pair.1 := by
      rw [Finset.sum_image hinj]
      apply Finset.sum_congr rfl
      intro h hh
      have data := (Finset.mem_filter.mp hh).2
      simp [blockSubsidy, data.1, cappedHalvingEpoch,
        Nat.min_eq_left (Nat.le_of_lt data.2), address]
    _ ≤ ∑ pair ∈ (Finset.range 63).product (Finset.range halvingInterval),
        initialSubsidy / pow2 pair.1 := Finset.sum_le_sum_of_subset subset
    _ = halvingInterval * (∑ epoch ∈ Finset.range 63, initialSubsidy / pow2 epoch) := by
      simp [Finset.sum_product, Finset.mul_sum]
    _ ≤ maxMonetarySupply := halving_bucket_budget

theorem blockSubsidy_prefix_sum_le (length : Nat) :
    (∑ height ∈ Finset.range length, blockSubsidy height) ≤ maxMonetarySupply :=
  blockSubsidy_finset_sum_le _

end Hegemon.Consensus

#print axioms Hegemon.Consensus.blockSubsidy_finset_sum_le
