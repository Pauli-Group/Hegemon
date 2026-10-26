import Hegemon.Consensus.Supply
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Algebra.BigOperators.Group.Finset.Sigma
import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Order.Monotone.Basic
import Lean.Elab.Tactic.Omega

/-! Exact native epoch-budget emission policy. The epoch budget is a difference
of remaining budgets; each block is a difference of integer floor prefixes.
Both levels telescope. No cap or constant per-block approximation is supplied
as a theorem premise. Finsets count each accepted issuance height once.
This is not gross fee-inclusive supply_digest accounting, native circulating
wealth/history conservation, Rust/compiler refinement or release authority.
The previous integer-halving policy and its actual receipts remain historical.
-/
set_option maxRecDepth 10000
open scoped BigOperators
namespace HegemonCrypto.NativeMonetaryCap
open Hegemon.Consensus

/-- Generic arithmetic: increasing integer prefixes telescope without loss. -/
theorem nat_forward_prefix_sum (f : Nat → Nat) (mono : Monotone f) (n : Nat) :
    (∑ j ∈ Finset.range n, (f (j + 1) - f j)) = f n - f 0 :=
  Finset.sum_range_tsub mono n

/-- Generic arithmetic: decreasing remaining budgets telescope without loss. -/
theorem nat_remaining_budget_sum (f : Nat → Nat)
    (decreasing : ∀ j, f (j + 1) ≤ f j) (n : Nat) :
    (∑ j ∈ Finset.range n, (f j - f (j + 1))) + f n = f 0 := by
  induction n with
  | zero => simp
  | succ n ih =>
      rw [Finset.sum_range_succ]
      have bounded := decreasing n
      omega

theorem floor_prefix_monotone (budget interval : Nat) :
    Monotone (fun slot : Nat => slot * budget / interval) := by
  intro left right ordered
  exact Nat.div_le_div_right (Nat.mul_le_mul_right budget ordered)

theorem slot_subsidy_prefix_sum (epoch slots : Nat) :
    (∑ slot ∈ Finset.range slots, slotSubsidy epoch slot) =
      slots * epochBudget epoch / halvingInterval := by
  simpa [slotSubsidy] using
    nat_forward_prefix_sum
      (fun slot => slot * epochBudget epoch / halvingInterval)
      (floor_prefix_monotone (epochBudget epoch) halvingInterval) slots

theorem interval_positive : 0 < halvingInterval := by decide

theorem slot_subsidy_full_epoch (epoch : Nat) :
    (∑ slot ∈ Finset.range halvingInterval, slotSubsidy epoch slot) =
      epochBudget epoch := by
  rw [slot_subsidy_prefix_sum]
  exact Nat.mul_div_cancel_left _ interval_positive

theorem remaining_at_zero : remainingBudget 0 = maxMonetarySupply := by decide

theorem remaining_at_51 : remainingBudget 51 = 0 := by decide

theorem remaining_at_64 : remainingBudget 64 = 0 := by decide

theorem remaining_budget_succ_le (epoch : Nat) :
    remainingBudget (epoch + 1) ≤ remainingBudget epoch := by
  by_cases active : epoch < 64
  · by_cases nextActive : epoch + 1 < 64
    · simp only [remainingBudget, if_pos active, if_pos nextActive]
      apply Nat.div_le_div_left
      · unfold pow2
        rw [Nat.pow_succ]
        omega
      · unfold pow2
        exact Nat.two_pow_pos epoch
    · simp [remainingBudget, active, nextActive]
  · have nextInactive : ¬ epoch + 1 < 64 := by omega
    simp [remainingBudget, active, nextInactive]

theorem remaining_budget_antitone : Antitone remainingBudget :=
  antitone_nat_of_succ_le remaining_budget_succ_le

theorem remaining_budget_late {epoch : Nat} (late : 51 ≤ epoch) :
    remainingBudget epoch = 0 := by
  have bounded := remaining_budget_antitone late
  rw [remaining_at_51] at bounded
  omega

theorem epoch_budget_late {epoch : Nat} (late : 51 ≤ epoch) :
    epochBudget epoch = 0 := by
  unfold epochBudget
  rw [remaining_budget_late late, remaining_budget_late (by omega : 51 ≤ epoch + 1)]

theorem subsidy_after_last_epoch {height : Nat}
    (late : 51 ≤ (height - 1) / halvingInterval) : blockSubsidy height = 0 := by
  by_cases zero : height = 0
  · simp [blockSubsidy, zero]
  · simp only [blockSubsidy, if_neg zero, subsidyEpoch, subsidySlot, slotSubsidy]
    rw [epoch_budget_late late]
    simp

/-- Compatibility audit name; current extinction concerns epoch budgets. -/
theorem subsidy_epoch63_zero : epochBudget 63 = 0 :=
  epoch_budget_late (by decide)

/-- Exact total from the actual 51 positive-budget epochs; not an assumed cap. -/
def lifetimeIssuance : Nat := ∑ epoch ∈ Finset.range 51, epochBudget epoch

theorem lifetime_issuance_eq_cap : lifetimeIssuance = maxMonetarySupply := by
  have telescope := nat_remaining_budget_sum remainingBudget remaining_budget_succ_le 51
  change lifetimeIssuance + remainingBudget 51 = remainingBudget 0 at telescope
  rw [remaining_at_51, remaining_at_zero, Nat.add_zero] at telescope
  exact telescope

theorem lifetime_issuance_exact : lifetimeIssuance = 2100000000000000 := by
  rw [lifetime_issuance_eq_cap]
  decide

theorem lifetime_issuance_le_cap : lifetimeIssuance ≤ maxMonetarySupply :=
  Nat.le_of_eq lifetime_issuance_eq_cap

theorem cap_exact : maxMonetarySupply = 21000000 * 100000000 := by decide

theorem cap_gap_exact : maxMonetarySupply - lifetimeIssuance = 0 := by
  rw [lifetime_issuance_eq_cap]
  simp

/-- Each height maps injectively to its actual epoch and slot. The entire grid
sums to the epoch budgets because slot differences telescope within each epoch. -/
theorem blockSubsidy_finset_sum_le_lifetime (heights : Finset Nat) :
    (∑ height ∈ heights, blockSubsidy height) ≤ lifetimeIssuance := by
  classical
  let active := heights.filter (fun h => h ≠ 0 ∧ (h - 1) / halvingInterval < 51)
  let address := fun h : Nat => ((h - 1) / halvingInterval, (h - 1) % halvingInterval)
  have injective : Set.InjOn address (↑active : Set Nat) := by
    intro a ha b hb same
    have positiveA := (Finset.mem_filter.mp ha).2.1
    have positiveB := (Finset.mem_filter.mp hb).2.1
    have quotient : (a - 1) / halvingInterval = (b - 1) / halvingInterval :=
      congrArg Prod.fst same
    have remainder : (a - 1) % halvingInterval = (b - 1) % halvingInterval :=
      congrArg Prod.snd same
    have decompositionA := Nat.mod_add_div (a - 1) halvingInterval
    have decompositionB := Nat.mod_add_div (b - 1) halvingInterval
    rw [quotient, remainder] at decompositionA
    omega
  have subset : active.image address ⊆
      (Finset.range 51).product (Finset.range halvingInterval) := by
    intro pair member
    obtain ⟨h, hh, rfl⟩ := Finset.mem_image.mp member
    exact Finset.mem_product.mpr
      ⟨Finset.mem_range.mpr (Finset.mem_filter.mp hh).2.2,
       Finset.mem_range.mpr (Nat.mod_lt _ interval_positive)⟩
  have reduce : (∑ h ∈ heights, blockSubsidy h) = ∑ h ∈ active, blockSubsidy h := by
    symm
    apply Finset.sum_subset (Finset.filter_subset _ _)
    intro h hh outside
    by_cases zero : h = 0
    · simp [zero, blockSubsidy]
    · apply subsidy_after_last_epoch
      have noActive : ¬ (h - 1) / halvingInterval < 51 := by
        intro small
        exact outside (Finset.mem_filter.mpr ⟨hh, zero, small⟩)
      omega
  calc
    (∑ h ∈ heights, blockSubsidy h) = ∑ h ∈ active, blockSubsidy h := reduce
    _ = ∑ pair ∈ active.image address, slotSubsidy pair.1 pair.2 := by
      rw [Finset.sum_image injective]
      apply Finset.sum_congr rfl
      intro h hh
      have positive := (Finset.mem_filter.mp hh).2.1
      simp [blockSubsidy, positive, subsidyEpoch, subsidySlot, address]
    _ ≤ ∑ pair ∈ (Finset.range 51).product (Finset.range halvingInterval),
        slotSubsidy pair.1 pair.2 := Finset.sum_le_sum_of_subset subset
    _ = ∑ epoch ∈ Finset.range 51, epochBudget epoch := by
      simp only [Finset.product_eq_sprod, Finset.sum_product', slot_subsidy_full_epoch]
    _ = lifetimeIssuance := rfl

theorem blockSubsidy_finset_sum_le_cap (heights : Finset Nat) :
    (∑ height ∈ heights, blockSubsidy height) ≤ maxMonetarySupply :=
  (blockSubsidy_finset_sum_le_lifetime heights).trans lifetime_issuance_le_cap

theorem blockSubsidy_prefix_sum_le_lifetime (length : Nat) :
    (∑ height ∈ Finset.range length, blockSubsidy height) ≤ lifetimeIssuance :=
  blockSubsidy_finset_sum_le_lifetime _

theorem blockSubsidy_prefix_sum_le_cap (length : Nat) :
    (∑ height ∈ Finset.range length, blockSubsidy height) ≤ maxMonetarySupply :=
  blockSubsidy_finset_sum_le_cap _

theorem subsidy_sum_prefix_monotone :
    Monotone (fun length => ∑ height ∈ Finset.range length, blockSubsidy height) := by
  intro left right ordered
  exact Finset.sum_le_sum_of_subset (Finset.range_mono ordered)

theorem scheduled_prefix_le_cap (height : Nat) : scheduledPrefix height ≤ maxMonetarySupply := by
  let epoch := height / halvingInterval
  let slots := height % halvingInterval
  have slotBound : slots ≤ halvingInterval :=
    Nat.le_of_lt (Nat.mod_lt height interval_positive)
  have partialBound : slots * epochBudget epoch / halvingInterval ≤ epochBudget epoch := by
    calc
      slots * epochBudget epoch / halvingInterval ≤
          halvingInterval * epochBudget epoch / halvingInterval :=
        Nat.div_le_div_right (Nat.mul_le_mul_right _ slotBound)
      _ = epochBudget epoch := Nat.mul_div_cancel_left _ interval_positive
  have epochBound : epochBudget epoch ≤ remainingBudget epoch := Nat.sub_le _ _
  have remainingBound : remainingBudget epoch ≤ maxMonetarySupply := by
    have bounded := remaining_budget_antitone (Nat.zero_le epoch)
    rw [remaining_at_zero] at bounded
    exact bounded
  change maxMonetarySupply - remainingBudget epoch +
    slots * epochBudget epoch / halvingInterval ≤ maxMonetarySupply
  omega

/-- Full positive support, including zero slots, with its exact native height. -/
def issuanceHeights : Finset Nat :=
  ((Finset.range 51).product (Finset.range halvingInterval)).image
    (fun address : Nat × Nat => address.1 * halvingInterval + address.2 + 1)

private theorem decoded_epoch (epoch slot : Nat) (small : slot < halvingInterval) :
    ((epoch * halvingInterval + slot + 1) - 1) / halvingInterval = epoch := by
  change slot < 2100000 at small
  change ((epoch * 2100000 + slot + 1) - 1) / 2100000 = epoch
  omega

private theorem decoded_slot (epoch slot : Nat) (small : slot < halvingInterval) :
    ((epoch * halvingInterval + slot + 1) - 1) % halvingInterval = slot := by
  change slot < 2100000 at small
  change ((epoch * 2100000 + slot + 1) - 1) % 2100000 = slot
  omega

private theorem decoded_subsidy (epoch slot : Nat) (small : slot < halvingInterval) :
    blockSubsidy (epoch * halvingInterval + slot + 1) = slotSubsidy epoch slot := by
  have positive : epoch * halvingInterval + slot + 1 ≠ 0 := by omega
  simp only [blockSubsidy, if_neg positive, subsidyEpoch, subsidySlot]
  rw [decoded_epoch epoch slot small, decoded_slot epoch slot small]

theorem complete_schedule_sum_exact :
    (∑ height ∈ issuanceHeights, blockSubsidy height) = lifetimeIssuance := by
  classical
  have injective : Set.InjOn
      (fun address : Nat × Nat => address.1 * halvingInterval + address.2 + 1)
      (↑((Finset.range 51).product (Finset.range halvingInterval)) : Set (Nat × Nat)) := by
    intro a ha b hb same
    have smallA := Finset.mem_range.mp (Finset.mem_product.mp ha).2
    have smallB := Finset.mem_range.mp (Finset.mem_product.mp hb).2
    have epochEq : a.1 = b.1 := by
      have encoded := congrArg (fun h : Nat => (h - 1) / halvingInterval) same
      simpa only [decoded_epoch a.1 a.2 smallA, decoded_epoch b.1 b.2 smallB] using encoded
    apply Prod.ext epochEq
    change a.1 * halvingInterval + a.2 + 1 = b.1 * halvingInterval + b.2 + 1 at same
    rw [epochEq] at same
    omega
  unfold issuanceHeights
  rw [Finset.sum_image injective]
  calc
    (∑ address ∈ (Finset.range 51).product (Finset.range halvingInterval),
        blockSubsidy (address.1 * halvingInterval + address.2 + 1)) =
        ∑ address ∈ (Finset.range 51).product (Finset.range halvingInterval),
          slotSubsidy address.1 address.2 := by
      apply Finset.sum_congr rfl
      intro address member
      exact decoded_subsidy address.1 address.2
        (Finset.mem_range.mp (Finset.mem_product.mp member).2)
    _ = lifetimeIssuance := by
      simp only [Finset.product_eq_sprod, Finset.sum_product',
        slot_subsidy_full_epoch, lifetimeIssuance]

theorem complete_schedule_sum_atoms :
    (∑ height ∈ issuanceHeights, blockSubsidy height) = 2100000000000000 :=
  complete_schedule_sum_exact.trans lifetime_issuance_exact

theorem first_block_exact : blockSubsidy 1 = 5 * coin := by decide

theorem last_positive_block_exact : blockSubsidy 107100000 = 1 := by decide

theorem subsidy_cutoff_zero {height : Nat} (late : 107100001 ≤ height) :
    blockSubsidy height = 0 := by
  apply subsidy_after_last_epoch
  change 51 ≤ (height - 1) / 2100000
  omega

/-- Actual shipping source split: numerator1/denominator5; all fees go to miner.
These Nat functions model the successful u64 checked-add branch. The one-fifth
share is rounded down per block; no exact aggregate20percent allocation is
claimed from per-block rounding. Rounding dust remains in the miner share. -/
def fundingReward (subsidy : Nat) : Nat := subsidy / 5
def minerReward (subsidy fees : Nat) : Nat := subsidy - fundingReward subsidy + fees

theorem funding_is_one_fifth (subsidy : Nat) : fundingReward subsidy = subsidy / 5 := rfl

theorem funding_le_subsidy (subsidy : Nat) : fundingReward subsidy ≤ subsidy :=
  Nat.div_le_self _ _

theorem miner_and_funding_sum (subsidy fees : Nat) :
    minerReward subsidy fees + fundingReward subsidy = subsidy + fees := by
  have bounded := funding_le_subsidy subsidy
  unfold minerReward
  omega

/-- Fees are recycled from existing ownership; subtracting the included fees
from both coinbase outputs leaves exactly the new subsidy. Accepted transfer
fee conservation/history and the Rust checked-add branch are separate bindings. -/
theorem net_new_is_subsidy (subsidy fees : Nat) :
    (minerReward subsidy fees + fundingReward subsidy) - fees = subsidy := by
  rw [miner_and_funding_sum]
  omega

theorem zero_subsidy_funding : fundingReward 0 = 0 := rfl

theorem zero_subsidy_miner_fees (fees : Nat) : minerReward 0 fees = fees :=
  Nat.zero_add fees

end HegemonCrypto.NativeMonetaryCap
