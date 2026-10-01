import SmzaRecordSplitR3

/-! Record-slot support for the concrete Split construction. This is support
of physical record registers, not an asserted successful extraction log. -/
namespace HegemonCrypto.SmallWood.SmzaRecordSupportR5

open SmzaRecordSplitR3 V8Smz9CoherentMerklePartition
open scoped BigOperators Classical
noncomputable section

variable {Target Label Cell Answer : Type*}
variable [DecidableEq Target] [DecidableEq Label] [Fintype Target]

def activeTargets (empty : Cell) (registers : Registers Target Label Cell) : Finset Target :=
  Finset.univ.filter fun target => ∃ label, registers (target, label) ≠ empty

omit [DecidableEq Target] [Fintype Target] in
theorem active_split_iff (empty : Cell) (label : Target → Label)
    (registers : Registers Target Label Cell) (target : Target) :
    (∃ index, splitRegisters label registers (target, index) ≠ empty) ↔
      ∃ index, registers (target, index) ≠ empty := by
  constructor
  · rintro ⟨index, different⟩
    exact ⟨Equiv.swap none (some (label target)) index, different⟩
  · rintro ⟨index, different⟩
    refine ⟨Equiv.swap none (some (label target)) index, ?_⟩
    simpa [splitRegisters, reindex, slotSplit] using different

omit [DecidableEq Target] in
theorem split_preserves_active_targets (empty : Cell) (label : Target → Label)
    (registers : Registers Target Label Cell) :
    activeTargets empty (splitRegisters label registers) = activeTargets empty registers := by
  ext target
  simp only [activeTargets, Finset.mem_filter, Finset.mem_univ, true_and]
  exact active_split_iff empty label registers target

/- One actual local record operation can introduce at most its own target.
The gate is an arbitrary complex kernel and may be fully quantum. -/
omit [DecidableEq Label] in
theorem nonzero_record_kernel_active_subset (empty : Cell)
    (slot : Slot Target Label)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : Answer × Registers Target Label Cell)
    (nonzero : localRecordKernel slot gate source target ≠ 0) :
    activeTargets empty target.2 ⊆ insert slot.1 (activeTargets empty source.2) := by
  have agreement : agreeOutside slot source.2 target.2 := by
    by_contra missing
    simp [localRecordKernel, missing] at nonzero
  intro selected member
  by_cases same : selected = slot.1
  · exact Finset.mem_insert.mpr (Or.inl same)
  · apply Finset.mem_insert_of_mem
    obtain ⟨index, different⟩ := (Finset.mem_filter.mp member).2
    apply Finset.mem_filter.mpr
    refine ⟨Finset.mem_univ _, index, ?_⟩
    have outside : (selected, index) ≠ slot := by
      intro equal
      exact same (congrArg Prod.fst equal)
    have equal := agreement (selected, index) outside
    exact fun absent => different (equal.symm.trans absent)

omit [DecidableEq Label] in
theorem nonzero_record_kernel_active_card (empty : Cell)
    (slot : Slot Target Label)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (source target : Answer × Registers Target Label Cell)
    (nonzero : localRecordKernel slot gate source target ≠ 0) :
    (activeTargets empty target.2).card ≤ (activeTargets empty source.2).card + 1 :=
  (Finset.card_le_card
    (nonzero_record_kernel_active_subset empty slot gate source target nonzero)).trans
      (Finset.card_insert_le _ _)

variable [Fintype Label] [Fintype Cell] [Fintype Answer]

/- Quantum support growth, derived from the actual matrix entries. There is
no measurement of the target register and no successful-preimage premise. -/
theorem record_query_support_growth (empty : Cell)
    (slot : Slot Target Label)
    (gate : (Answer × Cell) → (Answer × Cell) → ℂ)
    (state : (Answer × Registers Target Label Cell) → ℂ) (bound : ℕ)
    (supported : ∀ basis, bound < (activeTargets empty basis.2).card → state basis = 0) :
    ∀ basis, bound + 1 < (activeTargets empty basis.2).card →
      applyKernel (localRecordKernel slot gate) state basis = 0 := by
  intro target tooLarge
  unfold applyKernel
  apply Finset.sum_eq_zero
  intro source _
  by_cases zero : state source = 0
  · rw [zero, zero_mul]
  · have before : (activeTargets empty source.2).card ≤ bound := by
      by_contra greater
      exact zero (supported source (Nat.lt_of_not_ge greater))
    by_cases zeroKernel : localRecordKernel slot gate source target = 0
    · rw [zeroKernel, mul_zero]
    · have growth := nonzero_record_kernel_active_card empty slot gate source target zeroKernel
      have impossible : (activeTargets empty target.2).card ≤ bound + 1 :=
        growth.trans (Nat.add_le_add_right before 1)
      exact False.elim (Nat.not_lt_of_ge impossible tooLarge)

end
end HegemonCrypto.SmallWood.SmzaRecordSupportR5
