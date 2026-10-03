import HegemonCrypto.Goldilocks
import Mathlib.Data.Finset.Card
import Mathlib.Data.List.Nodup
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Positivity
import Mathlib.Tactic.Push
import Mathlib.Tactic.Ring

/-!
# RP05 threshold-history arithmetic and finite combinatorics

This file proves the algebraic consequences of the proposed RP05 role gates
and the finite combinatorics of an explicit sequence of Approval transitions.
It does not assume that an accepted transcript has such a history.  Projecting
accepted source witnesses and honest producer state into `ApprovalHistory`
remains a separate registry/refinement obligation.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ThresholdHistory

set_option autoImplicit false

/-! ## T1/T2 selected-value positivity -/

/-- `phi(g,v) = 1-g+g*v`: an unselected factor is one and a selected factor
is the represented value. -/
def selectedValue {K : Type*} [Field K] (selected value : K) : K :=
  1 - selected + selected * value

/-- The common two-factor form used by both inverse-product gates. -/
def selectedPairProduct {K : Type*} [Field K]
    (inverse leftSelected leftValue rightSelected rightValue : K) : K :=
  inverse * selectedValue leftSelected leftValue *
    selectedValue rightSelected rightValue

private theorem selected_left_ne_zero {K : Type*} [Field K]
    {inverse leftSelected leftValue rightSelected rightValue : K}
    (equation : selectedPairProduct inverse leftSelected leftValue
      rightSelected rightValue = 1)
    (selected : leftSelected = 1) :
    leftValue ≠ 0 := by
  intro valueZero
  have impossible : (0 : K) = 1 := by
    simp [selectedPairProduct, selectedValue, selected, valueZero] at equation
  exact zero_ne_one impossible

private theorem selected_right_ne_zero {K : Type*} [Field K]
    {inverse leftSelected leftValue rightSelected rightValue : K}
    (equation : selectedPairProduct inverse leftSelected leftValue
      rightSelected rightValue = 1)
    (selected : rightSelected = 1) :
    rightValue ≠ 0 := by
  intro valueZero
  have impossible : (0 : K) = 1 := by
    simp [selectedPairProduct, selectedValue, selected, valueZero] at equation
  exact zero_ne_one impossible

theorem selected_pair_values_ne_zero {K : Type*} [Field K]
    {inverse leftSelected leftValue rightSelected rightValue : K}
    (equation : selectedPairProduct inverse leftSelected leftValue
      rightSelected rightValue = 1) :
    (leftSelected = 1 → leftValue ≠ 0) ∧
      (rightSelected = 1 → rightValue ≠ 0) := by
  exact ⟨selected_left_ne_zero equation, selected_right_ne_zero equation⟩

/-- The exact T1 input product. -/
def t1Product {K : Type*} [Field K]
    (zIn single approval finalMode i0 i1 vi0 vi1 : K) : K :=
  selectedPairProduct zIn (i0 * (single + finalMode)) vi0
    (i1 * (single + approval)) vi1

/-- T1 forces each value whose role selector is one to be nonzero. -/
theorem t1_selected_values_ne_zero {K : Type*} [Field K]
    {zIn single approval finalMode i0 i1 vi0 vi1 : K}
    (equation : t1Product zIn single approval finalMode i0 i1 vi0 vi1 = 1) :
    (i0 * (single + finalMode) = 1 → vi0 ≠ 0) ∧
      (i1 * (single + approval) = 1 → vi1 ≠ 0) := by
  exact selected_pair_values_ne_zero equation

/-- The exact T2 output product. -/
def t2Product {K : Type*} [Field K]
    (zOut single finalMode o0 o1 vo0 vo1 : K) : K :=
  selectedPairProduct zOut (o0 * (single + finalMode)) vo0 o1 vo1

/-- T2 forces each value whose role selector is one to be nonzero. -/
theorem t2_selected_values_ne_zero {K : Type*} [Field K]
    {zOut single finalMode o0 o1 vo0 vo1 : K}
    (equation : t2Product zOut single finalMode o0 o1 vo0 vo1 = 1) :
    (o0 * (single + finalMode) = 1 → vo0 ≠ 0) ∧
      (o1 = 1 → vo1 ≠ 0) := by
  exact selected_pair_values_ne_zero equation

/-! ## T4/T5 exact count-zero activity gate -/

/-- The six linear count factors in T5.  Multiplication by `A*i0` makes the
whole constraint degree eight. -/
def approvalRangeProduct (count : Goldilocks) : Goldilocks :=
  (count - 1) * (count - 2) * (count - 3) *
    (count - 4) * (count - 5) * (count - 6)

theorem goldilocks_modulus_gt_720 :
    720 < Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus := by
  norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]

theorem goldilocks_720_ne_zero : (720 : Goldilocks) ≠ 0 := by
  change (720 : ZMod
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus) ≠ 0
  intro castZero
  exact (Nat.not_dvd_of_pos_of_lt (by norm_num) goldilocks_modulus_gt_720)
    ((ZMod.natCast_eq_zero_iff _ _).mp castZero)

theorem approval_range_product_at_zero :
    approvalRangeProduct 0 = (720 : Goldilocks) := by
  norm_num [approvalRangeProduct]

/-- T4 is `A*(1-i0)*count = 0`. -/
def T4 (approval i0 : Goldilocks) (count : Fin 7) : Prop :=
  approval * (1 - i0) * (count.val : Goldilocks) = 0

/-- T5 is `A*i0*prod(count-j)=0` for `j=1,...,6`. -/
def T5 (approval i0 : Goldilocks) (count : Fin 7) : Prop :=
  approval * i0 * approvalRangeProduct (count.val : Goldilocks) = 0

private theorem fin7_cast_eq_zero {count : Fin 7}
    (castZero : (count.val : Goldilocks) = 0) :
    count.val = 0 := by
  have divides :
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus ∣
        count.val := by
    exact (ZMod.natCast_eq_zero_iff count.val
      Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus).mp
        castZero
  apply Nat.eq_zero_of_dvd_of_lt divides
  exact count.isLt.trans (by
    norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus])

/-- With Approval selected and a Boolean input flag, T4 and the degree-eight
T5 gate prove the intended equivalence, not merely one implication. -/
theorem approval_input_inactive_iff_count_zero
    {approval i0 : Goldilocks} {count : Fin 7}
    (approvalSelected : approval = 1)
    (i0Boolean : i0 = 0 ∨ i0 = 1)
    (t4 : T4 approval i0 count)
    (t5 : T5 approval i0 count) :
    i0 = 0 ↔ count.val = 0 := by
  constructor
  · intro inputInactive
    apply fin7_cast_eq_zero
    simpa [T4, approvalSelected, inputInactive] using t4
  · intro countZero
    rcases i0Boolean with inputInactive | inputActive
    · exact inputInactive
    · exfalso
      apply goldilocks_720_ne_zero
      simpa [T5, approvalSelected, inputActive, countZero,
        approval_range_product_at_zero] using t5

/-! ## Explicit one-hot Approval histories -/

abbrev SignerSlot := Fin 6

structure ApprovalState where
  count : Nat
  bitmap : Finset SignerSlot
deriving DecidableEq

/-- One Approval inserts exactly one previously-unselected signer slot and
increments the committed count exactly once. -/
structure ApprovalStep (before : ApprovalState) (slot : SignerSlot)
    (after : ApprovalState) : Prop where
  fresh : slot ∉ before.bitmap
  count_eq : after.count = before.count + 1
  bitmap_eq : after.bitmap = insert slot before.bitmap

/-- A concrete chronological transition sequence.  `snoc` records the edge
in the same order in which it is applied. -/
inductive ApprovalHistory : ApprovalState → List SignerSlot → ApprovalState → Prop where
  | nil (state : ApprovalState) : ApprovalHistory state [] state
  | snoc {start middle finish : ApprovalState} {slots : List SignerSlot}
      {slot : SignerSlot}
      (prior : ApprovalHistory start slots middle)
      (step : ApprovalStep middle slot finish) :
      ApprovalHistory start (slots.concat slot) finish

theorem history_count {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish) :
    finish.count = start.count + slots.length := by
  induction history with
  | nil => simp
  | @snoc start middle priorSlots newSlot priorHistory transition inductionHypothesis =>
      rw [transition.count_eq, inductionHypothesis]
      simp [Nat.add_assoc]

theorem history_bitmap {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish) :
    finish.bitmap = start.bitmap ∪ slots.toFinset := by
  induction history with
  | nil => simp
  | @snoc start middle priorSlots newSlot priorHistory transition inductionHypothesis =>
      rw [transition.bitmap_eq, inductionHypothesis]
      ext candidate
      simp

/-- Freshness at every concrete step derives global distinctness; it is not a
field of `ApprovalHistory`. -/
theorem history_slots_nodup {start finish : ApprovalState}
    {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish) :
    slots.Nodup := by
  induction history with
  | nil => simp
  | @snoc start middle priorSlots newSlot priorHistory transition inductionHypothesis =>
      rw [List.nodup_concat]
      refine ⟨?_, inductionHypothesis⟩
      intro earlier
      apply transition.fresh
      rw [history_bitmap priorHistory]
      exact Finset.mem_union_right _ (by simpa using earlier)

/-- The one-hot insert rule preserves `weight(bitmap)=count`. -/
theorem history_preserves_weight {start finish : ApprovalState}
    {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startWeight : start.bitmap.card = start.count) :
    finish.bitmap.card = finish.count := by
  induction history with
  | nil => exact startWeight
  | @snoc start middle priorSlots newSlot priorHistory transition inductionHypothesis =>
      calc
        _ = start.bitmap.card + 1 := by
          rw [transition.bitmap_eq, Finset.card_insert_of_notMem transition.fresh]
        _ = start.count + 1 := by rw [inductionHypothesis]
        _ = middle.count := transition.count_eq.symm

/-- A bootstrap history exposes both conclusions used by threshold
provenance: distinct edge slots and exact terminal bitmap weight. -/
theorem zero_start_history_distinct_and_weight
    {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startCount : start.count = 0)
    (startBitmap : start.bitmap = ∅) :
    slots.Nodup ∧ finish.bitmap.card = finish.count := by
  refine ⟨history_slots_nodup history, ?_⟩
  apply history_preserves_weight history
  simp [startCount, startBitmap]

/-- If the terminal count reaches threshold while fewer than threshold slots
belong to `corrupted ∪ honestlyAuthorized`, one actual history edge lies
outside that union.  Edge count and distinctness are derived from the concrete
history above. -/
theorem terminal_threshold_has_uncovered_edge
    {start finish : ApprovalState} {slots : List SignerSlot}
    (history : ApprovalHistory start slots finish)
    (startCount : start.count = 0)
    (threshold : Nat)
    (thresholdReached : threshold ≤ finish.count)
    (corrupted honestlyAuthorized : Finset SignerSlot)
    (authorizedSmall : (corrupted ∪ honestlyAuthorized).card < threshold) :
    ∃ slot ∈ slots, slot ∉ corrupted ∪ honestlyAuthorized := by
  have count_eq_length : finish.count = slots.length := by
    simpa [startCount] using history_count history
  have slotsCard : slots.toFinset.card = slots.length :=
    List.toFinset_card_of_nodup (history_slots_nodup history)
  have cardLt :
      (corrupted ∪ honestlyAuthorized).card < slots.toFinset.card := by
    omega
  obtain ⟨slot, inHistory, outside⟩ :=
    Finset.exists_mem_notMem_of_card_lt_card cardLt
  exact ⟨slot, by simpa using inHistory, outside⟩

/-! ## Generic finite event partition -/

def finiteProbability {Outcome : Type*} [Fintype Outcome]
    (event : Finset Outcome) : Rat :=
  event.card / Fintype.card Outcome

/-- Pure finite counting form of the separate-reductions partition.  The
event inclusion remains a premise: this theorem does not assert the RP05
registry/source projection. -/
theorem finite_event_partition_bound {Outcome : Type*}
    [Fintype Outcome] [DecidableEq Outcome]
    (target extractionFailure bindingBad recoverableFreshKey : Finset Outcome)
    (included : target ⊆
      extractionFailure ∪ bindingBad ∪ recoverableFreshKey) :
    finiteProbability target ≤
      finiteProbability extractionFailure + finiteProbability bindingBad +
        finiteProbability recoverableFreshKey := by
  have cardBound :
      target.card ≤ extractionFailure.card + bindingBad.card +
        recoverableFreshKey.card := by
    calc
      target.card ≤
          (extractionFailure ∪ bindingBad ∪ recoverableFreshKey).card :=
        Finset.card_le_card included
      _ ≤ (extractionFailure ∪ bindingBad).card + recoverableFreshKey.card :=
        Finset.card_union_le _ _
      _ ≤ (extractionFailure.card + bindingBad.card) +
          recoverableFreshKey.card :=
        Nat.add_le_add_right (Finset.card_union_le _ _) _
  unfold finiteProbability
  calc
    (target.card : Rat) / Fintype.card Outcome ≤
        ((extractionFailure.card + bindingBad.card +
          recoverableFreshKey.card : Nat) : Rat) /
            Fintype.card Outcome := by
      apply div_le_div_of_nonneg_right
      · exact_mod_cast cardBound
      · positivity
    _ = (extractionFailure.card : Rat) / Fintype.card Outcome +
          (bindingBad.card : Rat) / Fintype.card Outcome +
          (recoverableFreshKey.card : Rat) / Fintype.card Outcome := by
      push_cast
      ring

end HegemonCrypto.SmallWood.SmzaRp05ThresholdHistory
