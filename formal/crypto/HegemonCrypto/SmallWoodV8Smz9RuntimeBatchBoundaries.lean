import HegemonCrypto.SmallWoodV8Smz9RuntimeBatchBridge

namespace HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge

open V8Smz9RuntimeRandomness

private def accepted0 : RawWord := ⟨0, by decide⟩
private def accepted1 : RawWord := ⟨1, by decide⟩
private def accepted2 : RawWord := ⟨2, by decide⟩
private def rejected : RawWord :=
  ⟨fieldModulus, field_modulus_lt_raw_word_cardinality⟩

theorem zero_extra_empty_round_rejected : ¬ValidBatches 0 [[]] := by
  simp only [ValidBatches]
  decide

theorem too_short_refill_rejected : ¬ValidBatches 2 [[accepted0], [accepted1]] := by
  simp only [ValidBatches]
  decide

theorem oversized_refill_rejected : ¬ValidBatches 2 [[accepted0, accepted1, accepted2]] := by
  simp only [ValidBatches]
  decide

theorem rejection_updates_remaining_width :
    ValidBatches 2 [[rejected, accepted0], [accepted1]] := by
  simp only [ValidBatches]
  decide

theorem all_reject_round_does_not_decrease_missing_count :
    ValidBatches 2 [[rejected, rejected], [accepted0, accepted1]] := by
  simp only [ValidBatches]
  decide

theorem rejected_tail_after_last_acceptance_rejected :
    ¬ExactPrefix 1 [accepted0, rejected] := by
  simp only [ExactPrefix]
  decide


end HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge
