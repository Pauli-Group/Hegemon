import SmzaRp05CurrentSourceLedgerPrefix
import SmzaRp05CurrentInputSlotUniqueness
import SmzaRp05SupplyClosureHistoricalInputs
import SmzaRp05SupplyClosureInputNative

/-! # Current source spend-position set

The source spend list records positive input slots individually.  Its
position image as a finite set is exactly the accepted run's positive input
position set; the `toFinset` intentionally forgets duplicate positions.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSourceSpendPositionSet

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05CurrentSourceLedgerPrefix
open HegemonCrypto.SmallWood.SmzaRp05CurrentInputSlotUniqueness
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureHistoricalInputs (publicAnchor)
open HegemonCrypto.SmallWood.SmzaRp05SupplyClosureInputNative (inputSlotNative)

set_option autoImplicit false

noncomputable section

theorem source_spend_positions_toFinset_eq_positive_positions
    {preamble : SmzaRp05StatementNamespace.Statement} {typed : V8PublicStatement}
    (snapshot : CurrentNativeSnapshot)
    (run : CurrentSourceRun preamble typed)
    (admitted : publicAnchor (encodePublicStatement typed) ∈ snapshot.parent.history) :
    ((sourceSpendsOfRun snapshot run admitted).map CurrentSourceSpend.position).toFinset =
      positiveDesignatedInputPositions run := by
  classical
  apply Finset.ext
  intro position
  constructor
  · intro member
    rcases List.mem_toFinset.mp member with spendMember
    rcases List.mem_map.mp spendMember with ⟨spend, spendInList, positionEq⟩
    rw [sourceSpendsOfRun] at spendInList
    rcases List.mem_filterMap.mp spendInList with ⟨input, _, produced⟩
    by_cases positive : 0 < inputSlotNative typed (sourcePacked run) input
    · simp only [dif_pos positive, Option.some.injEq] at produced
      cases produced
      apply Finset.mem_image.mpr
      refine ⟨input, ?_, ?_⟩
      · exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, positive⟩
      · simpa only [CurrentSourceSpend.position, designatedInputPosition,
          sourcePacked, designatedInputPacked] using positionEq
    · simp only [dif_neg positive] at produced
      cases produced
  · intro member
    rcases Finset.mem_image.mp member with ⟨input, slotMember, positionEq⟩
    have positive : 0 < inputSlotNative typed (designatedInputPacked run) input :=
      (Finset.mem_filter.mp slotMember).2
    have positiveSource : 0 < inputSlotNative typed (sourcePacked run) input := by
      simpa only [sourcePacked, designatedInputPacked] using positive
    let spend : CurrentSourceSpend :=
      ⟨preamble, typed, run, input,
        positiveSource,
        snapshot, admitted⟩
    have spendInList : spend ∈ sourceSpendsOfRun snapshot run admitted := by
      simp only [sourceSpendsOfRun]
      apply List.mem_filterMap.mpr
      refine ⟨input, by simp, ?_⟩
      simp only [dif_pos positiveSource, spend]
    apply List.mem_toFinset.mpr
    apply List.mem_map.mpr
    refine ⟨spend, spendInList, ?_⟩
    simpa only [spend, CurrentSourceSpend.position, designatedInputPosition,
      sourcePacked, designatedInputPacked] using
      positionEq

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentSourceSpendPositionSet
