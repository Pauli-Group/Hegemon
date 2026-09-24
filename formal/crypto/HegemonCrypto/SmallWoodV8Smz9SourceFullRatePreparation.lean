import HegemonCrypto.SmallWoodV8Smz9TypedScheduleInventory
import HegemonCrypto.SmallWoodV8Smz9FullRateSponge

/-! Direct pre-permutation frame equality. No cancellation of a permutation
and no accepted-trace or evaluator-equation premise is used. -/
namespace HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9FullRateSponge
set_option Elab.async false
set_option maxHeartbeats 1000000
set_option maxRecDepth 10000

private theorem exact_sixteen_words (state : List Nat) (shape : state.length = 16) :
    state = [state.getD 0 0, state.getD 1 0, state.getD 2 0, state.getD 3 0,
      state.getD 4 0, state.getD 5 0, state.getD 6 0, state.getD 7 0,
      state.getD 8 0, state.getD 9 0, state.getD 10 0, state.getD 11 0,
      state.getD 12 0, state.getD 13 0, state.getD 14 0, state.getD 15 0] := by
  exact (range_getD state 16 shape).symm

/-- Concrete list algebra before the primitive is called. -/
theorem source_full_rate_preparation (domain : Nat) (inputs state : List Nat)
    (blocks block : Nat) (inputShape : inputs.length = 8*blocks)
    (blockBound : block<blocks) (stateShape : state.length=16) :
    spongePreparedWords domain inputs blocks state block =
      fullRateFrame domain inputs blocks state block := by
  have h0 : block*8<inputs.length := by omega
  have h1 : block*8+1<inputs.length := by omega
  have h2 : block*8+2<inputs.length := by omega
  have h3 : block*8+3<inputs.length := by omega
  have h4 : block*8+4<inputs.length := by omega
  have h5 : block*8+5<inputs.length := by omega
  have h6 : block*8+6<inputs.length := by omega
  have h7 : block*8+7<inputs.length := by omega
  conv => lhs; rw [exact_sixteen_words state stateShape]
  by_cases first : block=0
  · subst block
    simp only [Nat.zero_mul, Nat.zero_add] at h0 h1 h2 h3 h4 h5 h6 h7
    by_cases last : 1=blocks
    · subst blocks
      simp [spongePreparedWords, poseidon2V8SeedFirstBlock,
        Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate, fullRateFrame, List.range_succ,
        List.getD, h0, h1, h2, h3, h4, h5, h6, h7]
    · simp [spongePreparedWords, poseidon2V8SeedFirstBlock,
        Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate, fullRateFrame, last, List.range_succ,
        List.getD, h0, h1, h2, h3, h4, h5, h6, h7]
  · by_cases last : block+1=blocks <;>
      simp [spongePreparedWords, Poseidon2Width16Kernel.rate, fullRateFrame,
        first, last, List.range_succ, List.getD, h0, h1, h2, h3, h4, h5, h6, h7]

theorem full_rate_frame_word (domain : Nat) (inputs state : List Nat)
    (blocks block : Nat) (lane : Fin 16) :
    (fullRateFrame domain inputs blocks state block).getD lane.val 0 =
      let previous := state.getD lane.val 0
      let seeded := if block=0 then
        if lane.val=8 then domain else if lane.val=9 then inputs.length
        else if lane.val=10 then poseidon2V8SpongeModeMarker
        else if lane.val=15 then poseidon2V8SuiteMarker else previous
        else previous
      let absorbed := if lane.val<8 then
        Poseidon2Width16Kernel.fieldAdd previous (inputs.getD (block*8+lane.val) 0)
        else seeded
      if block+1=blocks ∧ lane.val=11 then Poseidon2Width16Kernel.fieldAdd absorbed 1
      else absorbed := by
  simp only [fullRateFrame, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range, lane.isLt, Option.map_some, Option.getD_some]



end HegemonCrypto.SmallWood.V8Smz9SourcePolicyInitial
