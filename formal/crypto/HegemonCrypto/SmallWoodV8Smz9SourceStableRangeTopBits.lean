import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeDigits

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeTopBits
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_odd_top_boolean_readback (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 20) :
    (sourceBooleanValues statement.stablecoin witness.stablecoin
      (sourceAux statement.stablecoin witness.stablecoin)).getD (33+slot.val) 0 =
      sourceBit (sourceRangeEntry statement witness (7+slot.val)).1
        ((sourceRangeEntry statement witness (7+slot.val)).2-1) := by
  fin_cases slot <;> simp [sourceBooleanValues,sourceRangeValues,sourceRangeEntry,
    SourceMul3.rangeValues,List.ofFn_succ]

theorem full_candidate_odd_top_boolean_readback (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 20) :
    (fullTypedSourceCandidate statement witness).getD (42145+slot.val) 0 =
      sourceBit (sourceRangeEntry statement witness (7+slot.val)).1
        ((sourceRangeEntry statement witness (7+slot.val)).2-1) := by
  have flat := full_candidate_tail_flat_nat_readback statement witness
    .booleans 0 (by decide) ⟨33+slot.val,by omega⟩
  have address : (647+TailFamily.booleans.base+0)*64+(33+slot.val)=42145+slot.val := by
    simp only [TailFamily.base]; omega
  rw [address] at flat
  exact flat.trans (source_odd_top_boolean_readback statement witness slot)

end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeTopBits
