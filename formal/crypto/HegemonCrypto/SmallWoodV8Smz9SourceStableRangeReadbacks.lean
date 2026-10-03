import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeDigits
import HegemonCrypto.SmallWoodV8Smz9SourceStableLeafFrames
import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabledCore
import HegemonCrypto.SmallWoodV8Smz9SourceParentMultiplication

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open Hegemon.Transaction
open Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableLeafFrames
open HegemonCrypto.SmallWood.V8Smz9SourceSimpleStableCsr
open HegemonCrypto.SmallWood.V8Smz9SourceParentMultiplication (encoded_parent_height)
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def sourceEvenSpec (index : Fin 46) : StableEvenRange := stableEvenRanges.getD index.val ⟨0,false,0,0,0,0⟩
def sourceOddSpec (index : Fin 20) : StableOddRange := stableOddRanges.getD index.val ⟨0,false,0,0,0,0,0⟩

theorem source_even_spec_properties (index : Fin 46) :
    (sourceEvenSpec index).localIndex<66 ∧
    sourceRangeWidth (sourceEvenSpec index).localIndex=2*(sourceEvenSpec index).digits ∧
    sourceRangeStart (sourceEvenSpec index).localIndex=(sourceEvenSpec index).start ∧
    sourceEvenSpec index ∈ stableEvenRanges := by
  fin_cases index <;> decide

theorem source_odd_spec_properties (index : Fin 20) :
    (sourceOddSpec index).localIndex=7+index.val ∧
    sourceRangeWidth (sourceOddSpec index).localIndex=2*(sourceOddSpec index).digits+1 ∧
    sourceRangeStart (sourceOddSpec index).localIndex=(sourceOddSpec index).start ∧
    (sourceOddSpec index).topLane=33+index.val ∧
    sourceOddSpec index ∈ stableOddRanges := by
  fin_cases index <;> decide

theorem full_candidate_private_at (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 41408 ≤ index) (upper : index<41502) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      stableWitnessWord witness.stablecoin (sourcePrivateIndex (index-41408)) := by
  have readback := full_candidate_stable_private_readback statement witness ⟨index-41408,by omega⟩
  have address : 41408+(index-41408)=index := by omega
  exact (congrArg (fun coordinate => (fullTypedSourceCandidate statement witness).getD coordinate 0) address.symm).trans readback

theorem full_candidate_numeric_at (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) (lower : 42176 ≤ index) (upper : index<42240) :
    (fullTypedSourceCandidate statement witness).getD index 0 =
      (sourceNumericValues (sourceAux statement.stablecoin witness.stablecoin)).getD (index-42176) 0 := by
  have readback := full_candidate_tail_flat_nat_readback statement witness .numeric 0 (by decide) ⟨index-42176,by omega⟩
  have address : (647+TailFamily.numeric.base+0)*64+(index-42176)=index := by
    simp only [TailFamily.base]; omega
  rw [address] at readback
  exact readback

theorem full_candidate_even_source (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 46) :
    stableEvenSource (encodePublicStatement statement) (fullTypedSourceCandidate statement witness) (sourceEvenSpec index) =
      (sourceRangeEntry statement witness (sourceEvenSpec index).localIndex).1 := by
  have magnitude := (encoded_stable_public_scalars statement witness valid).2.2.2
  have minted := encoded_stable_after_counter statement witness valid ⟨1,by decide⟩
  have debt := encoded_stable_after_counter statement witness valid ⟨2,by decide⟩
  fin_cases index <;>
    simp only [sourceEvenSpec,stableEvenRanges,List.range_succ,List.map_append,List.map_cons,List.map_nil,List.cons_append,List.nil_append,
      List.getD_cons_zero,List.getD_cons_succ,stableEvenSource,Bool.false_eq_true,if_false,if_true,packedWord]
  all_goals first
    | (rw [full_candidate_private_at statement witness _ (by decide) (by decide)]; rfl)
    | (rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)];
        simp [sourceNumericValues,sourceRangeEntry,sourceRangeValues,SourceMul3.rangeValues,List.ofFn_succ])
    | (exact magnitude)
    | (exact minted)
    | (exact debt)

theorem full_candidate_odd_source (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 20) :
    stableOddSource (encodePublicStatement statement) (fullTypedSourceCandidate statement witness) (sourceOddSpec index) =
      (sourceRangeEntry statement witness (sourceOddSpec index).localIndex).1 := by
  have height := encoded_parent_height statement witness valid
  have epoch := encoded_stable_after_counter statement witness valid ⟨0,by decide⟩
  have sequence := encoded_stable_after_counter statement witness valid ⟨3,by decide⟩
  fin_cases index <;>
    simp only [sourceOddSpec,stableOddRanges,List.getD_cons_zero,List.getD_cons_succ,
      stableOddSource,Bool.false_eq_true,if_false,if_true,packedWord]
  all_goals first
    | (rw [full_candidate_private_at statement witness _ (by decide) (by decide)]; rfl)
    | (rw [full_candidate_numeric_at statement witness _ (by decide) (by decide)]; rfl)
    | (exact epoch)
    | (exact sequence)
    | (exact height)

end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
