import HegemonCrypto.SmallWoodV8Smz9SourceEarlyPublicBooleans

namespace HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField laneField_eq_packedWord)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem full_candidate_raw_word_readback (statement : V8PublicStatement) (witness : V8Witness)
    (row : Fin 92) (lane : Fin 64) :
    (fullTypedSourceCandidate statement witness).getD (row.val * 64 + lane.val) 0 =
      sourceWord statement witness row.val := by
  have leading := constructed_first92_unchanged statement witness (typedLiveInitialStates statement witness)
    (typedSourceTail statement witness) (⟨row.val * 64 + lane.val,by omega⟩ : Fin 5888)
  change (fullTypedSourceCandidate statement witness).getD (row.val * 64 + lane.val) 0 =
    (packedPrefix statement witness).getD (row.val * 64 + lane.val) 0 at leading
  rw [leading]
  have source := placed_source_word statement witness [] row.val lane.val row.isLt lane.isLt
  simpa only [placePrefix,List.append_nil,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,Nat.zero_add] using source

def pathRootIndex (input bit : Nat) : Nat := if input = 0 then 31 + bit else 64 + bit
def pathSourceRow (input bit : Nat) : Nat := 34 * input + 2 + bit
def pathMinusNode (input bit : Nat) : Nat := if input = 0 then 840 + 2 * bit else 917 + 2 * bit
def pathRootNode (input bit : Nat) : Nat := if input = 0 then 841 + 2 * bit else 918 + 2 * bit

/-- Exact nodes/list indices are used, not the inaccurate contiguous family labels. -/
theorem exact_path_root_nodes (input : Fin 2) (bit : Fin 32) :
    exactNonlinearExpressions[124 + pathSourceRow input.val bit.val]? =
      some (.witnessRow (pathSourceRow input.val bit.val)) ∧
    exactNonlinearExpressions[pathMinusNode input.val bit.val]? =
      some (.sub (124 + pathSourceRow input.val bit.val) 1) ∧
    exactNonlinearExpressions[pathRootNode input.val bit.val]? =
      some (.mul (124 + pathSourceRow input.val bit.val) (pathMinusNode input.val bit.val)) ∧
    exactNonlinearRoots[pathRootIndex input.val bit.val]? = some (pathRootNode input.val bit.val) := by
  fin_cases input
  · have member : (⟨2 + bit.val,840 + 2 * bit.val,841 + 2 * bit.val⟩ : BooleanWitnessRoot) ∈
        exactBooleanWitnessRoots := by
      simp only [exactBooleanWitnessRoots,List.mem_append]
      exact Or.inl (Or.inl (List.mem_map.mpr ⟨bit.val,List.mem_range.mpr bit.isLt,rfl⟩))
    obtain ⟨_,source,minus,root,_⟩ := exact_boolean_witness_roots_valid _ member
    have roots : ∀ b : Fin 32, exactNonlinearRoots[31 + b.val]? = some (841 + 2 * b.val) := by decide
    simpa [pathSourceRow,pathMinusNode,pathRootNode,pathRootIndex] using
      And.intro source (And.intro minus (And.intro root (roots bit)))
  · have member : (⟨36 + bit.val,917 + 2 * bit.val,918 + 2 * bit.val⟩ : BooleanWitnessRoot) ∈
        exactBooleanWitnessRoots := by
      simp only [exactBooleanWitnessRoots,List.mem_append]
      exact Or.inl (Or.inr (List.mem_map.mpr ⟨bit.val,List.mem_range.mpr bit.isLt,rfl⟩))
    obtain ⟨_,source,minus,root,_⟩ := exact_boolean_witness_roots_valid _ member
    have roots : ∀ b : Fin 32, exactNonlinearRoots[64 + b.val]? = some (918 + 2 * b.val) := by decide
    simpa [pathSourceRow,pathMinusNode,pathRootNode,pathRootIndex] using
      And.intro source (And.intro minus (And.intro root (roots bit)))

noncomputable section

theorem full_candidate_raw_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (row : Fin 92) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val row.val =
      (sourceWord statement witness row.val : F) := by
  rw [laneField_eq_packedWord _ _ _ (by omega : row.val < 686)]
  exact congrArg (fun n : Nat => (n : F)) (full_candidate_raw_word_readback statement witness row lane)

theorem actual_path_root_formula (pub rows : Nat → F) (input : Fin 2) (bit : Fin 32) :
    fieldAt exactNonlinearExpressions pub rows (pathRootNode input.val bit.val) =
      rows (pathSourceRow input.val bit.val) * (rows (pathSourceRow input.val bit.val) - 1) := by
  obtain ⟨sourceNode,minusNode,rootNode,_⟩ := exact_path_root_nodes input bit
  have source := actual_node_field_equation pub rows sourceNode
  have one := (actual_source_constants pub rows).2.1
  have minus := actual_node_field_equation pub rows minusNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField] at source minus root
  rw [source,one] at minus
  rw [source,minus] at root
  exact root

theorem full_candidate_path_source_readback (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (bit : Fin 32) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (pathSourceRow input.val bit.val) =
      (positionBit (witness.inputs.getD input.val default).position bit.val : F) := by
  rw [full_candidate_raw_field_readback statement witness
    (⟨pathSourceRow input.val bit.val,by unfold pathSourceRow; omega⟩ : Fin 92) lane]
  change (sourceWord statement witness (pathSourceRow input.val bit.val) : F) = _
  have source := source_input_word statement witness input.val (2 + bit.val) input.isLt (by omega)
  have address : pathSourceRow input.val bit.val = 34 * input.val + (2 + bit.val) := by
    unfold pathSourceRow
    omega
  rw [address,source]
  simp only [inputWord,if_neg (by omega : ¬2 + bit.val = 0),
    if_neg (by omega : ¬2 + bit.val = 1),Nat.add_sub_cancel_left]

/-- All 64 actual path roots, in all physical lanes; modulo-two construction is unconditional. -/
theorem full_candidate_all_path_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (pub : Nat → F) (lane : Fin 64) (input : Fin 2) (bit : Fin 32) :
    (exactNonlinearRoots[pathRootIndex input.val bit.val]?).map
      (fieldAt exactNonlinearExpressions pub
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  rw [(exact_path_root_nodes input bit).2.2.2,Option.map_some,actual_path_root_formula,
    full_candidate_path_source_readback]
  exact congrArg some (boolean_field_zero _ (position_bit_boolean _ _))

theorem path_boolean_two_negative_control (pub : Nat → F) :
    fieldAt exactNonlinearExpressions pub (fun _ => 2) 841 = 2 := by
  have formula := actual_path_root_formula pub (fun _ => 2)
    (⟨0,by decide⟩ : Fin 2) (⟨0,by decide⟩ : Fin 32)
  norm_num [pathRootNode] at formula ⊢
  exact formula









end
end HegemonCrypto.SmallWood.V8Smz9SourceEarlyRoots
