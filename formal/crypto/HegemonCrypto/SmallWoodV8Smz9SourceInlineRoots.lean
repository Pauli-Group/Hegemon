import HegemonCrypto.SmallWoodV8Smz9InputMerkleEquations
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate

/-! Forward satisfaction of actual root-list positions 121 through 128.
The seven orientation roots and policy bridge use the same source cells;
no packed acceptance, validity or desired equality is an input premise. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceInlineRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (actual_node_field_equation)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)
open HegemonCrypto.SmallWood.V8Smz9InputMerkleEquations (orientation_nodes orientation_row_nodes)
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem actual_inline_root_indices :
    (∀ group : Fin 7, exactNonlinearRoots[121 + group.val]? = some (1207 + 4 * group.val)) ∧
    exactNonlinearRoots[128]? = some 1233 := by decide

noncomputable section

theorem actual_orientation_formula (pub rows : Nat → F) (group : Fin 7) :
    fieldAt exactNonlinearExpressions pub rows (1207 + 4 * group.val) =
      rows (252 + 4 * group.val) -
        (rows (253 + 4 * group.val) + rows (255 + 4 * group.val) *
          (rows (254 + 4 * group.val) - rows (253 + 4 * group.val))) := by
  obtain ⟨differenceNode,productNode,sumNode,rootNode,_⟩ := orientation_nodes group
  have row (component : Fin 4) :=
    actual_node_field_equation pub rows (orientation_row_nodes group component)
  have current := row ⟨0,by decide⟩
  have left := row ⟨1,by decide⟩
  have right := row ⟨2,by decide⟩
  have direction := row ⟨3,by decide⟩
  have difference := actual_node_field_equation pub rows differenceNode
  have product := actual_node_field_equation pub rows productNode
  have sum := actual_node_field_equation pub rows sumNode
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField, Nat.add_zero] at current left right direction difference product sum root
  have leftIndex : 376 + 4 * group.val + 1 = 377 + 4 * group.val := by omega
  have rightIndex : 376 + 4 * group.val + 2 = 378 + 4 * group.val := by omega
  have directionIndex : 376 + 4 * group.val + 3 = 379 + 4 * group.val := by omega
  rw [leftIndex] at left
  rw [rightIndex] at right
  rw [directionIndex] at direction
  rw [sum,product,difference,current,left,right,direction] at root
  simpa only [show 252 + 4 * group.val + 1 = 253 + 4 * group.val by omega,
    show 252 + 4 * group.val + 2 = 254 + 4 * group.val by omega,
    show 252 + 4 * group.val + 3 = 255 + 4 * group.val by omega] using root

theorem actual_policy_bridge_formula (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows 1233 = rows 282 * (rows 280 - rows 281) := by
  have left := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[404]? = some (.witnessRow 280) by decide)
  have right := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[405]? = some (.witnessRow 281) by decide)
  have gate := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[406]? = some (.witnessRow 282) by decide)
  have difference := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1232]? = some (.sub 404 405) by decide)
  have root := actual_node_field_equation pub rows
    (show exactNonlinearExpressions[1233]? = some (.mul 406 1232) by decide)
  simp only [expressionField] at left right gate difference root
  rw [gate,difference,left,right] at root
  exact root

theorem constructed_inline_lane_readback (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (row : Fin 31) (lane : Fin 64) :
    laneField (constructedAssignment statement witness live tail) lane.val (252 + row.val) =
      (inlineCell live witness row.val lane.val : F) := by
  have bound : 252 + row.val < 686 := by omega
  have address : (252 + row.val) * 64 + lane.val = 16128 + (row.val * 64 + lane.val) := by omega
  simp only [laneField,packedWitnessLaneRows,relationRowCount,packingFactor,
    List.getD_eq_getElem?_getD,List.getElem?_map,List.getElem?_range,bound,
    Option.map_some,Option.getD_some]
  change ((constructedAssignment statement witness live tail).getD
    ((252 + row.val) * 64 + lane.val) 0 : F) = _
  rw [constructed_as_inline_placement,address,
    placed_inline_cell _ _ live witness (before_inline_length statement witness live)
      row.val lane.val row.isLt lane.isLt]

theorem source_orientation_equation (live : LiveInitialStates) (witness : V8Witness)
    (input level limb : Nat) :
    (orientedWord live witness input level limb 0 : F) =
      (orientedWord live witness input level limb 1 : F) +
      (orientedWord live witness input level limb 3 : F) *
        ((orientedWord live witness input level limb 2 : F) -
          (orientedWord live witness input level limb 1 : F)) := by
  rcases direction_boolean witness input level with zero | one
  · simp [orientedWord,zero]
  · simp [orientedWord,one]

theorem inline_group_cell (live : LiveInitialStates) (witness : V8Witness)
    (group : Fin 7) (lane : Fin 64) (component : Fin 4) :
    inlineCell live witness (4 * group.val + component.val) lane.val =
      orientedWord live witness ((group.val * 64 + lane.val) / 224)
        (((group.val * 64 + lane.val) % 224) / 7)
        ((group.val * 64 + lane.val) % 7) component.val := by
  have bound : 4 * group.val + component.val < 28 := by omega
  have quotient : (4 * group.val + component.val) / 4 = group.val := by omega
  have remainder : (4 * group.val + component.val) % 4 = component.val := by omega
  simp only [inlineCell,if_pos bound,quotient,remainder]

theorem constructed_orientation_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F)
    (group : Fin 7) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions pub
      (laneField (constructedAssignment statement witness live tail) lane.val)
      (1207 + 4 * group.val) = 0 := by
  rw [actual_orientation_formula]
  have row (component : Fin 4) := constructed_inline_lane_readback statement witness live tail
    ⟨4 * group.val + component.val,by omega⟩ lane
  have h0 := row ⟨0,by decide⟩
  have h1 := row ⟨1,by decide⟩
  have h2 := row ⟨2,by decide⟩
  have h3 := row ⟨3,by decide⟩
  simp only [Nat.add_zero] at h0
  have a1 : 252 + (4 * group.val + 1) = 253 + 4 * group.val := by omega
  have a2 : 252 + (4 * group.val + 2) = 254 + 4 * group.val := by omega
  have a3 : 252 + (4 * group.val + 3) = 255 + 4 * group.val := by omega
  rw [a1] at h1
  rw [a2] at h2
  rw [a3] at h3
  rw [h0,h1,h2,h3]
  have cell (component : Fin 4) := inline_group_cell live witness group lane component
  have equation := source_orientation_equation live witness
    ((group.val * 64 + lane.val) / 224)
    (((group.val * 64 + lane.val) % 224) / 7) ((group.val * 64 + lane.val) % 7)
  have c0 := cell ⟨0,by decide⟩
  simp only [Nat.add_zero] at c0
  rw [c0,cell ⟨1,by decide⟩,cell ⟨2,by decide⟩,cell ⟨3,by decide⟩]
  exact sub_eq_zero.mpr equation

theorem constructed_policy_bridge_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (live : LiveInitialStates) (tail : List Nat) (pub : Nat → F) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions pub
      (laneField (constructedAssignment statement witness live tail) lane.val) 1233 = 0 := by
  rw [actual_policy_bridge_formula]
  have h30 := constructed_inline_lane_readback statement witness live tail ⟨30,by decide⟩ lane
  have h28 := constructed_inline_lane_readback statement witness live tail ⟨28,by decide⟩ lane
  have h29 := constructed_inline_lane_readback statement witness live tail ⟨29,by decide⟩ lane
  change laneField (constructedAssignment statement witness live tail) lane.val 282 =
    (inlineCell live witness 30 lane.val : F) at h30
  change laneField (constructedAssignment statement witness live tail) lane.val 280 =
    (inlineCell live witness 28 lane.val : F) at h28
  change laneField (constructedAssignment statement witness live tail) lane.val 281 =
    (inlineCell live witness 29 lane.val : F) at h29
  rw [h30,h28,h29]
  by_cases rate : lane.val < 7
  · by_cases single : witness.authorization.mode = .singleKey
    · simp [inlineCell,rate,policyWord,nonSingle,single]
    · simp [inlineCell,rate,policyWord,nonSingle,single]
  · simp [inlineCell,rate]

theorem full_candidate_actual_eight_inline_roots_zero
    (statement : V8PublicStatement) (witness : V8Witness) (pub : Nat → F)
    (lane : Fin 64) (offset : Fin 8) :
    (exactNonlinearRoots[121 + offset.val]?).map
      (fieldAt exactNonlinearExpressions pub
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  by_cases group : offset.val < 7
  · rw [actual_inline_root_indices.1 ⟨offset.val,group⟩,Option.map_some]
    exact congrArg some (constructed_orientation_root_zero statement witness
      (typedLiveInitialStates statement witness) (typedSourceTail statement witness) pub
      ⟨offset.val,group⟩ lane)
  · have last : offset.val = 7 := by omega
    rw [last,show 121 + 7 = 128 from rfl,actual_inline_root_indices.2,Option.map_some]
    exact congrArg some (constructed_policy_bridge_root_zero statement witness
      (typedLiveInitialStates statement witness) (typedSourceTail statement witness) pub lane)

end











end HegemonCrypto.SmallWood.V8Smz9SourceInlineRoots
