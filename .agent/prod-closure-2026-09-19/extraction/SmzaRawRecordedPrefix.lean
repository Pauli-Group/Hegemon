import SmzaRawTraceDepth
import SmzaRecordedTracePath

/-! Recorded RP04 wrapper prefixes recover the same complete subtree at every
challenge stage. This removes dependence on the different remaining recursion
budgets of the root, FPP, PIOP and DECS traversals. -/
namespace HegemonCrypto.SmallWood.SmzaRawRecordedPrefix

open V8SmzaOracleParser V8SmzaOnlineParser SmzaRawStageGeometry
open V8Smz9CoherentMerkleGeometry SmzaRawTraceDepth SmzaRecordedTracePath
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev Digest := V8SmzaOracleParser.RawDigest
abbrev Trace := ExtractionTrace RawInput

def subtree : List Nat → Trace → Trace
  | [], trace => trace
  | index :: rest, .record _ children =>
      subtree rest (children[index]?.getD .missing)
  | _ :: _, _ => .missing

theorem recorded_child_is_complete_subtree
    (records : Records RawInput Digest) (collisionFree : RecordsCollisionFree records)
    (fuel : Nat) (stage : Stage) (target : Digest) (input : RawInput)
    (edges : List (Stage × Digest)) (index : Nat) (childStage : Stage) (childTarget : Digest)
    (recorded : (input, target) ∈ records)
    (parsed : rawOnlineNext stage input = some edges)
    (edge : edges[index]? = some (childStage, childTarget))
    (enough : stageDepth stage ≤ fuel) :
    subtree [index] (extract rawOnlineNext records fuel stage target) =
      extract rawOnlineNext records fuel childStage childTarget := by
  have member : (childStage, childTarget) ∈ edges := List.mem_of_getElem? edge
  have decreases := raw_edge_decreases_depth stage input edges parsed
    (childStage, childTarget) member
  change stageDepth childStage < stageDepth stage at decreases
  have selected := selected_input_of_recorded rawOnlineNext records collisionFree
    stage target input recorded (by simp only [parsed, Option.isSome_some])
  cases fuel with
  | zero => have positive := stage_depth_positive stage; omega
  | succ fuel =>
      simp only [extract, selected, parsed, subtree, List.getElem?_map,
        edge, Option.map_some, Option.getD_some]
      exact sufficient_fuel_same_trace records fuel (fuel + 1) childStage childTarget
        (by omega) (by omega)

/-- Every step records the exact parsed edge and its parent hash input. No
successful-extraction premise is built into this chronological path. -/
inductive RecordedStages (records : Records RawInput Digest) :
    Stage → Digest → List Nat → Stage → Digest → Prop where
  | here (stage target) : RecordedStages records stage target [] stage target
  | step (stage target input edges index childStage childTarget rest finalStage finalTarget)
      (recorded : (input, target) ∈ records)
      (parsed : rawOnlineNext stage input = some edges)
      (edge : edges[index]? = some (childStage, childTarget))
      (below : RecordedStages records childStage childTarget rest finalStage finalTarget) :
      RecordedStages records stage target (index :: rest) finalStage finalTarget

theorem subtree_cons (index : Nat) (rest : List Nat) (trace : Trace) :
    subtree (index :: rest) trace = subtree rest (subtree [index] trace) := by
  cases trace <;> cases rest <;> rfl

theorem recorded_prefix_is_complete_subtree
    (records : Records RawInput Digest) (collisionFree : RecordsCollisionFree records)
    (stage : Stage) (target : Digest) (path : List Nat) (finalStage : Stage) (finalTarget : Digest)
    (recorded : RecordedStages records stage target path finalStage finalTarget)
    (fuel : Nat) (enough : stageDepth stage ≤ fuel) :
    subtree path (extract rawOnlineNext records fuel stage target) =
      extract rawOnlineNext records fuel finalStage finalTarget := by
  induction recorded with
  | here stage target => rfl
  | step stage target input edges index childStage childTarget rest finalStage finalTarget
      recorded parsed edge below ih =>
      have member : (childStage, childTarget) ∈ edges := List.mem_of_getElem? edge
      have decreases := raw_edge_decreases_depth stage input edges parsed
        (childStage, childTarget) member
      change stageDepth childStage < stageDepth stage at decreases
      rw [subtree_cons, recorded_child_is_complete_subtree records collisionFree fuel
        stage target input edges index childStage childTarget recorded parsed edge enough]
      exact ih (by omega)

end
end HegemonCrypto.SmallWood.SmzaRawRecordedPrefix
