import HegemonCrypto.SmallWoodV8Smz9CoherentMerkleGeometry
import HegemonCrypto.FiniteOracleDatabase

/-! Collision-free recorded paths are read back by the actual least-preimage
VC extractor. This connects authenticated path evidence to extraction traces;
it does not assume successful extraction or global hash injectivity. -/
namespace HegemonCrypto.SmallWood.SmzaRecordedTracePath

open V8Smz9CoherentMerkleGeometry HegemonCrypto.FiniteOracleDatabase
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Input Output Stage : Type*} [LinearOrder Input] [DecidableEq Output]

def RecordsCollisionFree (records : Records Input Output) : Prop :=
  ∀ input other output, (input, output) ∈ records →
    (other, output) ∈ records → input = other

theorem selected_input_of_recorded
    (next : Stage → Input → Option (List (Stage × Output)))
    (records : Records Input Output) (collisionFree : RecordsCollisionFree records)
    (stage : Stage) (target : Output) (input : Input)
    (recorded : (input, target) ∈ records) (valid : (next stage input).isSome) :
    selectedInput next records stage target = some input := by
  have member : input ∈ candidateInputs next records stage target := by
    apply Finset.mem_image.mpr
    exact ⟨(input, target), Finset.mem_filter.mpr ⟨recorded, rfl, valid⟩, rfl⟩
  have present : (candidateInputs next records stage target).Nonempty := ⟨input, member⟩
  let chosen := (candidateInputs next records stage target).min' present
  have selected : selectedInput next records stage target = some chosen := by
    simp only [selectedInput, dif_pos present, chosen]
  have chosenRecorded := selected_input_recorded next records stage target chosen selected
  have same := collisionFree chosen input target chosenRecorded recorded
  exact selected.trans (congrArg some same)

def readPath : List Nat → ExtractionTrace Input → Option Input
  | [], .record input _ => some input
  | index :: rest, .record _ children =>
      (children[index]?).bind (readPath rest)
  | _, _ => none

inductive RecordedPath
    (next : Stage → Input → Option (List (Stage × Output)))
    (records : Records Input Output) : Stage → Output → List Nat → Input → Prop where
  | here (stage target input)
      (recorded : (input, target) ∈ records)
      (valid : (next stage input).isSome) :
      RecordedPath next records stage target [] input
  | step (stage target input edges index childStage childTarget rest leaf)
      (recorded : (input, target) ∈ records)
      (parsed : next stage input = some edges)
      (edge : edges[index]? = some (childStage, childTarget))
      (below : RecordedPath next records childStage childTarget rest leaf) :
      RecordedPath next records stage target (index :: rest) leaf

/-- Every recorded path shorter than the explicit recursion budget is
recovered, including its final complete raw input. -/
theorem recorded_path_readback
    (next : Stage → Input → Option (List (Stage × Output)))
    (records : Records Input Output) (collisionFree : RecordsCollisionFree records)
    (stage : Stage) (target : Output) (path : List Nat) (input : Input)
    (recorded : RecordedPath next records stage target path input)
    (fuel : Nat) (enough : path.length < fuel) :
    readPath path (extract next records fuel stage target) = some input := by
  induction recorded generalizing fuel with
  | here stage target input recorded valid =>
      cases fuel with
      | zero => simp at enough
      | succ fuel =>
          have selected := selected_input_of_recorded next records collisionFree
            stage target input recorded valid
          obtain ⟨edges, parsed⟩ := Option.isSome_iff_exists.mp valid
          simp only [extract, selected, parsed, readPath]
  | step stage target input edges index childStage childTarget rest leaf recorded parsed edge below ih =>
      cases fuel with
      | zero => simp at enough
      | succ fuel =>
          have selected := selected_input_of_recorded next records collisionFree
            stage target input recorded (by simp only [parsed, Option.isSome_some])
          have remaining : rest.length < fuel := by simpa using enough
          simpa only [extract, selected, parsed, readPath, List.getElem?_map,
            edge, Option.map_some, Option.bind_some] using ih fuel remaining

/-- The structural collision predicate is a consequence of the actual
recorded database collision event, not a separate cryptographic assumption. -/
theorem records_collision_free_of_database
    (records : Records Input Output) (database : Database Input Output)
    (collisionFree : CollisionFree database)
    (recorded : ∀ input output, (input, output) ∈ records → database input = some output) :
    RecordsCollisionFree records := by
  intro input other output left right
  exact input_unique_of_same_recorded_output collisionFree
    (recorded input output left) (recorded other output right)

end
end HegemonCrypto.SmallWood.SmzaRecordedTracePath
