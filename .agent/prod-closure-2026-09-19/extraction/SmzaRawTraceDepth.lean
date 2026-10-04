import SmzaRawStageGeometry

/-! A fixed sufficient extraction budget gives the same committed subtree at
every RP04 challenge stage. No later challenge output or successful-extraction
assumption is needed for this equality. -/
namespace HegemonCrypto.SmallWood.SmzaRawTraceDepth

open V8SmzaOracleParser V8SmzaOnlineParser SmzaRawStageGeometry
open V8Smz9CoherentMerkleGeometry
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

def stageDepth : Stage → Nat
  | .tree depth => depth + 1
  | .root => 25
  | .fpp => 26
  | .piop => 27
  | .decs => 28

theorem stage_depth_positive (stage : Stage) : 0 < stageDepth stage := by
  cases stage <;> simp [stageDepth]

theorem payload_edge_decreases_depth (stage : Stage) (payload : Payload)
    (edges : List (Stage × V8SmzaOracleParser.RawDigest))
    (parsed : payloadNext stage payload = some edges)
    (edge : Stage × V8SmzaOracleParser.RawDigest) (member : edge ∈ edges) :
    stageDepth edge.1 < stageDepth stage := by
  cases stage with
  | tree depth =>
      cases depth with
      | zero =>
          cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
          subst edges
          simp at member
      | succ depth =>
          cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
          subst edges
          simp only [List.mem_cons, List.not_mem_nil, or_false] at member
          rcases member with rfl | rfl <;> simp [stageDepth]
  | root =>
      cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
      subst edges
      rcases List.mem_singleton.mp member with rfl
      norm_num [stageDepth]
  | fpp =>
      cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
      subst edges
      rcases List.mem_singleton.mp member with rfl
      norm_num [stageDepth]
  | piop =>
      cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
      subst edges
      rcases List.mem_singleton.mp member with rfl
      norm_num [stageDepth]
  | decs =>
      cases kind : payload.kind <;> simp [payloadNext, kind] at parsed
      subst edges
      rcases List.mem_singleton.mp member with rfl
      norm_num [stageDepth]

theorem raw_edge_decreases_depth (stage : Stage) (input : V8SmzaOracleParser.RawInput)
    (edges : List (Stage × V8SmzaOracleParser.RawDigest))
    (parsed : rawOnlineNext stage input = some edges)
    (edge : Stage × V8SmzaOracleParser.RawDigest) (member : edge ∈ edges) :
    stageDepth edge.1 < stageDepth stage := by
  cases decoded : rawPayload input with
  | none => simp [rawOnlineNext, decoded] at parsed
  | some payload =>
      exact payload_edge_decreases_depth stage payload edges
        (by simpa [rawOnlineNext, decoded] using parsed) edge member

theorem sufficient_fuel_same_trace
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (leftFuel rightFuel : Nat) (stage : Stage) (target : V8SmzaOracleParser.RawDigest)
    (leftEnough : stageDepth stage ≤ leftFuel)
    (rightEnough : stageDepth stage ≤ rightFuel) :
    extract rawOnlineNext records leftFuel stage target =
      extract rawOnlineNext records rightFuel stage target := by
  induction leftFuel generalizing rightFuel stage target with
  | zero => have positive := stage_depth_positive stage; omega
  | succ leftFuel ih =>
      cases rightFuel with
      | zero => have positive := stage_depth_positive stage; omega
      | succ rightFuel =>
          cases selected : selectedInput rawOnlineNext records stage target with
          | none => simp only [extract, selected]
          | some input =>
              cases parsed : rawOnlineNext stage input with
              | none => simp only [extract, selected, parsed]
              | some edges =>
                  simp only [extract, selected, parsed]
                  apply congrArg (ExtractionTrace.record input)
                  apply List.map_congr_left
                  intro edge member
                  have decreases := raw_edge_decreases_depth stage input edges parsed edge member
                  exact ih rightFuel edge.1 edge.2 (by omega) (by omega)

end
end HegemonCrypto.SmallWood.SmzaRawTraceDepth
