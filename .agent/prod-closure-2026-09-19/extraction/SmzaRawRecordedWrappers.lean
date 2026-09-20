import SmzaRp04TracePrefixes
import SmzaRawRecordedPrefix

/-! Exact recorded wrapper-chain and payload readback, independent of the
heavy chronological label postprocessing. -/
namespace HegemonCrypto.SmallWood.SmzaRp04TracePrefixReadback

open SmzaRp04TracePrefixes SmzaRp04CompleteRawRoleCells
open SmzaRawStageGeometry SmzaRawTraceDepth SmzaRawRecordedPrefix
open SmzaRecordedTracePath V8Smz9CoherentMerkleGeometry
open V8SmzaOnlineParser
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option linter.unusedSimpArgs false
attribute [local irreducible] matrixPrefix openingPrefix rootOracle sourceResponse

theorem child_eq_subtree (trace : SmzaRp04TracePrefixes.Trace) (index : Nat) :
    child trace index = subtree [index] trace := by
  cases trace <;> rfl

/-- A recorded wrapper is recovered with its literal input bytes and the
complete child trace, not merely a postulated equality of role labels. -/
theorem recorded_single_child_trace
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (stage childStage : V8SmzaOracleParser.Stage)
    (target childTarget : V8SmzaOracleParser.RawDigest)
    (input : V8SmzaOracleParser.RawInput)
    (recorded : (input, target) ∈ records)
    (parsed : rawOnlineNext stage input = some [(childStage, childTarget)])
    (fuel : Nat) (enough : stageDepth stage ≤ fuel) :
    extract rawOnlineNext records fuel stage target =
      .record input [extract rawOnlineNext records fuel childStage childTarget] := by
  have selected := selected_input_of_recorded rawOnlineNext records collisionFree
    stage target input recorded (by simp only [parsed, Option.isSome_some])
  have decreases := raw_edge_decreases_depth stage input [(childStage, childTarget)]
    parsed (childStage, childTarget) (by simp)
  change stageDepth childStage < stageDepth stage at decreases
  cases fuel with
  | zero => have positive := stage_depth_positive stage; omega
  | succ fuel =>
      simp only [extract, selected, parsed, List.map_cons, List.map_nil]
      rw [sufficient_fuel_same_trace records fuel (fuel + 1) childStage childTarget
        (by omega) (by omega)]
      rfl

/-- The final recorded DECS wrapper recovers all three literal transcript
messages and the same complete root used by the earlier challenge roles. -/
theorem recorded_decs_piop_fpp_trace
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (decsTarget piopTarget fppTarget rootTarget : V8SmzaOracleParser.RawDigest)
    (decsInput piopInput fppInput : V8SmzaOracleParser.RawInput)
    (decsRecorded : (decsInput, decsTarget) ∈ records)
    (piopRecorded : (piopInput, piopTarget) ∈ records)
    (fppRecorded : (fppInput, fppTarget) ∈ records)
    (decsNext : rawOnlineNext .decs decsInput = some [(.piop, piopTarget)])
    (piopNext : rawOnlineNext .piop piopInput = some [(.fpp, fppTarget)])
    (fppNext : rawOnlineNext .fpp fppInput = some [(.root, rootTarget)])
    (fuel : Nat) (enough : 28 ≤ fuel) :
    extract rawOnlineNext records fuel .decs decsTarget =
      .record decsInput [.record piopInput [.record fppInput
        [extract rawOnlineNext records fuel .root rootTarget]]] := by
  rw [recorded_single_child_trace records collisionFree .decs .piop decsTarget
    piopTarget decsInput decsRecorded decsNext fuel enough]
  rw [recorded_single_child_trace records collisionFree .piop .fpp piopTarget
    fppTarget piopInput piopRecorded piopNext fuel (by change 27 ≤ fuel; omega)]
  rw [recorded_single_child_trace records collisionFree .fpp .root fppTarget
    rootTarget fppInput fppRecorded fppNext fuel (by change 26 ≤ fuel; omega)]

theorem payload_of_recorded_input
    (records : Records V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
    (stage : V8SmzaOracleParser.Stage) (target : V8SmzaOracleParser.RawDigest)
    (input : V8SmzaOracleParser.RawInput) (decoded : V8SmzaOracleParser.Payload)
    (recorded : (input, target) ∈ records)
    (parsed : V8SmzaOracleParser.rawPayload input = some decoded)
    (valid : (V8SmzaOnlineParser.payloadNext stage decoded).isSome)
    (fuel : Nat) (enough : 0 < fuel) :
    payload decoded.kind (extract rawOnlineNext records fuel stage target) = some decoded := by
  have rawValid : (rawOnlineNext stage input).isSome := by
    simpa [rawOnlineNext, parsed] using valid
  have selected := selected_input_of_recorded rawOnlineNext records collisionFree
    stage target input recorded rawValid
  obtain ⟨edges, next⟩ := Option.isSome_iff_exists.mp rawValid
  cases fuel with
  | zero => omega
  | succ fuel => simp [extract, selected, next, payload, parsed]


end
end HegemonCrypto.SmallWood.SmzaRp04TracePrefixReadback

