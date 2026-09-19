import SmzaChallengeStageTargets

/-! Context-free online geometry for the repaired transcript. Online traversal
retains full raw wrapper payloads and does not receive an expected relation,
statement, or binding preamble. Semantic/canonical validation belongs to the
accepted-transcript readback. This deliberately does not reuse the RP03-only
Context.Canonical predicate as if it accepted RP04. Permitting extra raw
payloads does not increase the two-child geometry bound. -/
namespace HegemonCrypto.SmallWood.SmzaRawStageGeometry

open V8SmzaOracleParser V8SmzaOnlineParser SmzaChallengeStageTargets
open V8Smz9CoherentMerkleGeometry
noncomputable section
set_option autoImplicit false

def rawOnlineNext (stage : Stage) (input : V8SmzaOracleParser.RawInput) :
    Option (List (Stage × V8SmzaOracleParser.RawDigest)) := do
  let payload ← rawPayload input
  payloadNext stage payload

theorem raw_online_next_child (stage : Stage) (input : V8SmzaOracleParser.RawInput)
    (edges : List (Stage × V8SmzaOracleParser.RawDigest))
    (decoded : rawOnlineNext stage input = some edges)
    (edge : Stage × V8SmzaOracleParser.RawDigest) (member : edge ∈ edges) :
    edge.2 ∈ rawChildren input := by
  cases parsed : rawPayload input with
  | none => simp [rawOnlineNext, parsed] at decoded
  | some payload =>
      have decoded' : payloadNext stage payload = some edges := by
        simpa [rawOnlineNext, parsed] using decoded
      simpa [rawChildren, parsed] using
        payload_next_child stage payload edges decoded' edge member

theorem selected_stage_probability_bound
    (role : Role)
    (records : V8Smz9CoherentMerkleGeometry.Records
      V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (input : V8SmzaOracleParser.RawInput)
    (queries : List V8SmzaOracleParser.RawInput) (fuel cap : Nat)
    (recordBound : records.card < cap) (queryBound : queries.length ≤ cap) :
    uniformChangeProbability rawOnlineNext records input fuel (selectedTargets role queries) ≤
      (3*cap : Rat)/(2^512 : Rat) :=
  selected_stage_change_probability_le rawOnlineNext raw_online_next_child
    role records input queries fuel cap recordBound queryBound

end
end HegemonCrypto.SmallWood.SmzaRawStageGeometry
