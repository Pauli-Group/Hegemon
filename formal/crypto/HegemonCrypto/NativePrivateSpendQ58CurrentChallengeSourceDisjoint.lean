import HegemonCrypto.NativePrivateSpendQ58CurrentConstructorGrouping
import HegemonCrypto.NativePrivateSpendQ58CurrentFullStageEnvelope

/-! Finite disjointness of the literal current challenge constructor and
current source-preimage grammar. No namespace relabeling or coverage premise.
This concerns source grammar; an unfiltered FPP preimage selector can still
change on a challenge digest target hit, which remains a charged event.
SOURCE ONLY; normal kernel check remains required. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentChallengeSourceDisjoint
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets (Role StageQuery)
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (roleDomain canonicalCurrentQueryBytes parseCurrentStageQuery successful_query_frame_exact)
end C
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (parseFrame rawPayload rawNext decodeRole Stage)
end F
namespace L
export NativePrivateSpendQ58CurrentLeafInput (currentProfile)
end L
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (current_profile_width)
end G
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- All four current challenge domains differ from all six source domains. -/
theorem current_challenge_domain_is_not_source (role : Role) :
    F.decodeRole (C.roleDomain role) = none := by cases role <;> decide

private def payload (query : StageQuery) : List Byte :=
  if query.role = .piopOpening then
    encodeLE 8 query.nonce ++ List.ofFn query.target else List.ofFn query.target

/-- The common framing parser reads the exact current challenge role.
No nonce/counter bound is needed for source-domain disjointness. -/
private theorem current_challenge_source_frame_parse (query : StageQuery) :
    F.parseFrame (C.canonicalCurrentQueryBytes query) =
      if decodeLE (encodeLE 8 query.counter) = 0 then
        some (C.roleDomain query.role, payload query) else none := by
  have roleBound : (C.roleDomain query.role).length < 256 ^ 8 := by
    cases query.role <;> decide
  have roleMod := Nat.mod_eq_of_lt roleBound
  have profileMod : L.currentProfile.length % 256 ^ 8 = L.currentProfile.length := by
    rw [G.current_profile_width]
    norm_num
  have countMod : (if query.role = .piopOpening then 9 else 8) % 256 ^ 8 =
      (if query.role = .piopOpening then 9 else 8) := by
    by_cases opening : query.role = .piopOpening <;> simp [opening]
  have aligned : (payload query).length =
      8 * (if query.role = .piopOpening then 9 else 8) := by
    by_cases opening : query.role = .piopOpening <;>
      simp [payload, opening, encodeLE_length]
  have lastRead : readFixed 8 (encodeLE 8 query.counter) =
      some (encodeLE 8 query.counter, []) := by
    simpa only [List.append_nil] using
      (readFixed_append (suffix := []) (encodeLE_length 8 query.counter))
  have decodeProfile : decodeLE (encodeLE 8 L.currentProfile.length) =
      L.currentProfile.length :=
    (decodeLE_encodeLE 8 L.currentProfile.length).trans profileMod
  have decodeRoleLength : decodeLE (encodeLE 8 (C.roleDomain query.role).length) =
      (C.roleDomain query.role).length :=
    (decodeLE_encodeLE 8 (C.roleDomain query.role).length).trans roleMod
  have decodeCount : decodeLE (encodeLE 8 (if query.role = .piopOpening then 9 else 8)) =
      (if query.role = .piopOpening then 9 else 8) :=
    (decodeLE_encodeLE 8 (if query.role = .piopOpening then 9 else 8)).trans countMod
  change F.parseFrame
      (encodeLE 8 L.currentProfile.length ++ L.currentProfile ++
       encodeLE 8 (C.roleDomain query.role).length ++ C.roleDomain query.role ++
       encodeLE 8 (if query.role = .piopOpening then 9 else 8) ++
       payload query ++ encodeLE 8 query.counter) = _
  simp [F.parseFrame, List.append_assoc, encodeLE_length,
    decodeProfile, decodeRoleLength, decodeCount, aligned, lastRead]

/-- Every literal current challenge frame is outside the source grammar. -/
theorem current_challenge_has_no_source_payload (query : StageQuery) :
    F.rawPayload (C.canonicalCurrentQueryBytes query) = none := by
  unfold F.rawPayload
  rw [current_challenge_source_frame_parse]
  by_cases base : decodeLE (encodeLE 8 query.counter) = 0
  · rw [if_pos base]
    change (F.decodeRole (C.roleDomain query.role)).bind _ = none
    rw [current_challenge_domain_is_not_source]
    rfl
  · rw [if_neg base]
    rfl

/-- Successful current parsing supplies the literal constructor equality;
source exclusion is derived, rather than supplied as an inactivity premise. -/
theorem current_parsed_challenge_has_no_source_payload
    (input : V8SmzaOracleParser.RawInput) (query : StageQuery)
    (parsed : C.parseCurrentStageQuery input = some query) : F.rawPayload input = none := by
  rw [C.successful_query_frame_exact input query parsed]
  exact current_challenge_has_no_source_payload query

theorem current_parsed_challenge_has_no_source_edges (stage : F.Stage)
    (input : V8SmzaOracleParser.RawInput) (query : StageQuery)
    (parsed : C.parseCurrentStageQuery input = some query) : F.rawNext stage input = none := by
  simp only [F.rawNext, current_parsed_challenge_has_no_source_payload input query parsed,
    Option.bind_none]

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentChallengeSourceDisjoint
