import SmzaChallengeStageTargets
import SmzaRp05FilteredDecoderInstability

/-! Minimal parser separation used by the current-role marked-write lemma.
This avoids importing the broader challenge-record erasure development. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure

open scoped Classical
open HegemonCrypto.CanonicalBytes
open V8Smz9CoherentMerkleGeometry V8SmzaOnlineParser
open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Stage := V8SmzaOracleParser.Stage
abbrev RawRecords := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

theorem decode_challenge_role_eq_some_iff (bytes : List Byte) (role : Role) :
    decodeChallengeRole bytes = some role ↔ bytes = roleDomain role := by
  constructor
  · intro decoded
    unfold decodeChallengeRole at decoded
    split at decoded
    · rename_i same
      have roleEq : Role.decsMatrix = role := Option.some.inj decoded
      subst role
      exact same
    · split at decoded
      · rename_i same
        have roleEq : Role.piopMatrix = role := Option.some.inj decoded
        subst role
        exact same
      · split at decoded
        · rename_i same
          have roleEq : Role.piopOpening = role := Option.some.inj decoded
          subst role
          exact same
        · split at decoded
          · rename_i same
            have roleEq : Role.decsSample = role := Option.some.inj decoded
            subst role
            exact same
          · contradiction
  · intro same
    subst bytes
    exact role_roundtrip role

theorem challenge_role_not_historical (role : Role) :
    V8SmzaOracleParser.decodeRole (roleDomain role) = none := by
  cases role <;> decide

theorem challenge_role_not_v2_leaf (role : Role) :
    roleDomain role ≠ leafV2Role := by
  cases role <;> decide

theorem parse_stage_query_global_payload_none
    (ns : SmzaRp05LeafNamespace.Namespace) (input : RawInput) (query : StageQuery)
    (parsed : parseStageQuery input = some query) :
    globalNormalizedPayload ns input = none := by
  rcases first : readFixed 8 input with _ | ⟨profileLength, rest1⟩
  · simp [parseStageQuery, first] at parsed
  rcases second : readFixed (decodeLE profileLength) rest1 with _ | ⟨profile, rest2⟩
  · simp [parseStageQuery, first, second] at parsed
  rcases third : readFixed 8 rest2 with _ | ⟨roleLength, rest3⟩
  · simp [parseStageQuery, first, second, third] at parsed
  rcases fourth : readFixed (decodeLE roleLength) rest3 with _ | ⟨roleBytes, rest4⟩
  · simp [parseStageQuery, first, second, third, fourth] at parsed
  rcases roleRead : decodeChallengeRole roleBytes with _ | role
  · simp [parseStageQuery, first, second, third, fourth, roleRead] at parsed
  have roleBytesEq : roleBytes = roleDomain role :=
    (decode_challenge_role_eq_some_iff roleBytes role).mp roleRead
  subst roleBytes
  rcases fifth : readFixed 8 rest4 with _ | ⟨wordCount, rest5⟩
  · simp [parseStageQuery, first, second, third, fourth, roleRead, fifth] at parsed
  rcases sixth : readFixed (8 * decodeLE wordCount) rest5 with _ | ⟨payload, rest6⟩
  · simp [parseStageQuery, first, second, third, fourth, roleRead, fifth, sixth] at parsed
  rcases seventh : readFixed 8 rest6 with _ | ⟨counter, suffix⟩
  · simp [parseStageQuery, first, second, third, fourth, roleRead, fifth, sixth,
      seventh] at parsed
  let nonce := if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0
  have accepted :
      profile = V8SmzaOracleParser.profileDomain ∧
      payload.length = payloadLength role ∧ suffix = [] ∧ nonce < 2^32 := by
    by_contra rejected
    simp [parseStageQuery, first, second, third, fourth, roleRead, fifth, sixth,
      seventh] at parsed
    exact rejected parsed.1
  by_cases zero : decodeLE counter = 0
  · have framed : V8SmzaOracleParser.parseFramed input =
        some (roleDomain role, payload) := by
      simp [V8SmzaOracleParser.parseFramed, first, second, third, fourth, fifth,
        sixth, seventh, accepted.1, accepted.2.2.1, zero]
    have historical := challenge_role_not_historical role
    have current := challenge_role_not_v2_leaf role
    simp [globalNormalizedPayload, framed, normalizedPayload, parseCurrentLeaf,
      V8SmzaOracleParser.rawPayload, historical, current]
  · have framed : V8SmzaOracleParser.parseFramed input = none := by
      simp [V8SmzaOracleParser.parseFramed, first, second, third, fourth, fifth,
        sixth, seventh, accepted.1, accepted.2.2.1, zero]
    simp [globalNormalizedPayload, framed]

theorem global_leaf_statement_global_payload_some
    (ns : SmzaRp05LeafNamespace.Namespace) (input : RawInput) (statement : List Byte)
    (parsed : globalLeafStatement ns input = some statement) :
    ∃ payload, globalNormalizedPayload ns input = some payload := by
  cases framed : V8SmzaOracleParser.parseFramed input with
  | none => simp [globalLeafStatement, framed] at parsed
  | some frame =>
      rcases frame with ⟨role, bytes⟩
      let salt := (bytes.drop preambleBytes).take 32
      have leafParsed : leafStatement ns salt input = some statement := by
        simpa [globalLeafStatement, framed, salt] using parsed
      cases current : parseCurrentLeaf ns salt input with
      | none => simp [leafStatement, current] at leafParsed
      | some leaf =>
          refine ⟨leaf.normalized, ?_⟩
          simp [globalNormalizedPayload, framed, normalizedPayload, salt, current]

theorem global_leaf_statement_parse_stage_query_none
    (ns : SmzaRp05LeafNamespace.Namespace) (input : RawInput) (statement : List Byte)
    (leaf : globalLeafStatement ns input = some statement) :
    parseStageQuery input = none := by
  cases stageParsed : parseStageQuery input with
  | none => rfl
  | some query =>
      obtain ⟨payload, payloadSome⟩ :=
        global_leaf_statement_global_payload_some ns input statement leaf
      have payloadNone := parse_stage_query_global_payload_none ns input query stageParsed
      rw [payloadNone] at payloadSome
      contradiction

theorem global_leaf_statement_not_in_role_domain
    (ns : SmzaRp05LeafNamespace.Namespace) (input : RawInput) (statement : List Byte)
    (leaf : globalLeafStatement ns input = some statement) (role : Role) :
    ¬ InRoleDomain role input := by
  rintro ⟨query, parsed, _⟩
  rw [global_leaf_statement_parse_stage_query_none ns input statement leaf] at parsed
  contradiction

end
end HegemonCrypto.SmallWood.SmzaRp05ChallengeRecordErasure
