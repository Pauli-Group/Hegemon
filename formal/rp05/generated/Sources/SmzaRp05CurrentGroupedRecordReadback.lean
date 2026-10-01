import SmzaRp05GroupedSuffix
import SmzaRp05AdaptiveRetainedAdviceParser
import SmzaRp05ExecutableChallengeStage
import SmzaRp05CurrentOpeningProgram
import SmzaRp05ChallengeRecordErasure

/-! # Current decoder relevance and grouped-record representatives

Challenge counter frames are erased by the current VC decoder. This file
connects that fact to the fixed grouped address: any raw input that can
contribute a global VC edge is in the ungrouped complement, hence is its own
counter-zero representative. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedRecordReadback

open HegemonCrypto.CanonicalBytes
open SmzaRp05GroupedSuffix
open SmzaChallengeStageTargets
open SmzaRp05AdaptiveRetainedAdviceParser (canonicalQueryBytes successful_query_frame_exact)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)

set_option autoImplicit false
noncomputable section

def canonicalQueryPrefix (query : StageQuery) : RawInput :=
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++ V8SmzaOracleParser.profileDomain ++
    encodeLE 8 (roleDomain query.role).length ++ roleDomain query.role ++
    encodeLE 8 (if query.role = .piopOpening then 9 else 8) ++
    (if query.role = .piopOpening then encodeLE 8 query.nonce ++ List.ofFn query.target
      else List.ofFn query.target)

private theorem canonical_query_bytes_split (query : StageQuery) :
    canonicalQueryBytes query = canonicalQueryPrefix query ++ encodeLE 8 query.counter := by
  simp [canonicalQueryBytes, canonicalQueryPrefix, List.append_assoc]

private theorem parsed_query_nonce_facts (input : RawInput) (query : StageQuery)
    (parsed : parseStageQuery input = some query) :
    (query.role = .piopOpening → query.nonce < 2 ^ 32) ∧
      (query.role ≠ .piopOpening → query.nonce = 0) := by
  unfold parseStageQuery at parsed
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨profileLength, afterProfileLength⟩, profileLengthRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨profile, afterProfile⟩, profileRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨roleLength, afterRoleLength⟩, roleLengthRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨roleBytes, afterRole⟩, roleRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨role, decodedRole, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨wordCount, afterWordCount⟩, wordCountRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨payload, afterPayload⟩, payloadRead, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with
    ⟨⟨counter, suffix⟩, counterRead, parsed⟩
  change (if profile = V8SmzaOracleParser.profileDomain ∧
      payload.length = SmzaChallengeStageTargets.payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
    then some (⟨role, V8SmzaOracleParser.digestAt payload (digestOffset role),
      if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0,
      decodeLE counter⟩ : StageQuery) else none) = some query at parsed
  by_cases valid : profile = V8SmzaOracleParser.profileDomain ∧
      payload.length = SmzaChallengeStageTargets.payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
  · rw [if_pos valid] at parsed
    have outputEq := Option.some.inj parsed
    subst query
    rcases valid with ⟨_, _, _, nonceBound⟩
    constructor
    · intro opening
      simpa [opening] using nonceBound
    · intro notOpening
      simp [notOpening]
  · rw [if_neg valid] at parsed
    cases parsed

private theorem prefix_of_counter_zero_frame (leading : RawInput) (query : StageQuery)
    (parsed : parseStageQuery (leading ++ encodeLE 8 0) = some query) :
    leading = canonicalQueryPrefix query := by
  have exactFrame := successful_query_frame_exact _ _ parsed
  rw [canonical_query_bytes_split] at exactFrame
  have leftLength : (encodeLE 8 0).length = 8 := by simp [encodeLE_length]
  have rightLength : (encodeLE 8 query.counter).length = 8 := by simp [encodeLE_length]
  have totalLength := congrArg List.length exactFrame
  have prefixLength : leading.length = (canonicalQueryPrefix query).length := by
    simp only [List.length_append, leftLength, rightLength] at totalLength
    omega
  exact (List.append_inj exactFrame prefixLength).1

/-- The admitted grouped prefix retains the exact query accepted at its zero
counter coordinate, including the attempted opening nonce. -/
theorem canonical_role_prefix_query_and_leading
    (rolePrefix : CanonicalRolePrefix) :
    ∃ query,
      parseStageQuery (rolePrefix.leading ++ encodeLE 8 0) = some query ∧
        query.role = rolePrefix.role ∧
          rolePrefix.leading = canonicalQueryPrefix query := by
  obtain ⟨query, parsed, roleEq⟩ := rolePrefix.canonical
  exact ⟨query, parsed, roleEq,
    prefix_of_counter_zero_frame rolePrefix.leading query parsed⟩

private theorem decode_eight_byte_counter (value : Nat) (bound : value < 2 ^ 64) :
    decodeLE (encodeLE 8 value) = value := by
  rw [decodeLE_encodeLE]
  have power : 256 ^ 8 = 2 ^ 64 := by norm_num
  rw [power]
  exact Nat.mod_eq_of_lt bound

private theorem ordinary_counter_recognized
    (role : Role) (notOpening : role ≠ .piopOpening)
    (digest : RawDigest) (counter : Fin (2 ^ 64)) :
    (parseStageQuery
      (SmzaRp05ExecutableChallengeStage.counterInput (roleDomain role) digest counter.val)).isSome := by
  have profileLength : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have profileBound : V8SmzaOracleParser.profileDomain.length < 2 ^ 64 := by
    rw [profileLength]
    norm_num
  have decodeProfile := decode_eight_byte_counter _ profileBound
  have roleBound : (roleDomain role).length < 2 ^ 64 := by
    cases role <;> decide
  have decodeRoleLength := decode_eight_byte_counter _ roleBound
  have decodeEight : decodeLE (encodeLE 8 8) = 8 :=
    decode_eight_byte_counter 8 (by norm_num)
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (show readFixed 8 (encodeLE 8 counter.val ++ []) =
          some (encodeLE 8 counter.val, []) from
        readFixed_append (encodeLE_length 8 counter.val))
  have counterWord : decodeLE (encodeLE 8 counter.val) = counter.val := by
    exact decode_eight_byte_counter counter.val counter.isLt
  have payloadRead : readFixed 64 (List.ofFn digest ++ encodeLE 8 counter.val) =
      some (List.ofFn digest, encodeLE 8 counter.val) := by
    rw [readFixed_append (by simp : (List.ofFn digest).length = 64)]
  have digestRead : readFixed 64 (List.ofFn digest ++ encodeLE 8 counter.val) =
      some (List.ofFn digest, encodeLE 8 counter.val) := by
    exact payloadRead
  by_cases opening : role = .piopOpening
  · exact (notOpening opening).elim
  · cases role with
    | decsMatrix =>
        simp only [parseStageQuery, SmzaRp05ExecutableChallengeStage.counterInput,
          Bind.bind, Option.bind, List.append_assoc, readFixed_append, digestRead,
          encodeLE_length, List.length_ofFn,
          decodeProfile, decodeRoleLength, decodeEight, counterRead, counterWord,
          SmzaChallengeStageTargets.role_roundtrip,
          SmzaChallengeStageTargets.payloadLength]
        simp
    | piopMatrix =>
        simp only [parseStageQuery, SmzaRp05ExecutableChallengeStage.counterInput,
          Bind.bind, Option.bind, List.append_assoc, readFixed_append, digestRead,
          encodeLE_length, List.length_ofFn,
          decodeProfile, decodeRoleLength, decodeEight, counterRead, counterWord,
          SmzaChallengeStageTargets.role_roundtrip,
          SmzaChallengeStageTargets.payloadLength]
        simp
    | piopOpening => exact (opening rfl).elim
    | decsSample =>
        simp only [parseStageQuery, SmzaRp05ExecutableChallengeStage.counterInput,
          Bind.bind, Option.bind, List.append_assoc, readFixed_append, digestRead,
          encodeLE_length, List.length_ofFn,
          decodeProfile, decodeRoleLength, decodeEight, counterRead, counterWord,
          SmzaChallengeStageTargets.role_roundtrip,
          SmzaChallengeStageTargets.payloadLength]
        simp

private theorem opening_counter_recognized
    (digest : RawDigest) (nonce : Fin (2 ^ 32)) (counter : Fin (2 ^ 64)) :
    (parseStageQuery
      (SmzaRp05CurrentOpeningProgram.openingCounterInput digest nonce.val counter.val)).isSome := by
  have profileLength : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have profileBound : V8SmzaOracleParser.profileDomain.length < 2 ^ 64 := by
    rw [profileLength]
    norm_num
  have decodeProfile := decode_eight_byte_counter _ profileBound
  have roleBound : SmallWoodTranscript.piopOpeningDomain.length < 2 ^ 64 := by decide
  have decodeRoleLength := decode_eight_byte_counter _ roleBound
  have decodeCount := decode_eight_byte_counter 9 (by norm_num)
  have openingRole : decodeChallengeRole SmallWoodTranscript.piopOpeningDomain =
      some .piopOpening := by
    change decodeChallengeRole (roleDomain .piopOpening) = some .piopOpening
    exact SmzaChallengeStageTargets.role_roundtrip .piopOpening
  have nonceWord : V8SmzaOracleParser.wordAt
      (encodeLE 8 nonce.val ++ List.ofFn digest) 0 = nonce.val := by
    have nonce64 : nonce.val < 2 ^ 64 := by
      have nonceBound := nonce.isLt
      omega
    have noncePayload :
        (encodeLE 8 nonce.val ++ List.ofFn digest).take 8 = encodeLE 8 nonce.val := by
      simp [encodeLE_length]
    simp only [V8SmzaOracleParser.wordAt,
      V8Smz9CoherentMerkleGeometry.wordAt, Nat.mul_zero, List.drop_zero]
    rw [noncePayload]
    exact decode_eight_byte_counter nonce.val nonce64
  have payloadRead : readFixed 72
      ((encodeLE 8 nonce.val ++ List.ofFn digest) ++ encodeLE 8 counter.val) =
      some (encodeLE 8 nonce.val ++ List.ofFn digest, encodeLE 8 counter.val) := by
    have payloadLength :
        (encodeLE 8 nonce.val ++ List.ofFn digest).length = 72 := by
      simp only [List.length_append, encodeLE_length, List.length_ofFn]
    exact readFixed_append payloadLength
  have payloadReadRight : readFixed 72
      (encodeLE 8 nonce.val ++ (List.ofFn digest ++ encodeLE 8 counter.val)) =
      some (encodeLE 8 nonce.val ++ List.ofFn digest, encodeLE 8 counter.val) := by
    simpa only [List.append_assoc] using payloadRead
  have counterRead : readFixed 8 (encodeLE 8 counter.val) =
      some (encodeLE 8 counter.val, []) := by
    simpa only [List.append_nil] using
      (show readFixed 8 (encodeLE 8 counter.val ++ []) =
          some (encodeLE 8 counter.val, []) from
        readFixed_append (by simp [encodeLE_length]))
  have counterWord : decodeLE (encodeLE 8 counter.val) = counter.val := by
    exact decode_eight_byte_counter counter.val counter.isLt
  simp only [parseStageQuery, SmzaRp05CurrentOpeningProgram.openingCounterInput,
    Bind.bind, Option.bind, List.append_assoc, readFixed_append, payloadReadRight,
    counterRead, counterWord, encodeLE_length,
    decodeProfile, decodeRoleLength, decodeCount, nonceWord, openingRole,
    SmzaChallengeStageTargets.payloadLength]
  simp [encodeLE_length]

/-- Reconstruct the exact executable raw call for the query associated with a
grouped role prefix. Ordinary roles carry no nonce bytes; opening calls retain
the nonce from the zero-counter parser witness. -/
def canonicalQueryCounterInput (query : StageQuery) (counter : Nat) : RawInput :=
  match query.role with
  | .decsMatrix =>
      SmzaRp05ExecutableChallengeStage.counterInput
        (roleDomain .decsMatrix) query.target counter
  | .piopMatrix =>
      SmzaRp05ExecutableChallengeStage.counterInput
        (roleDomain .piopMatrix) query.target counter
  | .piopOpening =>
      SmzaRp05CurrentOpeningProgram.openingCounterInput query.target query.nonce counter
  | .decsSample =>
      SmzaRp05ExecutableChallengeStage.counterInput
        (roleDomain .decsSample) query.target counter

/-- Every bounded group coordinate is literally the corresponding source
counter call under its counter-zero parser witness. -/
theorem grouped_coordinate_eq_canonical_query_counter_input
    (rolePrefix : CanonicalRolePrefix) (counter : GroupCounter) :
    ∃ query,
      parseStageQuery (rolePrefix.leading ++ encodeLE 8 0) = some query ∧
        query.role = rolePrefix.role ∧
          groupEncode (rolePrefix, counter) =
            canonicalQueryCounterInput query counter.val := by
  obtain ⟨query, parsed, roleEq, leadingEq⟩ :=
    canonical_role_prefix_query_and_leading rolePrefix
  refine ⟨query, parsed, roleEq, ?_⟩
  change rolePrefix.leading ++ encodeLE 8 counter.val = _
  rw [leadingEq]
  cases roleCase : query.role <;>
    simp [roleCase, canonicalQueryCounterInput, canonicalQueryPrefix, roleDomain,
      SmzaRp05ExecutableChallengeStage.counterInput,
      SmzaRp05CurrentOpeningProgram.openingCounterInput, List.append_assoc]

private theorem grouped_prefix_query_exists (rolePrefix : CanonicalRolePrefix)
    (counter : GroupCounter) :
    ∃ query, parseStageQuery (groupEncode (rolePrefix, counter)) = some query := by
  obtain ⟨baseQuery, baseParsed, roleEq⟩ := rolePrefix.canonical
  have leadingEq := prefix_of_counter_zero_frame rolePrefix.leading baseQuery baseParsed
  have nonceFacts := parsed_query_nonce_facts
    (rolePrefix.leading ++ encodeLE 8 0) baseQuery baseParsed
  have counterBound : counter.val < 2 ^ 64 := by
    exact lt_of_lt_of_le counter.isLt group_block_cap_le_u64
  let counter64 : Fin (2 ^ 64) := ⟨counter.val, counterBound⟩
  cases roleCase : rolePrefix.role with
  | decsMatrix =>
      have qRole : baseQuery.role = .decsMatrix := roleEq.trans roleCase
      have inputEq : groupEncode (rolePrefix, counter) =
          SmzaRp05ExecutableChallengeStage.counterInput
            SmallWoodTranscript.decsCoefficientDomain baseQuery.target counter64.val := by
        change rolePrefix.leading ++ encodeLE 8 counter.val = _
        rw [leadingEq]
        simp [canonicalQueryPrefix, qRole, roleDomain,
          SmallWoodTranscript.decsCoefficientDomain,
          SmzaRp05ExecutableChallengeStage.counterInput, counter64]
      rw [inputEq]
      exact Option.isSome_iff_exists.mp
        (ordinary_counter_recognized .decsMatrix (by decide) baseQuery.target counter64)
  | piopMatrix =>
      have qRole : baseQuery.role = .piopMatrix := roleEq.trans roleCase
      have inputEq : groupEncode (rolePrefix, counter) =
          SmzaRp05ExecutableChallengeStage.counterInput
            SmallWoodTranscript.piopCoefficientDomain baseQuery.target counter64.val := by
        change rolePrefix.leading ++ encodeLE 8 counter.val = _
        rw [leadingEq]
        simp [canonicalQueryPrefix, qRole, roleDomain,
          SmallWoodTranscript.piopCoefficientDomain,
          SmzaRp05ExecutableChallengeStage.counterInput, counter64]
      rw [inputEq]
      exact Option.isSome_iff_exists.mp
        (ordinary_counter_recognized .piopMatrix (by decide) baseQuery.target counter64)
  | piopOpening =>
      have qRole : baseQuery.role = .piopOpening := roleEq.trans roleCase
      have qNonce : baseQuery.nonce < 2 ^ 32 := nonceFacts.1 qRole
      let nonce32 : Fin (2 ^ 32) := ⟨baseQuery.nonce, qNonce⟩
      have inputEq : groupEncode (rolePrefix, counter) =
          SmzaRp05CurrentOpeningProgram.openingCounterInput baseQuery.target
            nonce32.val counter64.val := by
        change rolePrefix.leading ++ encodeLE 8 counter.val = _
        rw [leadingEq]
        simp [canonicalQueryPrefix, qRole, roleDomain, nonce32,
          SmzaRp05CurrentOpeningProgram.openingCounterInput,
          SmallWoodTranscript.piopOpeningDomain, counter64]
      rw [inputEq]
      exact Option.isSome_iff_exists.mp
        (opening_counter_recognized baseQuery.target nonce32 counter64)
  | decsSample =>
      have qRole : baseQuery.role = .decsSample := roleEq.trans roleCase
      have inputEq : groupEncode (rolePrefix, counter) =
          SmzaRp05ExecutableChallengeStage.counterInput
            SmallWoodTranscript.decsFixedSamplingDomain baseQuery.target counter64.val := by
        change rolePrefix.leading ++ encodeLE 8 counter.val = _
        rw [leadingEq]
        simp [canonicalQueryPrefix, qRole, roleDomain,
          SmallWoodTranscript.decsFixedSamplingDomain,
          SmzaRp05ExecutableChallengeStage.counterInput, counter64]
      rw [inputEq]
      exact Option.isSome_iff_exists.mp
        (ordinary_counter_recognized .decsSample (by decide) baseQuery.target counter64)

/-- Every bounded group coordinate is a challenge frame, so the current VC
decoder cannot select it as a record. -/
theorem grouped_coordinate_is_challenge_frame (rolePrefix : CanonicalRolePrefix)
    (counter : GroupCounter) :
    (parseStageQuery (groupEncode (rolePrefix, counter))).isSome := by
  obtain ⟨query, parsed⟩ := grouped_prefix_query_exists rolePrefix counter
  exact Option.isSome_iff_exists.mpr ⟨query, parsed⟩

/-- Global current-decoder relevance forces a physical raw input into the
group complement. Therefore it is its own representative at coordinate zero;
challenge-query records are excluded by the exact current erasure theorem. -/
theorem nonchallenge_input_is_group_representative
    (input : V8SmzaOracleParser.RawInput) (notChallenge : parseStageQuery input = none) :
    input = groupRepresentative (groupAddress input).1 ∧
      (groupAddress input).2 = groupZero := by
  have outside : input ∉ Set.range groupEncode := by
    intro inRange
    obtain ⟨pair, pairEq⟩ := inRange
    rw [← pairEq] at notChallenge
    obtain ⟨query, parsed⟩ := Option.isSome_iff_exists.mp
      (grouped_coordinate_is_challenge_frame pair.1 pair.2)
    simp [notChallenge] at parsed
  let complement : GroupComplement := ⟨input, outside⟩
  have addressEq : groupAddress input = (Sum.inr complement, groupZero) :=
    group_address_complement complement
  have representativeEq : groupRepresentative (Sum.inr complement) = input := rfl
  constructor
  · rw [addressEq]
    exact representativeEq.symm
  · exact congrArg Prod.snd addressEq

/-- Global current-decoder relevance forces a physical raw input into the
group complement. Therefore it is its own representative at coordinate zero;
challenge-query records are excluded by the exact current erasure theorem. -/
theorem global_online_relevant_input_is_group_representative
    (ns : SmzaRp05LeafNamespace.Namespace) (stage : V8SmzaOracleParser.Stage)
    (input : V8SmzaOracleParser.RawInput)
    (relevant : (globalOnlineNext ns stage input).isSome) :
    input = groupRepresentative (groupAddress input).1 ∧
      (groupAddress input).2 = groupZero := by
  have notChallenge : parseStageQuery input = none := by
    cases parsed : parseStageQuery input with
    | none => rfl
    | some query =>
        have inert :=
          SmzaRp05ChallengeRecordErasure.parse_stage_query_global_next_none
            ns input query parsed stage
        simp [inert] at relevant
  exact nonchallenge_input_is_group_representative input notChallenge

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedRecordReadback
