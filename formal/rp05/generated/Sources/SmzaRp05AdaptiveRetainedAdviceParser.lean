import SmzaChallengeStageTargets

/-! Successful role frames have a unique byte representation. This closes
the representation seam between an actual canonical oracle read and the
legacy fixed-table selector, without requiring a cryptographic assumption.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceParser

open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets

set_option autoImplicit false
set_option maxRecDepth 12000

theorem decode_le_injective_same_length (left right : List Byte)
    (length : left.length = right.length) (decoded : decodeLE left = decodeLE right) :
    left = right := by
  induction left generalizing right with
  | nil => cases right <;> simp_all
  | cons head tail ih =>
      cases right with
      | nil => simp at length
      | cons other rest =>
          have heads : head.val = other.val := by
            simp only [decodeLE] at decoded
            have headBound := head.isLt
            have otherBound := other.isLt
            omega
          have tails : decodeLE tail = decodeLE rest := by
            simp only [decodeLE, heads] at decoded
            omega
          exact congrArg₂ List.cons (Fin.ext heads) (ih rest (by simpa using length) tails)

theorem decode_le_lt (bytes : List Byte) : decodeLE bytes < 256 ^ bytes.length := by
  induction bytes with
  | nil => simp [decodeLE]
  | cons head tail ih =>
      simp only [decodeLE, List.length_cons, pow_succ]
      have bounded := head.isLt
      nlinarith

theorem encode_decode_le (bytes : List Byte) :
    encodeLE bytes.length (decodeLE bytes) = bytes := by
  apply decode_le_injective_same_length
  · exact encodeLE_length _ _
  · rw [decodeLE_encodeLE, Nat.mod_eq_of_lt (decode_le_lt bytes)]

theorem decode_challenge_role_sound (bytes : List Byte) (role : Role)
    (parsed : decodeChallengeRole bytes = some role) : bytes = roleDomain role := by
  unfold decodeChallengeRole at parsed
  split at parsed
  · cases parsed; assumption
  · split at parsed
    · cases parsed; assumption
    · split at parsed
      · cases parsed; assumption
      · split at parsed
        · cases parsed; assumption
        · contradiction

theorem digest_bytes_eq_suffix (payload : List Byte) (offset : Nat)
    (length : payload.length = offset + 64) :
    List.ofFn (V8SmzaOracleParser.digestAt payload offset) = payload.drop offset := by
  apply List.ext_getElem
  · simp [length]
  · intro index leftBound rightBound
    have bounded : offset + index < payload.length := by
      simp only [List.length_drop] at rightBound
      omega
    simp only [List.getElem_ofFn, List.getElem_drop]
    exact List.getD_eq_getElem payload 0 bounded

def canonicalQueryBytes (query : StageQuery) : RawInput :=
  let payload := if query.role = .piopOpening then
      encodeLE 8 query.nonce ++ List.ofFn query.target else List.ofFn query.target
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++ V8SmzaOracleParser.profileDomain ++
    encodeLE 8 (roleDomain query.role).length ++ roleDomain query.role ++
    encodeLE 8 (if query.role = .piopOpening then 9 else 8) ++ payload ++
    encodeLE 8 query.counter

theorem payload_reconstruction (role : Role) (payload : List Byte)
    (length : payload.length = payloadLength role) :
    payload = if role = .piopOpening then
        encodeLE 8 (V8SmzaOracleParser.wordAt payload 0) ++
          List.ofFn (V8SmzaOracleParser.digestAt payload (digestOffset role))
      else List.ofFn (V8SmzaOracleParser.digestAt payload (digestOffset role)) := by
  by_cases opening : role = .piopOpening
  · subst role
    have length72 : payload.length = 72 := length
    have headLength : (payload.take 8).length = 8 := by simp [length72]
    have head := encode_decode_le (payload.take 8)
    rw [headLength] at head
    change payload = encodeLE 8 (decodeLE (payload.take 8)) ++
      List.ofFn (V8SmzaOracleParser.digestAt payload 8)
    rw [head, digest_bytes_eq_suffix payload 8 (by omega), List.take_append_drop]
  · have length64 : payload.length = 64 := by cases role <;> simp_all [payloadLength]
    have offset : digestOffset role = 0 := by cases role <;> simp_all [digestOffset]
    rw [if_neg opening, offset, digest_bytes_eq_suffix payload 0 (by omega), List.drop_zero]

/-- All lengths and all payload bytes are consumed by a successful parser;
there is no ignored prefix, suffix, nonce word, or alternate role encoding. -/
theorem successful_query_frame_exact (input : RawInput) (query : StageQuery)
    (parsed : parseStageQuery input = some query) : input = canonicalQueryBytes query := by
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
      payload.length = payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
    then some (⟨role, V8SmzaOracleParser.digestAt payload (digestOffset role),
      if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0,
      decodeLE counter⟩ : StageQuery)
    else none) = some query at parsed
  by_cases valid : profile = V8SmzaOracleParser.profileDomain ∧
      payload.length = payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
  · rw [if_pos valid] at parsed
    obtain ⟨profileEq, payloadLengthEq, suffixEq, _nonceBound⟩ := valid
    cases parsed
    obtain ⟨profileHeaderWidth, inputEq⟩ := readFixed_sound profileLengthRead
    obtain ⟨profileWidth, profileRestEq⟩ := readFixed_sound profileRead
    obtain ⟨roleHeaderWidth, roleHeaderRestEq⟩ := readFixed_sound roleLengthRead
    obtain ⟨roleWidth, roleRestEq⟩ := readFixed_sound roleRead
    obtain ⟨countHeaderWidth, countRestEq⟩ := readFixed_sound wordCountRead
    obtain ⟨payloadWidth, payloadRestEq⟩ := readFixed_sound payloadRead
    obtain ⟨counterWidth, counterRestEq⟩ := readFixed_sound counterRead
    have roleEq := decode_challenge_role_sound roleBytes role decodedRole
    have profileHeader := encode_decode_le profileLength
    rw [profileHeaderWidth, ← profileWidth, profileEq] at profileHeader
    have roleHeader := encode_decode_le roleLength
    rw [roleHeaderWidth, ← roleWidth, roleEq] at roleHeader
    have countValue : decodeLE wordCount = if role = .piopOpening then 9 else 8 := by
      have relation : 8 * decodeLE wordCount = payloadLength role :=
        payloadWidth.symm.trans payloadLengthEq
      cases role with
      | decsMatrix =>
          change decodeLE wordCount = 8
          change 8 * decodeLE wordCount = 64 at relation
          omega
      | piopMatrix =>
          change decodeLE wordCount = 8
          change 8 * decodeLE wordCount = 64 at relation
          omega
      | piopOpening =>
          change decodeLE wordCount = 9
          change 8 * decodeLE wordCount = 72 at relation
          omega
      | decsSample =>
          change decodeLE wordCount = 8
          change 8 * decodeLE wordCount = 64 at relation
          omega
    have countHeader := encode_decode_le wordCount
    rw [countHeaderWidth, countValue] at countHeader
    have counterHeader := encode_decode_le counter
    rw [counterWidth] at counterHeader
    have payloadEq := payload_reconstruction role payload payloadLengthEq
    conv_lhs =>
      rw [inputEq, profileRestEq, roleHeaderRestEq, roleRestEq,
        countRestEq, payloadRestEq, counterRestEq, suffixEq, List.append_nil,
        ← profileHeader, ← roleHeader, ← countHeader, ← counterHeader,
        profileEq, roleEq, payloadEq]
    unfold canonicalQueryBytes
    by_cases opening : role = .piopOpening <;> simp only [opening, if_true, if_false,
      List.append_assoc]
  · rw [if_neg valid] at parsed
    contradiction

theorem successful_query_frame_unique (left right : RawInput) (query : StageQuery)
    (leftRead : parseStageQuery left = some query)
    (rightRead : parseStageQuery right = some query) : left = right :=
  (successful_query_frame_exact left query leftRead).trans
    (successful_query_frame_exact right query rightRead).symm

theorem successful_query_fields_unique (left right : RawInput)
    (leftQuery rightQuery : StageQuery)
    (leftRead : parseStageQuery left = some leftQuery)
    (rightRead : parseStageQuery right = some rightQuery)
    (role : leftQuery.role = rightQuery.role)
    (target : leftQuery.target = rightQuery.target)
    (nonce : leftQuery.nonce = rightQuery.nonce)
    (counter : leftQuery.counter = rightQuery.counter) : left = right := by
  have same : leftQuery = rightQuery := by
    cases leftQuery; cases rightQuery; simp_all
  subst rightQuery
  exact successful_query_frame_unique left right leftQuery leftRead rightRead

end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceParser
