import HegemonCrypto.NativePrivateSpendQ58PartitionTransport
import HegemonCrypto.NativePrivateSpendQ58CurrentLeafInput
import SmzaRp05AdaptiveRetainedAdviceParser

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleClassifier

open scoped Classical
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets (Role StageQuery payloadLength digestOffset)
open SmzaRp05AdaptiveRetainedAdviceParser
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
abbrev RawInput := List HegemonCrypto.CanonicalBytes.Byte
abbrev RawDigest := Fin 64 → HegemonCrypto.CanonicalBytes.Byte

def roleDomain : Role → List HegemonCrypto.CanonicalBytes.Byte
  | .decsMatrix => SmallWoodTranscript.decsCoefficientDomain
  | .piopMatrix => SmallWoodTranscript.piopCoefficientDomain
  | .piopOpening => SmallWoodTranscript.piopOpeningDomain
  | .decsSample =>
    [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,110,97,116,105,118,101,45,112,114,105,118,97,116,101,45,115,112,101,110,100,46,115,109,122,100,46,99,111,109,112,102,102,48,49,46,100,101,99,115,45,102,105,120,101,100,45,115,97,109,112,108,105,110,103,46,118,50]

def decodeCurrentRole (bytes : List HegemonCrypto.CanonicalBytes.Byte) : Option Role :=
  if bytes = roleDomain .decsMatrix then some .decsMatrix
  else if bytes = roleDomain .piopMatrix then some .piopMatrix
  else if bytes = roleDomain .piopOpening then some .piopOpening
  else if bytes = roleDomain .decsSample then some .decsSample else none

theorem current_role_roundtrip (role : Role) :
    decodeCurrentRole (roleDomain role) = some role := by
  cases role <;> decide

theorem decode_current_role_sound (bytes : List HegemonCrypto.CanonicalBytes.Byte) (role : Role)
    (parsed : decodeCurrentRole bytes = some role) : bytes = roleDomain role := by
  unfold decodeCurrentRole at parsed
  split at parsed
  · cases parsed; assumption
  · split at parsed
    · cases parsed; assumption
    · split at parsed
      · cases parsed; assumption
      · split at parsed
        · cases parsed; assumption
        · contradiction

def parseCurrentStageQuery (input : RawInput) : Option StageQuery := do
  let (profileLength, rest) ← readFixed 8 input
  let (profile, rest) ← readFixed (decodeLE profileLength) rest
  let (roleLength, rest) ← readFixed 8 rest
  let (roleBytes, rest) ← readFixed (decodeLE roleLength) rest
  let role ← decodeCurrentRole roleBytes
  let (wordCount, rest) ← readFixed 8 rest
  let (payload, rest) ← readFixed (8 * decodeLE wordCount) rest
  let (counter, suffix) ← readFixed 8 rest
  let nonce := if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0
  if profile = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
      payload.length = payloadLength role ∧ suffix = [] ∧ nonce < 2^32 then
    some ⟨role, V8SmzaOracleParser.digestAt payload (digestOffset role), nonce, decodeLE counter⟩
  else none

def canonicalCurrentQueryBytes (query : StageQuery) : RawInput :=
  let payload := if query.role = .piopOpening then
      encodeLE 8 query.nonce ++ List.ofFn query.target else List.ofFn query.target
  encodeLE 8 NativePrivateSpendQ58CurrentLeafInput.currentProfile.length ++
    NativePrivateSpendQ58CurrentLeafInput.currentProfile ++
    encodeLE 8 (roleDomain query.role).length ++ roleDomain query.role ++
    encodeLE 8 (if query.role = .piopOpening then 9 else 8) ++ payload ++
    encodeLE 8 query.counter

theorem successful_query_frame_exact (input : RawInput) (query : StageQuery)
    (parsed : parseCurrentStageQuery input = some query) : input = canonicalCurrentQueryBytes query := by
  unfold parseCurrentStageQuery at parsed
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
  change (if profile = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
      payload.length = payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
    then some (⟨role, V8SmzaOracleParser.digestAt payload (digestOffset role),
      if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0,
      decodeLE counter⟩ : StageQuery)
    else none) = some query at parsed
  by_cases valid : profile = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
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
    have roleEq := decode_current_role_sound roleBytes role decodedRole
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
    unfold canonicalCurrentQueryBytes
    by_cases opening : role = .piopOpening <;> simp only [opening, if_true, if_false,
      List.append_assoc]
  · rw [if_neg valid] at parsed
    contradiction

theorem successful_query_frame_unique (left right : RawInput) (query : StageQuery)
    (leftRead : parseCurrentStageQuery left = some query)
    (rightRead : parseCurrentStageQuery right = some query) : left = right :=
  (successful_query_frame_exact left query leftRead).trans
    (successful_query_frame_exact right query rightRead).symm

theorem successful_query_fields_unique (left right : RawInput)
    (leftQuery rightQuery : StageQuery)
    (leftRead : parseCurrentStageQuery left = some leftQuery)
    (rightRead : parseCurrentStageQuery right = some rightQuery)
    (role : leftQuery.role = rightQuery.role)
    (target : leftQuery.target = rightQuery.target)
    (nonce : leftQuery.nonce = rightQuery.nonce)
    (counter : leftQuery.counter = rightQuery.counter) : left = right := by
  have same : leftQuery = rightQuery := by
    cases leftQuery; cases rightQuery; simp_all
  subst rightQuery
  exact successful_query_frame_unique left right leftQuery leftRead rightRead

variable {Key Counter Work Result : Type}

def RoleActive (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → RawInput) (key : Key) : Prop :=
  match parseCurrentStageQuery (keyBytes key) with
  | none => True
  | some query => query.role = selected ∨ ¬query.counter < blockCap query.role

theorem unrecognized_is_active (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → RawInput) (key : Key)
    (unrecognized : parseCurrentStageQuery (keyBytes key) = none) :
    RoleActive selected blockCap keyBytes key := by
  simp [RoleActive, unrecognized]

theorem other_bounded_role_is_fixed (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → RawInput) (key : Key) (query : StageQuery)
    (parsed : parseCurrentStageQuery (keyBytes key) = some query)
    (different : query.role ≠ selected) (bounded : query.counter < blockCap query.role) :
    ¬RoleActive selected blockCap keyBytes key := by
  simp [RoleActive, parsed, different, bounded]

abbrev FixedKey (selected : Role) (blockCap : Role → Nat) (keyBytes : Key → RawInput) :=
  NativePrivateSpendQ58PartitionTransport.FixedKey (RoleActive selected blockCap keyBytes)

abbrev FixedTable (selected : Role) (blockCap : Role → Nat) (keyBytes : Key → RawInput) :=
  NativePrivateSpendQ58PartitionTransport.FixedTable (Counter := Counter)
    (RoleActive selected blockCap keyBytes)

def fixedVectorAtNonce (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → RawInput) (fixed : FixedTable (Counter := Counter) selected blockCap keyBytes)
    (role : Role) (target : RawDigest) (nonce : Nat) : Option (VectorOutput Counter) :=
  if found : ∃ key : FixedKey selected blockCap keyBytes,
      ∃ query, parseCurrentStageQuery (keyBytes key.val) = some query ∧
        query.role = role ∧ query.target = target ∧ query.nonce = nonce ∧ query.counter = 0 then
    some (fixed (Classical.choose found)) else none

theorem fixed_vector_at_nonce_eq_actual_cell
    (selected : Role) (blockCap : Role → Nat) (keyBytes : Key → RawInput)
    (injection : Function.Injective keyBytes)
    (fixed : FixedTable (Counter := Counter) selected blockCap keyBytes)
    (key : FixedKey selected blockCap keyBytes) (query : StageQuery)
    (parsed : parseCurrentStageQuery (keyBytes key.val) = some query)
    (base : query.counter = 0) :
    fixedVectorAtNonce selected blockCap keyBytes fixed query.role query.target query.nonce =
      some (fixed key) := by
  let found : ∃ candidate : FixedKey selected blockCap keyBytes,
      ∃ parsedQuery, parseCurrentStageQuery (keyBytes candidate.val) = some parsedQuery ∧
        parsedQuery.role = query.role ∧ parsedQuery.target = query.target ∧
        parsedQuery.nonce = query.nonce ∧ parsedQuery.counter = 0 :=
    ⟨key, query, parsed, rfl, rfl, rfl, base⟩
  obtain ⟨chosenQuery, chosenParsed, sameRole, sameTarget, sameNonce, chosenBase⟩ :=
    Classical.choose_spec found
  have sameKey : Classical.choose found = key := by
    apply Subtype.ext
    apply injection
    exact successful_query_fields_unique _ _ chosenQuery query chosenParsed parsed
      sameRole sameTarget sameNonce (chosenBase.trans base.symm)
  simp only [fixedVectorAtNonce, dif_pos found, sameKey]

theorem current_fixed_vector_matches_actual_record
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (selected : Role) (blockCap : Role → Nat) (keyBytes : Key → RawInput)
    (injection : Function.Injective keyBytes)
    (fixed : FixedTable (Counter := Counter) selected blockCap keyBytes)
    (encode : RawInput → Key) (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result) (branch : Branches decode program)
    (state : NativePrivateSpendQ58PartitionTransport.CmsState
      (Key := Key) (Counter := Counter) (Work := Work))
    (basis : HegemonCrypto.CmsCompressedOracle.Basis
      Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (nonzero : NativePrivateSpendQ58PartitionTransport.conditioned
      (RoleActive selected blockCap keyBytes) fixed
      (physicalRun encode decode program branch state) basis ≠ 0)
    (call : RawInput × VectorOutput Counter) (recorded : call ∈ answerLog decode program branch)
    (query : StageQuery) (parsed : parseCurrentStageQuery (keyBytes (encode call.1)) = some query)
    (different : query.role ≠ selected) (bounded : query.counter < blockCap query.role)
    (base : query.counter = 0) :
    fixedVectorAtNonce selected blockCap keyBytes fixed query.role query.target query.nonce =
      some call.2 := by
  have inactive := other_bounded_role_is_fixed selected blockCap keyBytes
    (encode call.1) query parsed different bounded
  have receipt := NativePrivateSpendQ58PartitionTransport.nonzero_physical_fiber_fixed_answers
    (RoleActive selected blockCap keyBytes) fixed encode decode program branch state basis
    nonzero call recorded inactive
  exact (fixed_vector_at_nonce_eq_actual_cell selected blockCap keyBytes injection fixed
    ⟨encode call.1, inactive⟩ query parsed base).trans (congrArg some receipt)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRoleClassifier
