import HegemonCrypto.NativePrivateSpendQ58CurrentClaimReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentChallengeSourceDisjoint
import SmzaRp05ChallengeRecordErasure

/-! Current finite grouping preserves every non-challenge source input.
This is a literal parser/counter constructor proof. The retained arbitrary
Program branch supplies reachability, while claim storage supplies its actual
vector. No old profile, source invariance or oracle agreement is assumed.
SOURCE ONLY; compiler and final event inclusion pending. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentComplementReadback
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets (Role StageQuery)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog rawLog)
open V8Smz9RawCounterCompiler
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentMerkleGeometry (Records extract)
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open scoped Classical
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (RawInput RawDigest Counter zero Prefix ComplementKey GroupKey groupEncode
   groupKeyOf coordinate address address_complement representative Key included
   encode decode keyBytes leading frame frame_parser_receipt nonceValue
   included_encode_of_reachable)
end G
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (parseCurrentStageQuery canonicalCurrentQueryBytes successful_query_frame_exact)
end C
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
  (fullClaims current_claims_store_every_branch_vector)
end Q
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext Trace Stage)
end F
namespace I
export NativePrivateSpendQ58CurrentChallengeSourceDisjoint
  (current_parsed_challenge_has_no_source_edges)
end I
abbrev RawRecords := Records G.RawInput G.RawDigest
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

private theorem successful_nonce_bound (input : G.RawInput) (query : StageQuery)
    (parsed : C.parseCurrentStageQuery input = some query) : query.nonce < 2^32 := by
  unfold C.parseCurrentStageQuery at parsed
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨a, ar⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨b, br⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨c, cr⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨d, dr⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨role, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨e, er⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨payload, rest⟩, _, parsed⟩
  rcases Option.bind_eq_some_iff.mp parsed with ⟨⟨counter, suffix⟩, _, parsed⟩
  change (if b = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
      payload.length = SmzaChallengeStageTargets.payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
    then some (⟨role, V8SmzaOracleParser.digestAt payload
      (SmzaChallengeStageTargets.digestOffset role),
      if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0,
      decodeLE counter⟩ : StageQuery)
    else none) = some query at parsed
  by_cases valid : b = NativePrivateSpendQ58CurrentLeafInput.currentProfile ∧
      payload.length = SmzaChallengeStageTargets.payloadLength role ∧ suffix = [] ∧
      (if role = .piopOpening then V8SmzaOracleParser.wordAt payload 0 else 0) < 2 ^ 32
  · rw [if_pos valid] at parsed
    cases parsed
    exact valid.2.2.2
  · rw [if_neg valid] at parsed
    contradiction

/-- Replacing only the consumed eight-byte counter of a successful current
prefix leaves its current role, target and nonce fixed. -/
theorem current_prefix_counter_parser («prefix» : G.Prefix) (counter : G.Counter) :
    ∃ query, C.parseCurrentStageQuery (G.groupEncode («prefix», counter)) = some query ∧
      query.counter = counter.val := by
  obtain ⟨query, parsed⟩ := «prefix».property
  let nonce : Fin (2^32) := ⟨query.nonce, successful_nonce_bound _ query parsed⟩
  have literal := C.successful_query_frame_exact _ query parsed
  have canonical : C.canonicalCurrentQueryBytes query =
      G.leading query.role query.target nonce ++ encodeLE 8 query.counter := rfl
  rw [canonical] at literal
  have lengths := congrArg List.length literal
  simp only [List.length_append, encodeLE_length] at lengths
  have sameLength : «prefix».val.length = (G.leading query.role query.target nonce).length := by omega
  have initial := congrArg (fun bytes : G.RawInput => bytes.take «prefix».val.length) literal
  have samePrefix : «prefix».val = G.leading query.role query.target nonce := by
    simpa [List.take_append, sameLength] using initial
  refine ⟨⟨query.role, query.target, G.nonceValue query.role nonce, counter.val⟩, ?_, rfl⟩
  change C.parseCurrentStageQuery («prefix».val ++ encodeLE 8 counter.val) = _
  rw [samePrefix]
  exact G.frame_parser_receipt query.role query.target nonce counter

/-- An unparsed source input cannot be one of the grouped current challenge
coordinates. It therefore has its own literal complement representative. -/
theorem current_unparsed_input_is_complement (raw : G.RawInput)
    (unparsed : C.parseCurrentStageQuery raw = none) :
    ¬∃ pair : G.Prefix × G.Counter, G.groupEncode pair = raw := by
  rintro ⟨⟨«prefix», counter⟩, same⟩
  obtain ⟨query, parsed, _⟩ := current_prefix_counter_parser «prefix» counter
  rw [same, unparsed] at parsed
  contradiction

theorem current_unparsed_representative_and_coordinate (raw : G.RawInput)
    (unparsed : C.parseCurrentStageQuery raw = none) :
    G.representative (G.groupKeyOf raw) = raw ∧ G.coordinate raw = G.zero := by
  let complement : G.ComplementKey := ⟨raw, current_unparsed_input_is_complement raw unparsed⟩
  have located := G.address_complement complement
  have key : G.groupKeyOf raw = Sum.inr complement := congrArg Prod.fst located
  have coordinate : G.coordinate raw = G.zero := congrArg Prod.snd located
  refine ⟨?_, coordinate⟩
  rw [key]
  rfl

/-- Every actual non-challenge source call retains its literal bytes and
counter-zero digest in this same Program's finite grouped universe. -/
theorem current_recorded_source_key_and_decoder {Result : Type}
    (program : Program Result) (branch : Branches G.decode program)
    (call : G.RawInput × VectorOutput G.Counter)
    (recorded : call ∈ answerLog G.decode program branch)
    (unparsed : C.parseCurrentStageQuery call.1 = none) :
    G.keyBytes program (G.encode program call.1) = call.1 ∧
      G.decode call.1 call.2 = vectorOutputBytes G.zero call.2 := by
  have reachable := SmzaRp05CurrentFiniteGroupedProgram.answer_log_input_reachable
    G.decode program branch call recorded
  have included := G.included_encode_of_reachable program call.1 reachable
  obtain ⟨representative, coordinate⟩ :=
    current_unparsed_representative_and_coordinate call.1 unparsed
  constructor
  · change G.representative (G.included program (G.encode program call.1)) = call.1
    rw [included]
    exact representative
  · simp only [G.decode, coordinate]

theorem current_claimed_source_record_is_in_database {Result : Type}
    (program : Program Result) (branch : Branches G.decode program)
    (database : Database (G.Key program) (VectorOutput G.Counter))
    (claims : ClaimsDatabaseEvent (Q.fullClaims program branch) database)
    (call : G.RawInput × VectorOutput G.Counter)
    (recorded : call ∈ answerLog G.decode program branch)
    (unparsed : C.parseCurrentStageQuery call.1 = none) :
    (call.1, G.decode call.1 call.2) ∈
      rawRecords (G.keyBytes program) (vectorOutputBytes G.zero) database := by
  obtain ⟨keyBytes, decoder⟩ :=
    current_recorded_source_key_and_decoder program branch call recorded unparsed
  have stored := Q.current_claims_store_every_branch_vector program branch database claims call recorded
  rw [decoder]
  have member : (G.keyBytes program (G.encode program call.1), vectorOutputBytes G.zero call.2) ∈
      rawRecords (G.keyBytes program) (vectorOutputBytes G.zero) database := by
    letI : DecidableEq G.RawInput := V8Smz9CoherentMerkleInstrument.instDecidableEqRawInput
    simp only [rawRecords]
    apply Finset.mem_image.mpr
    exact ⟨(G.encode program call.1, call.2), Finset.mem_filter.mpr
      ⟨Finset.mem_univ _, stored⟩, rfl⟩
  simpa only [keyBytes] using member

/-- Erasing the literal current challenge frames preserves extraction. This
says nothing about the unfiltered RR.priorInput any-preimage selector. -/
theorem current_extract_erases_challenge_records (records : RawRecords)
    (fuel : Nat) (stage : F.Stage) (target : G.RawDigest) :
    extract F.rawNext
      (records.filter fun record => C.parseCurrentStageQuery record.1 = none)
      fuel stage target = extract F.rawNext records fuel stage target := by
  convert (SmzaRp05ChallengeRecordErasure.extract_filter_inert F.rawNext records
    (fun input => C.parseCurrentStageQuery input = none)
    (by
      intro input notKept stage
      cases parsed : C.parseCurrentStageQuery input with
      | none => exact (notKept parsed).elim
      | some query => exact I.current_parsed_challenge_has_no_source_edges stage input query parsed)
    fuel stage target) using 1; congr 1; ext record; simp

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentComplementReadback
