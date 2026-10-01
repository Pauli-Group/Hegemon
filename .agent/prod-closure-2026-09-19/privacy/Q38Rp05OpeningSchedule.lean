import Q38Rp05RawInputPartition
import HegemonCrypto.SmallWoodV8Smz9HonestOpeningSchedule
import SmzaChallengeStageTargets

/-!
# SMZA nonce schedule on the corrected physical-input partition

The field sampler and validity predicate are profile-independent. The keys
are not: this schedule constructs SMZA keys in the length-2511 complement.
The historical SMZ9 schedule remains unchanged. Integrating this schedule
with the full request and accepted-execution arguments is still required.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9WholeViewObservation
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

/-- Minimal current-request selector record. This duplicates only the four
fields needed here, rather than importing the historical grouped-suffix
dependency closure. -/
structure Rp05OpeningSelector where
  role : Role
  target : V8SmzaOracleParser.RawDigest
  nonce : Nat
  leading : V8SmzaOracleParser.RawInput
deriving DecidableEq

/-- Exact current parser receipt for a prefix with counter zero. -/
def IsRp05CanonicalRolePrefix (role : Role)
    (leading : V8SmzaOracleParser.RawInput) : Prop :=
  ∃ query, parseStageQuery (leading ++ encodeLE 8 0) = some query ∧ query.role = role

/-- The current source loop's accepted words, retaining every attempted
counter in order. Kept local so this module does not need OpeningReadback. -/
def rp05AllAcceptedWords {Other : Type*}
    (oracle : Other → DigestRegister) (accepted : List FieldWord)
    (inputs : List Other) : List FieldWord :=
  accepted ++
    (inputs.map fun input => acceptedFieldWords (sourceDigestWords (oracle input))).flatten

theorem rp05_accepted_field_words_append (left right : List Nat) :
    acceptedFieldWords (left ++ right) = acceptedFieldWords left ++ acceptedFieldWords right := by
  simp [acceptedFieldWords]

theorem rp05_accepted_field_words_flatten (words : List (List Nat)) :
    acceptedFieldWords words.flatten = (words.map acceptedFieldWords).flatten := by
  induction words with
  | nil => rfl
  | cons head tail ih => simp [rp05_accepted_field_words_append, ih]

theorem rp05_interpret_source_field_read_loop {Other : Type}
    (requested : Nat) (accepted : List FieldWord) (inputs : List Other)
    (oracle : Other → DigestRegister) :
    NonleafProgram.interpret oracle (sourceFieldReadLoop requested accepted inputs) =
      if requested ≤ (rp05AllAcceptedWords oracle accepted inputs).length then
        some ((rp05AllAcceptedWords oracle accepted inputs).take requested) else none := by
  induction inputs generalizing accepted with
  | nil =>
      by_cases enough : requested ≤ accepted.length
      · simp [sourceFieldReadLoop, NonleafProgram.interpret,
          rp05AllAcceptedWords, enough]
      · simp [sourceFieldReadLoop, NonleafProgram.interpret,
          rp05AllAcceptedWords, enough]
  | cons input rest ih =>
      by_cases enough : requested ≤ accepted.length
      · simp [sourceFieldReadLoop, NonleafProgram.interpret, rp05AllAcceptedWords,
          enough, List.take_append_of_le_length, List.length_append]
        omega
      · simp only [sourceFieldReadLoop, enough, ↓reduceIte, NonleafProgram.interpret]
        rw [ih]
        simp [rp05AllAcceptedWords, List.length_append]

/-- A list of fixed counter keys is interpreted by the literal capped field
parser, without importing the historical grouped readback theory. -/
theorem rp05_source_field_loop_is_counter_parser {Other : Type} {blocks : Nat}
    (requested : Nat) (keys : Fin blocks → Other) (oracle : Other → DigestRegister) :
    NonleafProgram.interpret oracle (sourceFieldReadLoop requested [] (List.ofFn keys)) =
      parseCounterVector requested
        (fun counter => sourceDigest (oracle (keys counter))) := by
  rw [rp05_interpret_source_field_read_loop]
  unfold parseCounterVector counterVectorCandidates rp05AllAcceptedWords
  simp only [List.nil_append, List.map_ofFn]
  rw [rp05_accepted_field_words_flatten]
  have sameCounterMap :
      (fun input : Other => acceptedFieldWords (sourceDigestWords (oracle input))) ∘ keys =
        (fun counter : Fin blocks =>
          acceptedFieldWords ((sourceDigest (oracle (keys counter))).rawWords)) := by
    funext counter
    simp only [Function.comp_apply, sourceDigestWords]
  have mapFn :
      acceptedFieldWords ∘ (fun counter : Fin blocks =>
        (sourceDigest (oracle (keys counter))).rawWords) =
      (fun counter : Fin blocks =>
        acceptedFieldWords (sourceDigest (oracle (keys counter))).rawWords) := by
    funext counter
    simp only [Function.comp_apply]
  simp only [sameCounterMap, List.map_ofFn, mapFn]

def rp05OpeningKey (bound : Nat) (largeEnough : 194 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister)
    (counter : Fin (2 ^ 64)) : Rp05OtherRawInput bound :=
  rp05SourceCounterKey bound SmallWoodTranscript.piopOpeningDomain
    (sourceOpeningWords nonce digest)
    (by rw [source_opening_word_count]
        have role : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
        rw [role]
        omega)
    (by rw [source_opening_word_count]
        have role : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
        rw [role]
        decide)
    counter

theorem rp05_opening_key_is_literal (bound : Nat) (largeEnough : 194 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) (counter : Fin (2 ^ 64)) :
    rp05RawBytes (.inr (rp05OpeningKey bound largeEnough nonce digest counter)) =
      counterInput (rp05SourcePrefix SmallWoodTranscript.piopOpeningDomain
        (sourceOpeningWords nonce digest)) counter :=
  rp05_source_counter_key_is_literal_input _ _ _ _ _ _

/-- Every generated nonce/counter is accepted by the current SMZA stage
parser, with the exact encoded target and nonce. No profile equality is
assumed and no accepted-transcript route receipt is needed. -/
theorem rp05_opening_key_stage_roundtrip
    (bound : Nat) (largeEnough : 194 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) (counter : Fin (2 ^ 64)) :
    parseStageQuery
        (rp05RawBytes (.inr (rp05OpeningKey bound largeEnough nonce digest counter))) =
      some ⟨.piopOpening,
        V8SmzaOracleParser.digestAt
          (((sourceOpeningWords nonce digest).map (encodeLE 8)).flatten) 8,
        nonce.val, counter.val⟩ := by
  rw [rp05_opening_key_is_literal]
  let words := sourceOpeningWords nonce digest
  let payload := (words.map (encodeLE 8)).flatten
  have wordCount : words.length = 9 := source_opening_word_count nonce digest
  have payloadCount : payload.length = 72 := by
    have general (items : List Nat) :
        ((items.map (encodeLE 8)).flatten).length = 8 * items.length := by
      induction items with
      | nil => rfl
      | cons item rest ih =>
          simp [encodeLE_length, ih, Nat.mul_add, Nat.add_comm]
    simpa [payload, wordCount] using general words
  have nonceSmall : nonce.val < 256 ^ 8 := by omega
  have nonceWord : V8SmzaOracleParser.wordAt payload 0 = nonce.val := by
    simp [payload, words, sourceOpeningWords, V8SmzaOracleParser.wordAt,
      V8Smz9CoherentMerkleGeometry.wordAt, encodeLE_length,
      decodeLE_encodeLE]; omega
  have profileCount : V8SmzaOracleParser.profileDomain.length = 53 := by decide
  have roleCount : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
  have roleDecoded : decodeChallengeRole SmallWoodTranscript.piopOpeningDomain =
      some .piopOpening := by
    simpa only [roleDomain] using role_roundtrip .piopOpening
  have counterDecoded : decodeLE (List.take 8 (encodeLE 8 counter.val)) = counter.val := by
    rw [List.take_of_length_le (by simp [encodeLE_length]), decodeLE_encodeLE]
    apply Nat.mod_eq_of_lt
    calc
      counter.val < 2 ^ 64 := counter.isLt
      _ = 256 ^ 8 := by norm_num
  simp [parseStageQuery, counterInput, rp05SourcePrefix, readFixed,
    List.append_assoc, encodeLE_length, decodeLE_encodeLE, profileCount,
    roleCount, roleDecoded, wordCount, payloadCount, nonceWord, counterDecoded,
    SmzaChallengeStageTargets.payloadLength,
    SmzaChallengeStageTargets.digestOffset, words, payload]; omega

def rp05OpeningXof (bound : Nat) (largeEnough : 194 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) :
    NonleafProgram (Rp05OtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop 6 [] (List.ofFn fun index : Fin 5 =>
    rp05OpeningKey bound largeEnough nonce digest ⟨index.val, by omega⟩)

/-- Exact field-XOF readback on the corrected current-profile keys. This
keeps rejection as `none` and does not condition on obtaining six words. -/
theorem rp05_opening_xof_is_counter_parser
    (bound : Nat) (largeEnough : 194 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
        (rp05OpeningXof bound largeEnough nonce digest) =
      parseCounterVector 6 (fun counter : Fin 5 => sourceDigest
        (oracle (rp05OpeningKey bound largeEnough nonce digest
          ⟨counter.val, by omega⟩))) := by
  exact rp05_source_field_loop_is_counter_parser 6
    (fun counter : Fin 5 => rp05OpeningKey bound largeEnough nonce digest
      ⟨counter.val, by omega⟩) oracle

def rp05OpeningSelector (nonce : Fin 16) (digest : DigestRegister) : Rp05OpeningSelector where
  role := .piopOpening
  target := V8SmzaOracleParser.digestAt
    (((sourceOpeningWords nonce digest).map (encodeLE 8)).flatten) 8
  nonce := nonce.val
  leading := rp05SourcePrefix SmallWoodTranscript.piopOpeningDomain
    (sourceOpeningWords nonce digest)

/-- Canonicality for all nonce attempts now follows from the SMZA key
constructor, not an impossible equality with the historical SMZ9 prefix. -/
theorem rp05_opening_selector_canonical (nonce : Fin 16) (digest : DigestRegister) :
    IsRp05CanonicalRolePrefix .piopOpening (rp05OpeningSelector nonce digest).leading := by
  refine ⟨⟨.piopOpening, (rp05OpeningSelector nonce digest).target,
    nonce.val, 0⟩, ?_, rfl⟩
  have parsed := rp05_opening_key_stage_roundtrip 194 (by omega)
    nonce digest ⟨0, by norm_num⟩
  rw [rp05_opening_key_is_literal] at parsed
  exact parsed

/-- Literal 0..15 attempts with the repeated selected-nonce XOF and the
same latched failure state. There is no success-conditioned experiment. -/
def rp05ChooseOpeningLoop (bound : Nat) (largeEnough : 194 ≤ bound)
    (digest : DigestRegister) (pending : Bool) : List (Fin 16) →
    NonleafProgram (Rp05OtherRawInput bound) OpeningResult
  | [] => .done ⟨none, pending⟩
  | nonce :: rest =>
      NonleafProgram.bind (rp05OpeningXof bound largeEnough nonce digest) fun sampled =>
        let words := sourceReturnedWords 6 sampled
        let failed := sourcePendingFailure pending sampled
        if sourceOpeningValid words then
          NonleafProgram.bind (rp05OpeningXof bound largeEnough nonce digest) fun repeated =>
            .done ⟨some (nonce, sourceReturnedWords 6 repeated),
              sourcePendingFailure failed repeated⟩
        else rp05ChooseOpeningLoop bound largeEnough digest failed rest

def rp05ChooseOpening (bound : Nat) (largeEnough : 194 ≤ bound)
    (digest : DigestRegister) (pending : Bool) :
    NonleafProgram (Rp05OtherRawInput bound) OpeningResult :=
  rp05ChooseOpeningLoop bound largeEnough digest pending (List.ofFn id)

theorem rp05_choose_opening_loop_transition
    (bound : Nat) (largeEnough : 194 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonce : Fin 16)
    (nonces : List (Fin 16)) (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (rp05ChooseOpeningLoop bound largeEnough digest pending (nonce :: nonces)) =
      let sampled := NonleafProgram.interpret oracle
        (rp05OpeningXof bound largeEnough nonce digest)
      let words := sourceReturnedWords 6 sampled
      let failed := sourcePendingFailure pending sampled
      if sourceOpeningValid words then
        ⟨some (nonce, words), sourcePendingFailure failed sampled⟩
      else NonleafProgram.interpret oracle
        (rp05ChooseOpeningLoop bound largeEnough digest failed nonces) := by
  simp only [rp05ChooseOpeningLoop, NonleafProgram.interpret_bind]
  split
  · rw [NonleafProgram.interpret_bind]
    rfl
  · rfl

theorem rp05_selected_opening_loop_is_valid
    (bound : Nat) (largeEnough : 194 ≤ bound)
    (digest : DigestRegister) (pending : Bool) (nonces : List (Fin 16))
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (nonce : Fin 16) (words : List FieldWord)
    (selected : (NonleafProgram.interpret oracle
      (rp05ChooseOpeningLoop bound largeEnough digest pending nonces)).selected =
        some (nonce, words)) : sourceOpeningValid words = true := by
  induction nonces generalizing pending with
  | nil =>
      simp only [rp05ChooseOpeningLoop, NonleafProgram.interpret] at selected
      cases selected
  | cons attempt rest ih =>
      rw [rp05_choose_opening_loop_transition] at selected
      dsimp only at selected
      split at selected
      · rename_i valid
        have equal := congrArg Prod.snd (Option.some.inj selected)
        dsimp only at equal
        rw [← equal]
        exact valid
      · exact ih _ selected

theorem rp05_selected_opening_is_valid
    (bound : Nat) (largeEnough : 194 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (nonce : Fin 16) (words : List FieldWord)
    (selected : (NonleafProgram.interpret oracle
      (rp05ChooseOpening bound largeEnough digest pending)).selected =
        some (nonce, words)) :
    words.length = 6 ∧ SourceOpeningAdmissible (sourcePointVector words) :=
  (source_opening_valid_characterization words).mp
    (rp05_selected_opening_loop_is_valid bound largeEnough digest pending _
      oracle nonce words selected)

end
end HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
