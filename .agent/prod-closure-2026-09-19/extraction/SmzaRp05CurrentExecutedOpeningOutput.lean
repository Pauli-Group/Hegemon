import SmzaRp05CurrentExecutedEarlierReadback
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentRawFieldScan

/-! # Current executed opening output at the raw-role decoder boundary

This file uses the current SMZA `openingCounterInput` bytes. The historical
opening-key schedule is not used; only its generic scan/parser facts are
reused. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedOpeningOutput

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05CurrentExecutedEarlierReadback
open SmzaRp05CurrentOpeningProgram (openingCounterInput openingFieldInputs openingFieldCap
  decodeOpeningWords)
open SmzaRp05ExecutablePcsClosureOpening (DecodedAt)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp04RawRoleSampling
open SmzaRp05CurrentRawFieldScan (source_field_reader_eq_executable_scan)
open V8Smz9HonestRequestSchedule (NonleafProgram sourceFieldReadLoop sourceDigestWords sourceDigest)
open V8Smz9RawCounterCompiler (acceptedFieldWords decodeFieldWord parseCounterVector digestCallCap)
open SmzaRp05ExecutableChallengeStage (acceptedWords scan)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9CoherentMerkleGeometry (RawDigest)
open V8Smz9HiddenLeafQrom (DigestRegister)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open V8Smz9WholeViewObservation (Sha512Digest)
open V8Smz9PiopSoundness (Opening)

set_option autoImplicit false
noncomputable section

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

private def allAcceptedWords (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (accepted : List V8Smz9WholeViewObservation.FieldWord)
    (inputs : List V8SmzaOracleParser.RawInput) : List V8Smz9WholeViewObservation.FieldWord :=
  accepted ++ (inputs.map fun input => acceptedFieldWords (sourceDigestWords (oracle input))).flatten

private theorem accepted_field_words_append (left right : List Nat) :
    acceptedFieldWords (left ++ right) = acceptedFieldWords left ++ acceptedFieldWords right := by
  simp [acceptedFieldWords]

private theorem accepted_field_words_flatten (words : List (List Nat)) :
    acceptedFieldWords words.flatten = (words.map acceptedFieldWords).flatten := by
  induction words with
  | nil => rfl
  | cons head tail ih => simp [accepted_field_words_append, ih]

private theorem interpret_source_field_read_loop (requested : Nat)
    (accepted : List V8Smz9WholeViewObservation.FieldWord)
    (inputs : List V8SmzaOracleParser.RawInput)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister) :
  NonleafProgram.interpret oracle (sourceFieldReadLoop requested accepted inputs) =
      if requested ≤ (allAcceptedWords oracle accepted inputs).length then
        some ((allAcceptedWords oracle accepted inputs).take requested) else none := by
  induction inputs generalizing accepted with
  | nil =>
      simp only [allAcceptedWords, List.map_nil, List.flatten_nil, List.append_nil]
      change NonleafProgram.interpret oracle
        (if requested ≤ accepted.length then
          (NonleafProgram.done (some (accepted.take requested)) :
            NonleafProgram V8SmzaOracleParser.RawInput
              (Option (List V8Smz9WholeViewObservation.FieldWord)))
          else .done none) = _
      split <;> simp only [NonleafProgram.interpret]
  | cons input rest ih =>
      by_cases enough : requested ≤ accepted.length
      · have enoughAll : requested ≤ (allAcceptedWords oracle accepted (input :: rest)).length := by
          unfold allAcceptedWords
          simp only [List.length_append]
          omega
        change NonleafProgram.interpret oracle
          (if requested ≤ accepted.length then
            (NonleafProgram.done (some (accepted.take requested)) :
              NonleafProgram V8SmzaOracleParser.RawInput
                (Option (List V8Smz9WholeViewObservation.FieldWord)))
            else .read input (fun digest => sourceFieldReadLoop requested
              (accepted ++ acceptedFieldWords (sourceDigestWords digest)) rest)) = _
        rw [if_pos enough]
        simp only [NonleafProgram.interpret]
        rw [if_pos enoughAll]
        unfold allAcceptedWords
        simp only [List.take_append_of_le_length enough]
      · simp only [sourceFieldReadLoop, enough, ↓reduceIte, NonleafProgram.interpret]
        rw [ih]
        simp [allAcceptedWords, List.append_assoc]

private theorem source_field_loop_is_counter_parser {blocks : Nat}
    (requested : Nat) (keys : Fin blocks → V8SmzaOracleParser.RawInput)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister) :
    NonleafProgram.interpret oracle
        (sourceFieldReadLoop requested [] (List.ofFn keys)) =
      parseCounterVector requested (fun counter => sourceDigest (oracle (keys counter))) := by
  rw [interpret_source_field_read_loop]
  unfold parseCounterVector V8Smz9RawCounterCompiler.counterVectorCandidates allAcceptedWords
  simp only [List.nil_append]
  rw [accepted_field_words_flatten]
  simp only [List.map_ofFn, sourceDigestWords]
  rfl

def currentOpeningRawBlocks (oracle : Oracle) (digest : RawDigest) (nonce : Nat) :
    Fin (digestCallCap piopOpenings) → HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.RawByteBlock :=
  fun counter => oracle (openingCounterInput digest nonce counter.val)

def currentOpeningVector (oracle : Oracle) (digest : RawDigest) (nonce : Nat) :
    V8Smz9CoherentVectorMerkle.VectorOutput (Fin (digestCallCap piopOpenings)) :=
  fun counter => rawDigestBits (oracle (openingCounterInput digest nonce counter.val))

private theorem current_opening_scan_eq_raw_sample (oracle : Oracle)
    (digest : RawDigest) (nonce : Nat) :
    scan oracle 6 [] (openingFieldInputs digest nonce) =
      (rawFieldSample (digestCallCap piopOpenings) piopOpenings
        (currentOpeningRawBlocks oracle digest nonce)).map List.ofFn := by
  have cap : openingFieldCap = digestCallCap piopOpenings := by decide
  let keys : Fin (digestCallCap piopOpenings) → V8SmzaOracleParser.RawInput :=
    fun counter => openingCounterInput digest nonce counter.val
  have inputs : openingFieldInputs digest nonce = List.ofFn keys := by
    rw [openingFieldInputs, cap]
    simpa only [keys] using
      (ofFn_fin_val_eq_range_map (n := digestCallCap piopOpenings)
        (f := openingCounterInput digest nonce)).symm
  have reader := source_field_reader_eq_executable_scan 6 []
    (openingFieldInputs digest nonce) id oracle
  have reader' : NonleafProgram.interpret (fun key => rawDigestBits (oracle key))
      (sourceFieldReadLoop 6 [] (openingFieldInputs digest nonce)) =
        scan oracle 6 [] (openingFieldInputs digest nonce) := by
    exact reader.trans (congrArg (scan oracle 6 []) (List.map_id _))
  have byteParser := HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.exact_literal_byte_counter_parser
    6 (currentOpeningRawBlocks oracle digest nonce)
  have sourceBytes :
      (fun counter => HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.sourceDigestOfByteBlock
        (currentOpeningRawBlocks oracle digest nonce counter)) =
        (fun counter => HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule.sourceDigest
          (rawDigestBits (oracle (keys counter)))) := by
    funext counter
    simp [currentOpeningRawBlocks, keys,
      HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.sourceDigestOfByteBlock,
      HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule.sourceDigest,
      rawDigestBits.symm_apply_apply]
  calc
    scan oracle 6 [] (openingFieldInputs digest nonce) =
        NonleafProgram.interpret (fun key => rawDigestBits (oracle key))
          (sourceFieldReadLoop 6 [] (openingFieldInputs digest nonce)) := reader'.symm
    _ = parseCounterVector 6
        (fun counter => HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule.sourceDigest
          (rawDigestBits (oracle (keys counter)))) := by
          rw [inputs]
          exact source_field_loop_is_counter_parser 6 keys
            (fun key => rawDigestBits (oracle key))
    _ = parseCounterVector 6
        (fun counter => HegemonCrypto.SmallWood.V8Smz9CappedRawSampler.sourceDigestOfByteBlock
          (currentOpeningRawBlocks oracle digest nonce counter)) := by
          rw [sourceBytes]
    _ = _ := by
      rw [byteParser]
      rfl

/-- The selected value of the current six-point opening program is exactly
the raw-role opening decoder applied to the same five literal SMZA counter
inputs. Thus the executed first-success witness is also the actual
`actualPiopOpeningOutput`, not a separately framed oracle sample. -/
theorem execution_opening_is_actual_role_output
    (oracle : Oracle) (digest : RawDigest) (nonce : Nat) (opening : Opening)
    (readback : DecodedAt oracle digest nonce (some opening)) :
    actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
      (currentOpeningVector oracle digest nonce) = some opening := by
  obtain ⟨words, scanEq, decoded⟩ := readback
  have sampleEq := current_opening_scan_eq_raw_sample oracle digest nonce
  cases sampled : rawFieldSample (digestCallCap piopOpenings) piopOpenings
      (currentOpeningRawBlocks oracle digest nonce) with
  | none =>
      rw [sampled] at sampleEq
      rw [sampleEq] at scanEq
      cases scanEq
  | some fields =>
      have wordsEq : words = List.ofFn fields := by
        rw [sampleEq, sampled, Option.map_some] at scanEq
        exact (Option.some.inj scanEq).symm
      have decodedFields : openingDecoder fields = some opening := by
        have count : piopOpenings = 6 := SmzaRp04RawRoleSampling.actual_piop_opening_count_is_six
        rw [wordsEq] at decoded
        have decoded' := (show decodeOpeningWords (List.ofFn fields) = some opening from decoded)
        have hlen : (List.ofFn fields).length = 6 := by simp [count]
        have decodedFields' : openingDecoder (fun index =>
            (List.ofFn fields).getD index.val ⟨0, by decide⟩) = some opening := by
          change (if (List.ofFn fields).length = 6 then
            openingDecoder (fun index : Fin piopOpenings =>
              (List.ofFn fields).getD index.val
                (⟨0, by decide⟩ : V8Smz9WholeViewObservation.FieldWord))
            else none) = some opening at decoded'
          rw [if_pos hlen] at decoded'
          exact decoded'
        have hfun : (fun index : Fin piopOpenings =>
            (List.ofFn fields).getD index.val ⟨0, by decide⟩) = fields := by
          funext index
          simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn,
            index.isLt, dif_pos, Option.getD_some]
        rw [hfun] at decodedFields'
        exact decodedFields'
      have selectedEq : selectedRawBlocks
          (Equiv.refl (Fin (digestCallCap piopOpenings)))
          (currentOpeningVector oracle digest nonce) = currentOpeningRawBlocks oracle digest nonce := by
        funext counter
        change rawDigestBits.symm
            (rawDigestBits (oracle (openingCounterInput digest nonce counter.val))) = _
        exact rawDigestBits.symm_apply_apply _
      change (rawFieldSample (digestCallCap piopOpenings) piopOpenings
        (selectedRawBlocks (Equiv.refl (Fin (digestCallCap piopOpenings)))
          (currentOpeningVector oracle digest nonce))).bind openingDecoder = some opening
      rw [selectedEq, sampled]
      exact decodedFields

/-- The actual assembled verifier execution supplies both the first-success
prefix evidence and equality to its real raw-role opening output at that
nonce. The vector coordinates are computed from the same execution oracle
and the current `openingCounterInput` frame. -/
theorem execution_stages_current_raw_opening
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (binding : List Byte) (statementBinding : List Nat)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending binding statementBinding
      nonce wire oracle transcript)
    (openingClean : stages.openingPending = false) :
    ∃ before after,
      List.range 16 = before ++ nonce.val :: after ∧
      (∀ earlier, earlier ∈ before →
        DecodedAt oracle wire.hPiop earlier none) ∧
      DecodedAt oracle wire.hPiop nonce.val (some stages.opening) ∧
      actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector oracle wire.hPiop nonce.val) = some stages.opening := by
  obtain ⟨before, after, decomposition, prior, decoded⟩ :=
    execution_stages_readback_current_opening ns dsl statement pending binding
      statementBinding nonce wire oracle transcript stages openingClean
  exact ⟨before, after, decomposition, prior, decoded,
    execution_opening_is_actual_role_output oracle wire.hPiop nonce.val
      stages.opening decoded⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedOpeningOutput
