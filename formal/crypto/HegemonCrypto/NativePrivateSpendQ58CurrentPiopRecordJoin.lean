import HegemonCrypto.NativePrivateSpendQ58CurrentPiopRestoration
import HegemonCrypto.NativePrivateSpendQ58CurrentPrequeryEvents
import SmzaRp05CurrentResponsePrequeryDecode

/-! Exact current final PIOP raw record readout. The degree74 nonlinear
coefficients and132 nonconstant linear coefficients are read at the literal
8+207*row offsets from the current1043-word frame. An accepted run binds the
prior record or produces missing/collision alternatives; raw source timing
is not assumed. SOURCE PROPOSAL: no native execution or gate qualification. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopRecordJoin

open Polynomial V8Smz9PiopSoundness
open HegemonCrypto.CanonicalBytes (Byte encodeLE encodeLE_length)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRecordedTracePath
open V8Smz9CoherentMerkleGeometry (wordAt selectedInput)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open scoped Classical BigOperators
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire Transcript Opening PiopFields transcriptWords finalInput reconstruct
    verifierProgram ExecutionStages accepted_execution_has_stages)
end E
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawInput RawDigest rawPayload rawNext roleName frame raw_payload_frame payloadBytes)
end F
namespace R
export NativePrivateSpendQ58CurrentPiopRestoration (response serialized_coefficients)
end R
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false
local instance : DecidableEq F.RawInput :=
  (inferInstance : LinearOrder F.RawInput).toDecidableEq

def payload (raw : F.RawInput) : List Byte :=
  ((F.rawPayload raw).map V8SmzaOracleParser.Payload.bytes).getD []

def nonlinearCoefficients (raw : F.RawInput) (row : Fin 5) : Fin 75 → Goldilocks :=
  fun index => (wordAt (payload raw) (8 + 207 * row.val + index.val) : Goldilocks)

def nonlinearBounded (raw : F.RawInput) :
    V8Smz9McaRecovery.BoundedResponse Goldilocks (Fin 5) 74 :=
  fun row => (Polynomial.degreeLTEquiv Goldilocks 75).symm (nonlinearCoefficients raw row)

/-- This total raw decoder gives every malformed input an algebraic value.
On the good arm its input is derived equal to the actual accepted raw frame. -/
def rawResponse (raw : F.RawInput) : ClaimedTranscript where
  nonlinear row := (nonlinearBounded raw row).val
  nonlinearDegree row :=
    (V8Smz9McaRecovery.bounded_response_degree (nonlinearBounded raw) row).trans (by decide)
  linearHigh row index :=
    (wordAt (payload raw) (8 + 207 * row.val + 75 + index.val) : Goldilocks)

def anyNext (_ : Unit) (_ : F.RawInput) : Option (List (Unit × F.RawDigest)) := some []

def priorInput (records : RawRecords) (target : F.RawDigest) : Option F.RawInput :=
  selectedInput anyNext records () target

def priorResponse (records : RawRecords) (target : F.RawDigest) : ClaimedTranscript :=
  rawResponse ((priorInput records target).getD [])

private def rows (transcript : E.Transcript) : List (List Nat) :=
  List.ofFn fun row : Fin 5 =>
    (List.ofFn (transcript.nonlinear row)).map Fin.val ++
      (List.ofFn (transcript.linearHigh row)).map Fin.val

private theorem rows_shape (transcript : E.Transcript) :
    ∀ values, values ∈ rows transcript → values.length = 207 := by
  intro values member
  obtain ⟨row, rfl⟩ := List.mem_ofFn.mp member
  simp only [List.length_append, List.length_map, List.length_ofFn]

private theorem ofFn_getD_at {α : Type*} {n : Nat}
    (values : Fin n → α) (index : Fin n) (fallback : α) :
    (List.ofFn values).getD index.val fallback = values index := by
  have within : index.val < (List.ofFn values).length := by
    simpa only [List.length_ofFn] using index.isLt
  rw [List.getD_eq_getElem _ _ within]
  exact List.getElem_ofFn within

private theorem row_at (transcript : E.Transcript) (row : Fin 5) :
    (rows transcript).getD row.val [] =
      (List.ofFn (transcript.nonlinear row)).map Fin.val ++
        (List.ofFn (transcript.linearHigh row)).map Fin.val := by
  exact ofFn_getD_at (fun row : Fin 5 =>
    (List.ofFn (transcript.nonlinear row)).map Fin.val ++
      (List.ofFn (transcript.linearHigh row)).map Fin.val) row []

theorem current_final_word_length (transcript : E.Transcript) :
    (E.transcriptWords transcript).length = 1043 := by
  have flat := V8Smz9HonestHashMaterialization.rectangular_flatten_length
    (rows transcript) 207 (rows_shape transcript)
  have digest : (SmzaRp05ExecutableChallengeStage.digestWords transcript.hashFpp).length = 8 := by
    simp [SmzaRp05ExecutableChallengeStage.digestWords]
  change (SmzaRp05ExecutableChallengeStage.digestWords transcript.hashFpp ++
    (rows transcript).flatten).length = 1043
  rw [List.length_append, digest, flat]
  simp [rows]

private theorem encoded_length (words : List Nat) :
    (words.flatMap (encodeLE 8)).length = 8 * words.length := by
  induction words with
  | nil => rfl
  | cons word rest ih =>
      simp only [List.flatMap_cons, List.length_append, encodeLE_length,
        List.length_cons, ih]
      omega

private theorem payload_frame
    (kind : V8SmzaOracleParser.Kind) (count : Nat) (bytes : List Byte)
    (countBound : count < 256 ^ 8)
    (aligned : bytes.length = 8 * count)
    (length : bytes.length = F.payloadBytes kind) :
    payload (F.frame (F.roleName kind) count bytes) = bytes := by
  have parsed := F.raw_payload_frame kind count bytes countBound aligned length
  simp only [payload, parsed, Option.map_some, Option.getD_some]

private theorem payload_words_frame
    (words : List Nat) (wordLength : words.length = 1043) :
    payload (F.frame (F.roleName .piop) 1043 (words.flatMap (encodeLE 8))) =
      words.flatMap (encodeLE 8) := by
  have aligned : (words.flatMap (encodeLE 8)).length = 8 * 1043 :=
    (encoded_length words).trans (congrArg (fun count : Nat => 8 * count) wordLength)
  exact payload_frame .piop 1043 _ (by decide) aligned
    (by simpa only [F.payloadBytes] using aligned)

theorem current_final_payload (transcript : E.Transcript) :
    payload (E.finalInput transcript) =
      (E.transcriptWords transcript).flatMap (encodeLE 8) := by
  exact payload_words_frame (E.transcriptWords transcript)
    (current_final_word_length transcript)

private theorem transcript_cell (transcript : E.Transcript) (row : Fin 5)
    (offset : Fin 207) :
    (E.transcriptWords transcript).getD (8 + 207 * row.val + offset.val) 0 =
      ((List.ofFn (transcript.nonlinear row)).map Fin.val ++
        (List.ofFn (transcript.linearHigh row)).map Fin.val).getD offset.val 0 := by
  have digestLength : (SmzaRp05ExecutableChallengeStage.digestWords transcript.hashFpp).length = 8 := by
    simp [SmzaRp05ExecutableChallengeStage.digestWords]
  have rowBound : row.val < (rows transcript).length := by
    simpa only [rows, List.length_ofFn] using row.isLt
  change (SmzaRp05ExecutableChallengeStage.digestWords transcript.hashFpp ++
    (rows transcript).flatten).getD _ 0 = _
  rw [List.getD_append_right _ _ _ _ (by rw [digestLength]; omega)]
  rw [show 8 + 207 * row.val + offset.val -
      (SmzaRp05ExecutableChallengeStage.digestWords transcript.hashFpp).length =
        row.val * 207 + offset.val by rw [digestLength]; omega]
  rw [V8Smz9HonestHashMaterialization.rectangular_flatten_getD
    (rows transcript) 207 row.val offset.val (rows_shape transcript) rowBound offset.isLt,
    row_at]

private theorem ofFn_map_append_getD_left {α β : Type*} {n : Nat}
    (values : Fin n → α) (mapping : α → β) (right : List β)
    (index : Fin n) (fallback : β) :
    ((List.ofFn values).map mapping ++ right).getD index.val fallback =
      mapping (values index) := by
  have within : index.val < ((List.ofFn values).map mapping).length := by
    simpa only [List.length_map, List.length_ofFn] using index.isLt
  rw [List.getD_append _ _ _ _ within, List.map_ofFn]
  exact ofFn_getD_at (fun i => mapping (values i)) index fallback

private theorem append_ofFn_map_getD_right {α β : Type*} {n : Nat}
    (left : List β) (values : Fin n → α) (mapping : α → β)
    (index : Fin n) (fallback : β) :
    (left ++ (List.ofFn values).map mapping).getD (left.length + index.val) fallback =
      mapping (values index) := by
  rw [List.getD_append_right _ _ _ _ (Nat.le_add_right _ _),
    Nat.add_sub_cancel_left, List.map_ofFn]
  exact ofFn_getD_at (fun i => mapping (values i)) index fallback

theorem current_final_nonlinear_word (transcript : E.Transcript)
    (row : Fin 5) (index : Fin 75) :
    wordAt (payload (E.finalInput transcript)) (8 + 207 * row.val + index.val) =
      (transcript.nonlinear row index).val := by
  have cell := transcript_cell transcript row ⟨index.val, index.isLt.trans (by decide)⟩
  have cellEq : (E.transcriptWords transcript).getD
      (8 + 207 * row.val + index.val) 0 = (transcript.nonlinear row index).val := by
    exact cell.trans (ofFn_map_append_getD_left
      (transcript.nonlinear row) Fin.val
      ((List.ofFn (transcript.linearHigh row)).map Fin.val) index 0)
  have within : 8 + 207 * row.val + index.val < (E.transcriptWords transcript).length := by
    rw [current_final_word_length]
    have rowLt := row.isLt
    have indexLt := index.isLt
    omega
  have bounded : (E.transcriptWords transcript).getD
      (8 + 207 * row.val + index.val) 0 < 256 ^ 8 := by
    rw [cellEq]
    exact lt_trans (transcript.nonlinear row index).isLt (by decide)
  rw [current_final_payload]
  exact (SmzaRp05CurrentResponsePrequeryDecode.word_at_encoded_words
    (E.transcriptWords transcript) _ within bounded).trans cellEq

theorem current_final_linear_word (transcript : E.Transcript)
    (row : Fin 5) (index : Fin 132) :
    wordAt (payload (E.finalInput transcript)) (8 + 207 * row.val + 75 + index.val) =
      (transcript.linearHigh row index).val := by
  have offsetLt : 75 + index.val < 207 := by have bound := index.isLt; omega
  have cell := transcript_cell transcript row ⟨75 + index.val, offsetLt⟩
  have cellEq : (E.transcriptWords transcript).getD
      (8 + 207 * row.val + 75 + index.val) 0 = (transcript.linearHigh row index).val := by
    have lookup := append_ofFn_map_getD_right
      ((List.ofFn (transcript.nonlinear row)).map Fin.val)
      (transcript.linearHigh row) Fin.val index 0
    rw [List.length_map, List.length_ofFn] at lookup
    simpa only [Nat.add_assoc] using cell.trans lookup
  have within : 8 + 207 * row.val + 75 + index.val < (E.transcriptWords transcript).length := by
    rw [current_final_word_length]
    have rowLt := row.isLt
    have indexLt := index.isLt
    omega
  have bounded : (E.transcriptWords transcript).getD
      (8 + 207 * row.val + 75 + index.val) 0 < 256 ^ 8 := by
    rw [cellEq]
    exact lt_trans (transcript.linearHigh row index).isLt (by decide)
  rw [current_final_payload]
  exact (SmzaRp05CurrentResponsePrequeryDecode.word_at_encoded_words
    (E.transcriptWords transcript) _ within bounded).trans cellEq

private theorem rawResponse_nonlinear_coeff
    (raw : F.RawInput) (row : Fin 5) (index : Fin 75) :
    ((rawResponse raw).nonlinear row).coeff index.val =
      (wordAt (payload raw) (8 + 207 * row.val + index.val) : Goldilocks) := by
  have inverse := congrFun
    ((Polynomial.degreeLTEquiv Goldilocks 75).apply_symm_apply
      (nonlinearCoefficients raw row)) index
  change ((rawResponse raw).nonlinear row).coeff index.val =
    (wordAt (payload raw) (8 + 207 * row.val + index.val) : Goldilocks) at inverse
  exact inverse

private theorem claimedTranscript_ext_fields
    (left right : ClaimedTranscript)
    (nonlinear : ∀ row, left.nonlinear row = right.nonlinear row)
    (linear : ∀ row index, left.linearHigh row index = right.linearHigh row index) :
    left = right := by
  cases left with
  | mk lnl lbound ll =>
      cases right with
      | mk rnl rbound rl =>
          have nl : lnl = rnl := funext nonlinear
          have lh : ll = rl := funext (fun row => funext (linear row))
          cases nl
          cases lh
          rfl

/-- The literal final raw decoder restores the actual reconstructed PIOP
polynomials, including every omitted-linear-constant input. -/
theorem current_final_raw_response
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (matrix : Matrix 1344594) (opening : E.Opening) (proof : E.PiopFields)
    (hash : F.RawDigest) (pending : Bool) :
    rawResponse (E.finalInput (E.reconstruct relation matrix opening proof hash pending)) =
      R.response relation matrix opening proof := by
  have serialized := R.serialized_coefficients relation matrix opening proof hash pending
  let transcript := E.reconstruct relation matrix opening proof hash pending
  have nonlinear : ∀ row,
      (rawResponse (E.finalInput transcript)).nonlinear row =
        (R.response relation matrix opening proof).nonlinear row := by
    intro row
    apply Polynomial.ext
    intro degree
    by_cases within : degree < 75
    · let index : Fin 75 := ⟨degree, within⟩
      rw [rawResponse_nonlinear_coeff (E.finalInput transcript) row index]
      rw [current_final_nonlinear_word, serialized.1 row index]
      exact ZMod.natCast_zmod_val
        (n := Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus)
        (((R.response relation matrix opening proof).nonlinear row).coeff index.val : Goldilocks)
    · have leftDegree :
          ((rawResponse (E.finalInput transcript)).nonlinear row).natDegree ≤ 74 :=
        V8Smz9McaRecovery.bounded_response_degree (nonlinearBounded (E.finalInput transcript)) row
      have rightDegree : ((R.response relation matrix opening proof).nonlinear row).natDegree ≤ 74 :=
        NativePrivateSpendQ58CurrentExecutableVerifier.nonlinear_polynomial_degree opening proof _ row
      rw [Polynomial.coeff_eq_zero_of_natDegree_lt (by omega),
        Polynomial.coeff_eq_zero_of_natDegree_lt (by omega)]
  have linear : ∀ row index,
      (rawResponse (E.finalInput transcript)).linearHigh row index =
        (R.response relation matrix opening proof).linearHigh row index := by
    intro row index
    change (wordAt (payload (E.finalInput transcript)) _ : Goldilocks) = _
    rw [current_final_linear_word, serialized.2 row index]
    exact ZMod.natCast_zmod_val
      (n := Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus)
      ((R.response relation matrix opening proof).linearHigh row index : Goldilocks)
  exact claimedTranscript_ext_fields
    (rawResponse (E.finalInput transcript))
    (R.response relation matrix opening proof) nonlinear linear

/-- Actual accepted final record binds the earlier selected raw PIOP input
or yields the literal absent-preimage/collision alternatives. No transcript
or desired readout equality is a premise. -/
theorem accepted_current_final_binds_prior_response_or_bad
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (prior : RawRecords)
    (accepted : (E.verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    (¬ ∃ raw, (raw, wire.hPiop) ∈ prior) ∨
    (¬ RecordsCollisionFree
      (prior ∪ ((E.verifierProgram ns relation pending nonce wire).record oracle).2.toFinset)) ∨
    ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
      transcript.pending = false ∧
      (E.finalInput transcript, wire.hPiop) ∈ prior ∧
      priorResponse prior wire.hPiop =
        R.response relation stages.matrix stages.opening stages.decoded.piop := by
  obtain ⟨transcript, ⟨stages⟩, clean, _digestEq, finalRecorded⟩ :=
    E.accepted_execution_has_stages ns relation pending nonce wire oracle accepted
  by_cases present : ∃ raw, (raw, wire.hPiop) ∈ prior
  · by_cases free : RecordsCollisionFree
        (prior ∪ ((E.verifierProgram ns relation pending nonce wire).record oracle).2.toFinset)
    · obtain ⟨raw, recorded⟩ := present
      have same := free raw (E.finalInput transcript) wire.hPiop
        (Finset.mem_union_left _ recorded)
        (Finset.mem_union_right _ (List.mem_toFinset.mpr finalRecorded))
      have actual : (E.finalInput transcript, wire.hPiop) ∈ prior := by simpa [same] using recorded
      have priorFree : RecordsCollisionFree prior := by
        intro left right output lm rm
        exact free left right output (Finset.mem_union_left _ lm) (Finset.mem_union_left _ rm)
      have selected := selected_input_of_recorded anyNext prior priorFree () wire.hPiop
        (E.finalInput transcript) actual (by simp [anyNext])
      refine Or.inr (Or.inr ⟨transcript, stages, clean, actual, ?_⟩)
      rw [priorResponse, priorInput, selected, Option.getD_some]
      exact
        (congrArg (fun value : E.Transcript => rawResponse (E.finalInput value))
          stages.reconstructed).symm.trans
        (current_final_raw_response relation stages.matrix stages.opening
          stages.decoded.piop stages.pcs.hashFpp stages.finalPending)
    · exact Or.inr (Or.inl free)
  · exact Or.inl present

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopRecordJoin
