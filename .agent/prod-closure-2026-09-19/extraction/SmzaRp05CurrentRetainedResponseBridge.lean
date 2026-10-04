import SmzaRp05CurrentPrequeryChronology
import SmzaRp05CurrentResponseInputDecoder
import SmzaRp05ExecutablePcsClosureMca406
import SmzaRp05ExecutablePcsClosureDecsChecks

/-! # Decode a retained response preimage

When a record set fixed before q38 contains the response-hash input and the
record-set-plus-response record is collision-free, its bytes determine the
same five 406-coefficient rows that the accepted restoration serialized.
This yields a response rule constant at q38. This theorem is generic over
that record set: it does not identify a CMS database with a verifier-only
log, and does not claim matrix-role fixedness, quantum freshness, or an
end-to-end soundness bound.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedResponseBridge

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05ExecutableMerkleVerifier (Log Oracle)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05DecsResponseProjection
  (DecodedDecsResponseFields FieldRow responseTranscriptWords)
open SmzaRp05CurrentMaxAgreementRecovery (Coefficients ResponseRule)
open SmzaRp05CurrentAcceptedRoleSupport (responseTranscriptInput)
open SmzaRp05CurrentResponseInputDecoder
  (responseRuleOfRawInputSelection selected_input_response_polynomial_readback)
open SmzaRp05ExecutablePcsClosureMca406 (successful_restore_rows_have_406_coefficients)
open SmzaRp05ExecutablePcsClosureDecsChecks (successful_hash_fpp_program_has_restoration)
open V8SmzaOracleParser (RawDigest RawInput)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

private theorem field_rows_flatten_length (rows : List FieldRow)
    (rowShape : ∀ values, values ∈ rows → values.length = 406) :
    (rows.map fun values => values.map fun value => value.val).flatten.length =
      rows.length * 406 := by
  induction rows with
  | nil => rfl
  | cons head tail ih =>
      have headLength : head.length = 406 := rowShape head (by simp)
      have tailShape : ∀ values, values ∈ tail → values.length = 406 := by
        intro values member
        apply rowShape
        simp [member]
      have tailLength := ih tailShape
      simp only [List.map_cons, List.flatten_cons, List.length_append,
        List.length_map, List.length_cons, headLength, tailLength, Nat.succ_mul]
      omega

/-- A collision-free input in a record set fixed before q38 decodes to
the exact response polynomials restored by this `PcsStages` object. No
`responseAtSample` equation is supplied: it follows from the source hash
serialization, parser round-trip, and the 5-by-406 restoration shape. -/
theorem retained_record_set_has_fixed_response_readback
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : DecodedDecsResponseFields} {points : List Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (priorRecords : Log)
    (hasPriorInput : ∃ input, (input, hashFpp) ∈ priorRecords)
    (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree
      ((priorRecords ++ (stages.hashProgram.record oracle).2).toFinset))
    (coefficients : Coefficients)
    (statementBindingLength : statementBinding.length = 138) :
    ∃ input polynomials,
      (input, hashFpp) ∈ priorRecords ∧
      SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
          some polynomials ∧
      ∀ row : Fin 5,
        HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
          (responseRuleOfRawInputSelection (fun _ : Coefficients => input)
            coefficients) row =
          SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
            (polynomials.getD row.val []) := by
  let responseRows :=
    stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord
  let gamma := SmzaRp05PcsHashFppMiddle.gammaRows stages.post
  let evalPoints := stages.decsPoints.map SmzaRp05ExecutableRestore.toWord
  have preimage :=
    SmzaRp05CurrentAcceptedRoleSupport.accepted_stage_response_preimage_branch
      stages priorRecords
  rcases preimage with noPreimage | collision | retained
  · exact False.elim (noPreimage hasPriorInput)
  · exact False.elim (collision collisionFree)
  · obtain ⟨pcsWords, input, inputMember, wordsFormed, inputFormed⟩ := retained
    obtain ⟨polynomials, restore⟩ := successful_hash_fpp_program_has_restoration
      stages.post.root decs responseRows gamma evalPoints 140 368 statementBinding
      stages.hashProgram stages.responseBuilt
    have shape := successful_restore_rows_have_406_coefficients decs responseRows
      gamma evalPoints polynomials restore
    have restoreSource := restore
    change SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
          some polynomials at restoreSource
    have rowShape : ∀ values, values ∈ polynomials → values.length = 406 := by
      intro values member
      obtain ⟨index, indexBound, valueEq⟩ := List.mem_iff_getElem.mp member
      subst values
      have indexLt : index < 5 := by rw [shape.1] at indexBound; exact indexBound
      have rowLength := shape.2 index indexLt
      rw [List.getD_eq_getElem polynomials [] indexBound] at rowLength
      exact rowLength
    have flattenedLength := field_rows_flatten_length polynomials rowShape
    rw [shape.1] at flattenedLength
    norm_num at flattenedLength
    have pcsWordsEq : pcsWords =
        SmzaRp05ExecutableChallengeStage.digestWords stages.post.root ++
          (polynomials.map fun values => values.map fun value => value.val).flatten := by
      have formed := wordsFormed
      simp only [SmzaRp05DecsResponseProjection.responseTranscriptWords,
        restoreSource, Pure.pure] at formed
      have formedEq := Option.some.inj formed
      simpa only [List.map_flatten] using formedEq.symm
    let serializedWords := pcsWords ++ statementBinding
    have flattenedWordsLength :
        ((polynomials.map fun values => values.map fun value => value.val).flatten).length =
          2030 := by
      simpa only [List.length_flatten, List.map_map, Function.comp_def] using
        flattenedLength
    have wordBound : serializedWords.length < 256 ^ 8 := by
      rw [show serializedWords = pcsWords ++ statementBinding from rfl,
        pcsWordsEq, List.length_append]
      simp only [List.length_append, List.length_map,
        SmzaRp05ExecutableChallengeStage.digestWords, List.length_map,
        List.length_range]
      rw [flattenedWordsLength]
      rw [statementBindingLength]
      norm_num
    have frameEq : input = V8SmzaOracleParser.framedInput
        SmallWoodTranscript.piopInputDomain
        ((serializedWords.map (encodeLE 8)).flatten) := by
      have inputFormed' := inputFormed
      simp only [responseTranscriptInput, wordsFormed,
        Pure.pure] at inputFormed'
      exact (Option.some.inj inputFormed').symm
    let payload := (serializedWords.map (encodeLE 8)).flatten
    have parsed : V8SmzaOracleParser.parseFramed input =
        some (SmallWoodTranscript.piopInputDomain, payload) := by
      rw [frameEq]
      exact SmzaRp05CurrentResponsePrequeryDecode.current_piop_frame_roundtrip
        serializedWords wordBound
    let leading := SmzaRp05ExecutableChallengeStage.digestWords stages.post.root
    let suffix := statementBinding
    have wordsEq : serializedWords =
        leading ++
          ((polynomials.map fun values => values.map fun value => value.val).flatten ++ suffix) := by
      simp [serializedWords, pcsWordsEq, leading, suffix, List.append_assoc]
    have leadingLength : leading.length = 8 := by
      simp [leading, SmzaRp05ExecutableChallengeStage.digestWords]
    refine ⟨input, polynomials, inputMember, restore, ?_⟩
    intro row
    exact selected_input_response_polynomial_readback
      (fun _ : Coefficients => input) coefficients input payload
      serializedWords leading suffix polynomials row wordBound rfl frameEq parsed
      wordsEq leadingLength shape.1 rowShape

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedResponseBridge
