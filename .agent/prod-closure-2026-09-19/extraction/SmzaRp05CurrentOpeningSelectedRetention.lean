import SmzaRp05CurrentOpeningAttemptRetention
import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp05ExecutablePcsClosureOpening
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentPrequeryChronology

/-! The successful selected opening attempt itself makes a real raw counter
read.  This is separate from failed-prefix retention and is derived from the
executed canonical-opening program. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningSelectedRetention

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages canonicalOpening openingScan openingAttempt transcriptProgram verifierProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureOpening (DecodedAt)
open SmzaRp05CurrentExecutedOpeningOutput (execution_stages_current_raw_opening)
open SmzaRp05CurrentPrequeryChronology (transcript_q38_record_split)
open SmzaRp05CurrentOpeningProgram
  (openingCounterInput openingFieldInputs current_nonce_and_cap)
open SmzaRp05ExecutableChallengeStage
  (scan fieldLoop field_loop_executes_scan returnedWords pendingFailure)
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
noncomputable section

set_option maxHeartbeats 1000000 in
private theorem opening_attempt_first_query_retained_success
    (pending : Bool) (digest : RawDigest) (nonce : Nat)
    (oracle : Oracle)
    (sampleComplete : ∃ words, scan oracle 6 [] (openingFieldInputs digest nonce) =
      some words) :
    ∃ counter, counter < 5 ∧
      (openingCounterInput digest nonce counter,
        oracle (openingCounterInput digest nonce counter)) ∈
          ((openingAttempt pending digest nonce).record oracle).2 := by
  obtain ⟨words, scanEq⟩ := sampleComplete
  have cap : SmzaRp05CurrentOpeningProgram.openingFieldCap = 5 :=
    current_nonce_and_cap.1
  have nonempty : openingFieldInputs digest nonce ≠ [] := by
    simp [openingFieldInputs, cap]
  obtain ⟨input, rest, inputsEq⟩ := List.exists_cons_of_ne_nil nonempty
  have inputMember : input ∈ openingFieldInputs digest nonce := by
    rw [inputsEq]
    simp
  have mapped : ∃ counter, counter ∈ List.range 5 ∧
      openingCounterInput digest nonce counter = input := by
    rw [openingFieldInputs, cap] at inputMember
    exact List.mem_map.mp inputMember
  obtain ⟨counter, counterMember, inputEq⟩ := mapped
  have counterBound : counter < 5 := List.mem_range.mp counterMember
  have fieldLoopEval :
      (fieldLoop 6 [] (openingFieldInputs digest nonce)).eval oracle =
        some (some words) := by
    rw [field_loop_executes_scan, scanEq]
  have headRecorded : (input, oracle input) ∈
      ((fieldLoop 6 [] (input :: rest)).record oracle).2 := by
    simp [fieldLoop, Program.record]
  have inAttempt : (input, oracle input) ∈
      ((openingAttempt pending digest nonce).record oracle).2 := by
    unfold openingAttempt
    exact Program.bind_log_left oracle (fieldLoop 6 [] (openingFieldInputs digest nonce))
      (fun sampled => .done (some
        (SmzaRp05CurrentOpeningProgram.decodeOpeningWords
          (returnedWords 6 sampled), pendingFailure pending sampled)))
      (some words) fieldLoopEval (by simpa only [inputsEq] using headRecorded)
  refine ⟨counter, counterBound, ?_⟩
  simpa only [inputEq] using inAttempt

/-- In a successful current opening execution, the repeated sample at the
selected nonce retains a real raw opening-counter call in the canonical
opening record.  `openingClean` is the actual clean-stage fact used by the
source readback theorem; it is not a read-membership premise. -/
theorem successful_canonical_opening_retains_selected_nonce_call
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (openingClean : stages.openingPending = false) :
    ∃ counter, counter < 5 ∧
      (openingCounterInput wire.hPiop nonce.val counter,
        oracle (openingCounterInput wire.hPiop nonce.val counter)) ∈
          ((canonicalOpening pending nonce wire.hPiop).record oracle).2 := by
  obtain ⟨_, _, _, _, selectedDecoded, _⟩ :=
    execution_stages_current_raw_opening ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript stages openingClean
  let afterScan : Nat × Opening × Bool → Program (Opening × Bool) :=
    fun result =>
      let (expected, _, nextPending) := result
      if nonce.val = expected then
        (openingAttempt nextPending wire.hPiop nonce.val).bind
          fun (opening, finalPending) =>
            .done (opening.map fun points => (points, finalPending))
      else .done none
  have canonicalForm : canonicalOpening pending nonce wire.hPiop =
      (openingScan wire.hPiop (List.range 16) pending).bind afterScan := rfl
  have canonicalEval := stages.openingExecuted
  rw [canonicalForm] at canonicalEval
  obtain ⟨scanResult, scanEval, continuationEval⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (openingScan wire.hPiop (List.range 16) pending) afterScan
      (stages.opening, stages.openingPending) canonicalEval
  rcases scanResult with ⟨expected, earlierOpening, nextPending⟩
  have selected : nonce.val = expected := by
    by_cases equal : nonce.val = expected
    · exact equal
    · simp only [afterScan, if_neg equal, Program.eval] at continuationEval
      cases continuationEval
  have successfulAttempt :
      ((openingAttempt nextPending wire.hPiop nonce.val).bind
        (fun (opening, finalPending) =>
          .done (opening.map fun points => (points, finalPending)))).eval oracle =
        some (stages.opening, stages.openingPending) := by
    simpa only [afterScan, selected, if_pos] using continuationEval
  obtain ⟨attemptResult, attemptEval, _⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (openingAttempt nextPending wire.hPiop nonce.val)
      (fun (opening, finalPending) =>
        .done (opening.map fun points => (points, finalPending)))
      (stages.opening, stages.openingPending) successfulAttempt
  rcases selectedDecoded with ⟨words, selectedScan, _decodedOpening⟩
  obtain ⟨counter, bound, recorded⟩ :=
    opening_attempt_first_query_retained_success nextPending wire.hPiop nonce.val
      oracle ⟨words, selectedScan⟩
  have continuation : Nat × Opening × Bool → Program (Opening × Bool) := afterScan
  let secondContinuation : Option Opening × Bool → Program (Opening × Bool) :=
    fun pair => .done (pair.1.map fun points => (points, pair.2))
  have continuationAtSelected : afterScan (expected, earlierOpening, nextPending) =
      (openingAttempt nextPending wire.hPiop nonce.val).bind secondContinuation := by
    simp only [afterScan, selected, if_pos, secondContinuation]
  have inContinuation :
      (openingCounterInput wire.hPiop nonce.val counter,
        oracle (openingCounterInput wire.hPiop nonce.val counter)) ∈
          ((afterScan (expected, earlierOpening, nextPending)).record oracle).2 := by
    rw [continuationAtSelected]
    exact Program.bind_log_left oracle (openingAttempt nextPending wire.hPiop nonce.val)
      secondContinuation attemptResult attemptEval recorded
  have inCanonical := Program.bind_log_right oracle
    (openingScan wire.hPiop (List.range 16) pending) afterScan
    (expected, earlierOpening, nextPending) scanEval inContinuation
  rw [canonicalForm]
  exact ⟨counter, bound, inCanonical⟩

/-- Lift the selected-nonce call through the actual transcript and verifier
records. The transcript execution equation is obtained from accepted ordinary
verifier execution; no independent log-membership condition is supplied. -/
theorem successful_canonical_opening_retains_selected_nonce_call_in_verifier_record
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns stages.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows stages.middle.pcs stages.piop)
      stages.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points stages.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle stages.hashFpp stages.pcsPending)
    (openingClean : stages.openingPending = false)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire).eval oracle = some transcript) :
    ∃ counter, counter < 5 ∧
      (openingCounterInput wire.hPiop nonce.val counter,
        oracle (openingCounterInput wire.hPiop nonce.val counter)) ∈
          ((verifierProgram ns dsl statement pending statement.toBytes
            (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
            nonce wire).record oracle).2 := by
  obtain ⟨counter, bound, inCanonical⟩ :=
    successful_canonical_opening_retains_selected_nonce_call ns dsl statement pending
      nonce wire oracle transcript stages openingClean
  have transcriptSplit := transcript_q38_record_split ns dsl statement pending nonce
    wire oracle transcript stages pcs
  have transcriptInVerifier :
      ((transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).record oracle).2 ⊆
        ((verifierProgram ns dsl statement pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire).record oracle).2 := by
    intro call member
    have included := Program.bind_log_left oracle
      (transcriptProgram ns dsl statement pending statement.toBytes
        (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire)
      (SmzaRp05ExecutableFinalVerifier.finalize wire.hPiop)
      transcript transcriptSuccess member
    simpa only [verifierProgram] using included
  have inTranscript :
      (openingCounterInput wire.hPiop nonce.val counter,
        oracle (openingCounterInput wire.hPiop nonce.val counter)) ∈
        ((transcriptProgram ns dsl statement pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire).record oracle).2 := by
    rw [transcriptSplit]
    exact List.mem_append_left _ (List.mem_append_left _
      (List.mem_append_left _ (List.mem_append_left _ inCanonical)))
  exact ⟨counter, bound, transcriptInVerifier inTranscript⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningSelectedRetention
