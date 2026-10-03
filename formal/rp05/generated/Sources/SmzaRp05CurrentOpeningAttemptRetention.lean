import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp05ExecutablePcsClosureOpening
import SmzaRp05ExecutableMerklePaths
import SmzaRp05CurrentOpeningProgram
import SmzaRp05ExecutablePcsClosureStatement
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentPrequeryChronology

/-! For each failed nonce before the successful source opening, the actual
canonical-opening execution has retained at least one call from that
nonce's current opening-counter frame.  This is a record-membership fact
from the executed program, not a caller-supplied opened-log premise. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningAttemptRetention

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages canonicalOpening openingScan openingAttempt transcriptProgram verifierProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureOpening (DecodedAt)
open SmzaRp05CurrentExecutedOpeningOutput (execution_stages_current_raw_opening)
open SmzaRp05CurrentPrequeryChronology (transcript_q38_record_split)
open SmzaRp05CurrentOpeningProgram
  (openingCounterInput openingFieldInputs decodeOpeningWords current_nonce_and_cap)
open SmzaRp05ExecutableChallengeStage
  (fieldLoop field_loop_executes_scan returnedWords pendingFailure)
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawInput RawDigest)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
noncomputable section

private theorem opening_attempt_first_query_retained
    (pending : Bool) (digest : RawDigest) (nonce : Nat) (oracle : Oracle)
    (decoded : DecodedAt oracle digest nonce none) :
    ∃ counter, counter < 5 ∧
      (openingCounterInput digest nonce counter, oracle
        (openingCounterInput digest nonce counter)) ∈
          ((openingAttempt pending digest nonce).record oracle).2 := by
  rcases decoded with ⟨words, scanEq, decodeNone⟩
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
        (decodeOpeningWords (returnedWords 6 sampled), pendingFailure pending sampled)))
      (some words) fieldLoopEval (by simpa only [inputsEq] using headRecorded)
  refine ⟨counter, counterBound, ?_⟩
  simpa only [inputEq] using inAttempt

set_option maxHeartbeats 1000000 in
set_option maxRecDepth 12000 in
/-- Every nonce in a failed prefix contributes its actual first raw read to
the `openingScan` log. A successful scan result at that nonce ensures the
source sampler completed; `opening_attempt_first_query_retained` then follows
the literal `fieldLoop`/`Program.record` semantics. -/
private theorem opening_scan_prefix_first_calls_retained
    (digest : RawDigest) (nonces : List Nat) (pending : Bool) (oracle : Oracle)
    (selected : Nat) (opening : Opening) (finalPending : Bool)
    (before after : List Nat)
    (scanned : (openingScan digest nonces pending).eval oracle =
      some (selected, opening, finalPending))
    (order : nonces = before ++ selected :: after)
    (prior : ∀ nonce ∈ before, DecodedAt oracle digest nonce none) :
    ∀ nonce ∈ before, ∃ counter, counter < 5 ∧
      (openingCounterInput digest nonce counter,
        oracle (openingCounterInput digest nonce counter)) ∈
          ((openingScan digest nonces pending).record oracle).2 := by
  induction before generalizing nonces pending with
  | nil =>
      intro nonce member
      simp at member
  | cons head tail ih =>
      have noncesForm : nonces = head :: (tail ++ selected :: after) := by
        rw [order]
        rfl
      subst nonces
      have decodedHead : DecodedAt oracle digest head none :=
        prior head (by simp)
      let continuation : Option Opening × Bool → Program (Nat × Opening × Bool) :=
        fun pair => match pair.1 with
          | none => openingScan digest (tail ++ selected :: after) pair.2
          | some value => .done (some (head, value, pair.2))
      have scanStep : openingScan digest ((head :: tail) ++ selected :: after) pending =
          (openingAttempt pending digest head).bind continuation := rfl
      have scannedBind :
          ((openingAttempt pending digest head).bind continuation).eval oracle =
            some (selected, opening, finalPending) := by
        have scanned' := scanned
        rw [scanStep] at scanned'
        exact scanned'
      obtain ⟨attemptResult, attempted, continued⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (openingAttempt pending digest head) continuation
          (selected, opening, finalPending) scannedBind
      have attemptNone : attemptResult.1 = none := by
        rcases decodedHead with ⟨words, scanEq, decodeNone⟩
        have attemptShape :
            (openingAttempt pending digest head).eval oracle =
              some (none, pendingFailure pending (some words)) := by
          rw [SmzaRp05ExecutablePcsClosureOpening.opening_attempt_exact, scanEq]
          simp only [decodeNone, returnedWords, Option.getD_some]
        have pairEq : attemptResult = (none, pendingFailure pending (some words)) :=
          Option.some.inj (attempted.symm.trans attemptShape)
        rw [pairEq]
      have tailScanned :
          (openingScan digest (tail ++ selected :: after) attemptResult.2).eval oracle =
            some (selected, opening, finalPending) := by
        have continuationNone : continuation attemptResult =
            openingScan digest (tail ++ selected :: after) attemptResult.2 := by
          simp only [continuation, attemptNone]
        rw [continuationNone] at continued
        exact continued
      have headCall := opening_attempt_first_query_retained pending digest head oracle
        decodedHead
      intro nonce member
      rcases List.mem_cons.mp member with same | below
      · subst nonce
        obtain ⟨counter, bound, recorded⟩ := headCall
        refine ⟨counter, bound, ?_⟩
        have included := Program.bind_log_left oracle
          (openingAttempt pending digest head) continuation attemptResult attempted recorded
        rw [scanStep]
        exact included
      · obtain ⟨counter, bound, recorded⟩ :=
          ih (tail ++ selected :: after) attemptResult.2 tailScanned rfl (by
              intro next nextMember
              exact prior next (by simp [nextMember])) nonce below
        refine ⟨counter, bound, ?_⟩
        have recordedContinuation :
            (openingCounterInput digest nonce counter,
              oracle (openingCounterInput digest nonce counter)) ∈
                ((continuation attemptResult).record oracle).2 := by
          simpa only [continuation, attemptNone] using recorded
        have included := Program.bind_log_right oracle
          (openingAttempt pending digest head) continuation attemptResult attempted
          recordedContinuation
        rw [scanStep]
        exact included

/-- A successful current canonical-opening execution retains a counter call
for every failed nonce before its selected nonce. The returned nonce order
and failure evidence come from the existing same-execution readback theorem;
this lemma adds only actual record membership. -/
theorem successful_canonical_opening_retains_failed_nonce_calls
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : ReconstructedTranscript)
    (stages : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (openingClean : stages.openingPending = false) :
    ∃ before after,
      List.range 16 = before ++ nonce.val :: after ∧
      ∀ earlier ∈ before, ∃ counter, counter < 5 ∧
        (openingCounterInput wire.hPiop earlier counter,
          oracle (openingCounterInput wire.hPiop earlier counter)) ∈
            ((canonicalOpening pending nonce wire.hPiop).record oracle).2 := by
  obtain ⟨before, after, order, prior, _, _⟩ :=
    execution_stages_current_raw_opening ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript stages openingClean
  have canonicalEval := stages.openingExecuted
  obtain ⟨scannedResult, scanEval, continuationEval⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (openingScan wire.hPiop (List.range 16) pending)
      (fun (expected, _, nextPending) =>
        if nonce.val = expected then
          (openingAttempt nextPending wire.hPiop nonce.val).bind
            fun (opening, finalPending) =>
              .done (opening.map fun points => (points, finalPending))
        else .done none)
      (stages.opening, stages.openingPending) (by
        simpa only [canonicalOpening] using canonicalEval)
  rcases scannedResult with ⟨selected, selectedOpening, scanPending⟩
  have selectedEq : selected = nonce.val := by
    by_cases equal : nonce.val = selected
    · exact equal.symm
    · simp only [if_neg equal, Program.eval] at continuationEval
      cases continuationEval
  have scanOrder : List.range 16 = before ++ selected :: after := by
    simpa only [selectedEq] using order
  have scanPrior : ∀ earlier ∈ before, DecodedAt oracle wire.hPiop earlier none := prior
  have retained := opening_scan_prefix_first_calls_retained wire.hPiop
    (List.range 16) pending oracle selected selectedOpening scanPending before after
    scanEval scanOrder scanPrior
  have scanLogInCanonical : ((openingScan wire.hPiop (List.range 16) pending).record oracle).2 ⊆
      ((canonicalOpening pending nonce wire.hPiop).record oracle).2 := by
    exact Program.bind_log_left oracle (openingScan wire.hPiop (List.range 16) pending)
      (fun result =>
        let (expected, _, nextPending) := result
        if nonce.val = expected then
          (openingAttempt nextPending wire.hPiop nonce.val).bind fun (opening, finalPending) =>
            .done (opening.map fun points => (points, finalPending))
        else .done none)
      (selected, selectedOpening, scanPending) scanEval
  refine ⟨before, after, order, ?_⟩
  intro earlier member
  obtain ⟨counter, bound, recorded⟩ := retained earlier member
  exact ⟨counter, bound, scanLogInCanonical recorded⟩

/-- Lift failed-prefix calls from the canonical-opening subprogram into the
same verifier transcript and verifier records. `transcriptSuccess` is the
ordinary successful execution equation; it is normally extracted directly
from `ExecutionStages` in accepted grouped replay. -/
theorem successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record
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
    ∃ before after,
      List.range 16 = before ++ nonce.val :: after ∧
      ∀ earlier ∈ before, ∃ counter, counter < 5 ∧
        (openingCounterInput wire.hPiop earlier counter,
          oracle (openingCounterInput wire.hPiop earlier counter)) ∈
            ((verifierProgram ns dsl statement pending statement.toBytes
              (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
              nonce wire).record oracle).2 := by
  obtain ⟨before, after, order, failedCalls⟩ :=
    successful_canonical_opening_retains_failed_nonce_calls ns dsl statement pending
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
  refine ⟨before, after, order, ?_⟩
  intro earlier member
  obtain ⟨counter, bound, recorded⟩ := failedCalls earlier member
  have inTranscript :
      (openingCounterInput wire.hPiop earlier counter,
        oracle (openingCounterInput wire.hPiop earlier counter)) ∈
        ((transcriptProgram ns dsl statement pending statement.toBytes
          (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
          nonce wire).record oracle).2 := by
    rw [transcriptSplit]
    exact List.mem_append_left _ (List.mem_append_left _
      (List.mem_append_left _ (List.mem_append_left _ recorded)))
  exact ⟨counter, bound, transcriptInVerifier inTranscript⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningAttemptRetention
