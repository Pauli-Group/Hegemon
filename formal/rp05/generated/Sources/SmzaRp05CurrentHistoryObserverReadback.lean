import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentProofWireProgram
import SmzaRp05ExecutableProgramEquality
import SmzaRp05PhysicalAcceptedReplayLite

/-! # Exact terminal history-stage readback

From one accepted branch of the ordered history, extract the original
producer wire and stage-verifier branch, then append that exact indexed
prefix as a terminal observer.  The result reuses branch answers already
present in the chronology; it does not posit a fresh oracle or caller-chosen
replay branch.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryObserverReadback

open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult answerLog)
open SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch sequentialUnitBranch_result
    sequentialUnitBranch_answerLog sequentialUnitBranch_split)
open SmzaRp05ExecutableProgramEquality
  (castProgramBranch answerLog_cast_program branchResult_cast_program)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram historyPrefixAt retainedPrefixAt
    stageVerifierAt indexedStageVerifierProgram terminalHistoryStageObserver
    indexedStageVerifierProgram_eq_prefixAt)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open V8SmzaOracleParser (RawInput RawDigest)
open scoped Classical

noncomputable section
set_option autoImplicit false

variable {Output : Type} [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable (decode : RawInput → Output → RawDigest)

private theorem history_take_drop_eq (stages : List HistoryStage)
    (i : Fin stages.length) :
    historyProgram stages =
      (historyProgram (stages.take (i.val + 1))).bind
        (fun _ => historyProgram (stages.drop (i.val + 1))) := by
  calc
    historyProgram stages =
        historyProgram ((stages.take (i.val + 1)) ++ (stages.drop (i.val + 1))) :=
      congrArg historyProgram (List.take_append_drop (i.val + 1) stages).symm
    _ = (historyProgram (stages.take (i.val + 1))).bind
        (fun _ => historyProgram (stages.drop (i.val + 1))) :=
      SmzaRp05CurrentHistoryVerifierProgram.historyProgram_append _ _

omit [Fintype Output] [DecidableEq Output] [AddCommGroup Output] in
theorem branchResult_bind_some {α β : Type} (program : Program α)
    (next : α → Program β) (branch : Branches decode (program.bind next))
    (result : β) (accepted : branchResult decode (program.bind next) branch = some result) :
    ∃ (value : α) (programBranch : Branches decode program)
        (nextBranch : Branches decode (next value)),
      branchResult decode program programBranch = some value ∧
      branchResult decode (next value) nextBranch = some result := by
  induction program with
  | done outcome =>
      cases outcome with
      | none => cases branch; cases accepted
      | some value => exact ⟨value, PUnit.unit, branch, rfl, accepted⟩
  | read raw tail ih =>
      rcases branch with ⟨answer, tailBranch⟩
      have acceptedTail :
          branchResult decode ((tail (decode raw answer)).bind next) tailBranch =
            some result := by
        exact accepted
      obtain ⟨value, programBranch, nextBranch, leftAccepted, rightAccepted⟩ :=
        ih (decode raw answer) tailBranch acceptedTail
      exact ⟨value, ⟨answer, programBranch⟩, nextBranch,
        by simpa only [branchResult] using leftAccepted,
        by simpa only [branchResult] using rightAccepted⟩

/-- One accepted full-history branch determines its exact accepted indexed
stage prefix branch and producer wire.  The returned observer branch appends
that already-read prefix; its raw answer-log calls are all calls in the
original history (possibly repeated). -/
theorem accepted_history_has_exact_terminal_stage_observer_with_replay
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches decode (historyProgram stages))
    (historyAccepted : branchResult decode (historyProgram stages) historyBranch = some ()) :
    ∃ observerBranch : Branches decode (terminalHistoryStageObserver stages i),
      branchResult decode (terminalHistoryStageObserver stages i) observerBranch = some () ∧
      (∀ call, call ∈ answerLog decode (terminalHistoryStageObserver stages i) observerBranch →
        call ∈ answerLog decode (historyProgram stages) historyBranch) ∧
      (∃ (wire : ExistingProofFieldView)
          (producerBranch : Branches decode (stages[i.val].proofProducer))
          (verifierBranch : Branches decode (stageVerifierAt stages i wire)),
        branchResult decode (stages[i.val].proofProducer) producerBranch = some wire ∧
        branchResult decode (stageVerifierAt stages i wire) verifierBranch = some ()) ∧
      ∃ replayStageBranch : Branches decode (indexedStageVerifierProgram stages i),
        observerBranch = sequentialUnitBranch decode (historyProgram stages) historyBranch
          (indexedStageVerifierProgram stages i) replayStageBranch ∧
        branchResult decode (indexedStageVerifierProgram stages i) replayStageBranch = some () := by
  let through := historyProgram (stages.take (i.val + 1))
  let after := historyProgram (stages.drop (i.val + 1))
  let throughEq := history_take_drop_eq stages i
  let wholeBindBranch := castProgramBranch decode (historyProgram stages)
    (through.bind fun _ => after) throughEq historyBranch
  have wholeAccepted : branchResult decode (through.bind fun _ => after)
      wholeBindBranch = some () := by
    simpa [wholeBindBranch] using historyAccepted
  obtain ⟨throughBranch, afterBranch, throughAccepted, _afterAccepted,
      wholeSplit⟩ := sequentialUnitBranch_split decode through after wholeBindBranch wholeAccepted
  let prefixEq : historyPrefixAt stages i = indexedStageVerifierProgram stages i :=
    (indexedStageVerifierProgram_eq_prefixAt stages i).symm
  let replayStageBranch := castProgramBranch decode (historyPrefixAt stages i)
    (indexedStageVerifierProgram stages i) prefixEq throughBranch
  have replayStageAccepted : branchResult decode
      (indexedStageVerifierProgram stages i) replayStageBranch = some () := by
    have castResult := branchResult_cast_program decode (historyPrefixAt stages i)
      (indexedStageVerifierProgram stages i) prefixEq throughBranch
    have prefixAccepted : branchResult decode (historyPrefixAt stages i)
        throughBranch = some () := by
      change branchResult decode (historyProgram (stages.take (i.val + 1)))
        throughBranch = some ()
      exact throughAccepted
    exact castResult.trans prefixAccepted
  obtain ⟨wire, retainedPrefixBranch, verifierBranch,
      retainedPrefixAccepted, verifierAccepted⟩ :=
    branchResult_bind_some decode (retainedPrefixAt stages i)
      (fun wire => stageVerifierAt stages i wire) replayStageBranch () replayStageAccepted
  have retainedAsBind :
      retainedPrefixAt stages i =
        (historyProgram (stages.take i.val)).bind
          (fun _ => (stages[i.val]).proofProducer) := rfl
  let retainedBindBranch := castProgramBranch decode (retainedPrefixAt stages i)
    ((historyProgram (stages.take i.val)).bind
      (fun _ => (stages[i.val]).proofProducer)) retainedAsBind retainedPrefixBranch
  have retainedBindAccepted :
      branchResult decode
        ((historyProgram (stages.take i.val)).bind
          (fun _ => (stages[i.val]).proofProducer)) retainedBindBranch = some wire := by
    have castResult := branchResult_cast_program decode (retainedPrefixAt stages i)
      ((historyProgram (stages.take i.val)).bind
        (fun _ => (stages[i.val]).proofProducer)) retainedAsBind retainedPrefixBranch
    exact castResult.trans retainedPrefixAccepted
  obtain ⟨_, _beforeBranch, producerBranch, _beforeAccepted, producerAccepted⟩ :=
    branchResult_bind_some decode (historyProgram (stages.take i.val))
      (fun _ => (stages[i.val]).proofProducer) retainedBindBranch wire retainedBindAccepted
  let observerBranch := sequentialUnitBranch decode (historyProgram stages)
    historyBranch (indexedStageVerifierProgram stages i) replayStageBranch
  have observerAccepted : branchResult decode
      (terminalHistoryStageObserver stages i) observerBranch = some () := by
    change branchResult decode
      (sequentialUnitProgram (historyProgram stages) (indexedStageVerifierProgram stages i))
      (sequentialUnitBranch decode (historyProgram stages) historyBranch
        (indexedStageVerifierProgram stages i) replayStageBranch) = some ()
    rw [sequentialUnitBranch_result]
    rw [historyAccepted, replayStageAccepted]
    rfl
  have answerLogIncl : ∀ call,
      call ∈ answerLog decode (terminalHistoryStageObserver stages i) observerBranch →
        call ∈ answerLog decode (historyProgram stages) historyBranch := by
    intro call member
    have obsAppend := sequentialUnitBranch_answerLog decode (historyProgram stages)
      (indexedStageVerifierProgram stages i) historyBranch replayStageBranch historyAccepted
    have prefixInWhole : ∀ call,
        call ∈ answerLog decode (indexedStageVerifierProgram stages i) replayStageBranch →
        call ∈ answerLog decode (historyProgram stages) historyBranch := by
      intro call prefixMember
      have prefixLogEq : answerLog decode (indexedStageVerifierProgram stages i)
          replayStageBranch = answerLog decode through throughBranch := by
        exact answerLog_cast_program decode (historyPrefixAt stages i)
          (indexedStageVerifierProgram stages i) prefixEq throughBranch
      rw [prefixLogEq] at prefixMember
      have wholeLogEq : answerLog decode (historyProgram stages) historyBranch =
          answerLog decode through throughBranch ++
            answerLog decode after afterBranch := by
        calc
          answerLog decode (historyProgram stages) historyBranch =
              answerLog decode (through.bind fun _ => after) wholeBindBranch :=
            (answerLog_cast_program decode (historyProgram stages)
              (through.bind fun _ => after) throughEq historyBranch).symm
          _ = answerLog decode through throughBranch ++
                answerLog decode after afterBranch := by
            rw [wholeSplit]
            exact sequentialUnitBranch_answerLog decode through after
              throughBranch afterBranch throughAccepted
      rw [wholeLogEq]
      exact List.mem_append.mpr (Or.inl prefixMember)
    change call ∈ answerLog decode
      (sequentialUnitProgram (historyProgram stages) (indexedStageVerifierProgram stages i))
      (sequentialUnitBranch decode (historyProgram stages) historyBranch
        (indexedStageVerifierProgram stages i) replayStageBranch) at member
    rw [obsAppend] at member
    rcases List.mem_append.mp member with original | replayed
    · exact original
    · exact prefixInWhole call replayed
  exact ⟨observerBranch, observerAccepted, answerLogIncl,
    ⟨wire, producerBranch, verifierBranch, producerAccepted, verifierAccepted⟩,
    ⟨replayStageBranch, rfl, replayStageAccepted⟩⟩

/-- Compatibility wrapper retaining the original readback interface. -/
theorem accepted_history_has_exact_terminal_stage_observer
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches decode (historyProgram stages))
    (historyAccepted : branchResult decode (historyProgram stages) historyBranch = some ()) :
    ∃ observerBranch : Branches decode (terminalHistoryStageObserver stages i),
      branchResult decode (terminalHistoryStageObserver stages i) observerBranch = some () ∧
      (∀ call, call ∈ answerLog decode (terminalHistoryStageObserver stages i) observerBranch →
        call ∈ answerLog decode (historyProgram stages) historyBranch) ∧
      ∃ (wire : ExistingProofFieldView)
          (producerBranch : Branches decode (stages[i.val].proofProducer))
          (verifierBranch : Branches decode (stageVerifierAt stages i wire)),
        branchResult decode (stages[i.val].proofProducer) producerBranch = some wire ∧
        branchResult decode (stageVerifierAt stages i wire) verifierBranch = some () := by
  obtain ⟨observerBranch, observerAccepted, answerLogIncl,
      ⟨wire, producerBranch, verifierBranch, producerAccepted, verifierAccepted⟩,
      _replayData⟩ :=
    accepted_history_has_exact_terminal_stage_observer_with_replay decode
      stages i historyBranch historyAccepted
  exact ⟨observerBranch, observerAccepted, answerLogIncl,
    wire, producerBranch, verifierBranch, producerAccepted, verifierAccepted⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryObserverReadback
