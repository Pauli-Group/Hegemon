import SmzaRp05CurrentHistoryObserverReadback
import SmzaRp05CurrentHistoryVerifierProgram
import SmzaRp05CurrentJointAcceptedExecution
import SmzaRp05CurrentPhysicalBranchClaimReadback
import SmzaRp05CurrentVerifierReplay
import SmzaRp05PhysicalAcceptedReplayLite
import HegemonCrypto.CmsOracleSimulation

/-! # Same-key terminal history observer state replay

An indexed terminal verifier replay uses the actual branch answers from the
accepted history.  Its claims are therefore already known in the original
history's final standard view, and replay is the identity on that same global
key space. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryObserverStateReplay

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult answerLog branchKeys branchAnswers branchClaims physicalRun
    branch_claims_eq_answer_log KnownAt)
open SmzaRp05CurrentJointAcceptedExecution
  (sequentialUnitProgram sequentialUnitBranch sequentialUnitBranch_answerLog
    sequentialUnitBranch_physicalRun)
open SmzaRp05CurrentHistoryVerifierProgram
  (HistoryStage historyProgram terminalHistoryStageObserver indexedStageVerifierProgram
    stageVerifierAt)
open SmzaRp05CurrentHistoryObserverReadback
  (accepted_history_has_exact_terminal_stage_observer_with_replay)
open SmzaRp05CurrentVerifierReplay (physicalRun_eq_self_on_known_branch)
open SmzaRp05CurrentPhysicalBranchClaimReadback
  (physical_branch_claim_known_at_standard)
open V8SmzaOracleParser (RawInput RawDigest)
open scoped Classical

noncomputable section
set_option autoImplicit false

variable {Key Output Phase Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]

/-- The accepted terminal stage observer reuses the original history branch
and adds only a readback of its retained prefix.  The whole observer run is
the original history state, pointwise for every initial state and on the same
global key encoding. -/
theorem accepted_history_terminal_observer_state_replay
    (encode : RawInput → Key) (decode : RawInput → Output → RawDigest)
    (stages : List HistoryStage) (i : Fin stages.length)
    (historyBranch : Branches decode (historyProgram stages))
    (historyAccepted : branchResult decode (historyProgram stages) historyBranch = some ())
    (initial : State Key Output Phase Work) :
    ∃ observerBranch : Branches decode (terminalHistoryStageObserver stages i),
      branchResult decode (terminalHistoryStageObserver stages i) observerBranch = some () ∧
      (∀ call, call ∈ answerLog decode (terminalHistoryStageObserver stages i) observerBranch →
        call ∈ answerLog decode (historyProgram stages) historyBranch) ∧
      physicalRun encode decode (terminalHistoryStageObserver stages i) observerBranch initial =
        physicalRun encode decode (historyProgram stages) historyBranch initial := by
  obtain ⟨observerBranch, observerAccepted, observerLogSubset,
      _stageReadback, ⟨replayStageBranch, observerBranchEq, replayStageAccepted⟩⟩ :=
    accepted_history_has_exact_terminal_stage_observer_with_replay decode
      stages i historyBranch historyAccepted
  let historyState := physicalRun encode decode (historyProgram stages) historyBranch initial
  have replayLogSubset : ∀ call,
      call ∈ answerLog decode (indexedStageVerifierProgram stages i) replayStageBranch →
      call ∈ answerLog decode (historyProgram stages) historyBranch := by
    intro call member
    have observerIncludesReplay :
        call ∈ answerLog decode (terminalHistoryStageObserver stages i) observerBranch := by
      rw [observerBranchEq]
      change call ∈ answerLog decode
        (sequentialUnitProgram (historyProgram stages) (indexedStageVerifierProgram stages i))
        (sequentialUnitBranch decode (historyProgram stages) historyBranch
          (indexedStageVerifierProgram stages i) replayStageBranch)
      rw [sequentialUnitBranch_answerLog decode (historyProgram stages)
        (indexedStageVerifierProgram stages i) historyBranch replayStageBranch historyAccepted]
      exact List.mem_append.mpr (Or.inr member)
    exact observerLogSubset call observerIncludesReplay
  have replayClaimsSubset :
      branchClaims (branchKeys encode decode (indexedStageVerifierProgram stages i)
        replayStageBranch)
        (branchAnswers encode decode (indexedStageVerifierProgram stages i) replayStageBranch) ⊆
      branchClaims (branchKeys encode decode (historyProgram stages) historyBranch)
        (branchAnswers encode decode (historyProgram stages) historyBranch) := by
    intro claim member
    rw [branch_claims_eq_answer_log encode decode
      (indexedStageVerifierProgram stages i) replayStageBranch] at member
    rw [branch_claims_eq_answer_log encode decode (historyProgram stages) historyBranch]
    rcases List.mem_map.mp member with ⟨call, callMember, rfl⟩
    exact List.mem_map.mpr ⟨call, replayLogSubset call callMember, rfl⟩
  have originalClaimsKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode (historyProgram stages) historyBranch)
        (branchAnswers encode decode (historyProgram stages) historyBranch) →
      KnownAt claim.1 claim.2 (globalDecompress historyState) := by
    intro claim member
    simpa [historyState] using
      physical_branch_claim_known_at_standard encode decode
        (historyProgram stages) historyBranch initial claim member
  have replayClaimsKnown : ∀ claim,
      claim ∈ branchClaims (branchKeys encode decode (indexedStageVerifierProgram stages i)
        replayStageBranch)
        (branchAnswers encode decode (indexedStageVerifierProgram stages i) replayStageBranch) →
      KnownAt claim.1 claim.2 (globalDecompress historyState) := by
    intro claim member
    exact originalClaimsKnown claim (replayClaimsSubset member)
  have replayIdentity := physicalRun_eq_self_on_known_branch encode decode
    (indexedStageVerifierProgram stages i) replayStageBranch historyState replayClaimsKnown
  have observerRun :
      physicalRun encode decode (terminalHistoryStageObserver stages i) observerBranch initial =
        physicalRun encode decode (indexedStageVerifierProgram stages i) replayStageBranch
          (physicalRun encode decode (historyProgram stages) historyBranch initial) := by
    rw [observerBranchEq]
    exact sequentialUnitBranch_physicalRun decode encode
      (historyProgram stages) (indexedStageVerifierProgram stages i)
      historyBranch replayStageBranch historyAccepted initial
  exact ⟨observerBranch, observerAccepted, observerLogSubset, by
    simpa [historyState] using observerRun.trans replayIdentity⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentHistoryObserverStateReplay
