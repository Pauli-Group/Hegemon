import Hegemon.Consensus.Supply
import Hegemon.Native.ActionStreamEffect
import Hegemon.Native.BlockCommitmentAdmission

set_option linter.unusedSimpArgs false

namespace Hegemon
namespace Native
namespace BlockReplayRefinement

open Hegemon.Consensus
open Hegemon.Native.ActionStreamEffect
open Hegemon.Native.BlockCommitmentAdmission

inductive BlockReplayReject where
  | ciphertextCountMismatch
  | commitmentIndexOverflow
  | nullifierZero
  | duplicateNullifier
  | bridgeReplayDuplicate
  | supplyDeltaInvalid
  | txCountMismatch
  | stateRootMismatch
  | kernelRootMismatch
  | nullifierRootMismatch
  | extrinsicsRootMismatch
  | messageRootMismatch
  | messageCountMismatch
  | headerMmrRootMismatch
  | headerMmrLenMismatch
  | supplyDigestMismatch
deriving DecidableEq, Repr

structure BlockReplayInput where
  leafStart : Nat
  spentNullifiers : List Nat
  consumedBridgeReplays : List Nat
  actions : List StreamAction
  parentSupply : Nat
  height : Nat
  feeTotal : Nat
  hasCoinbase : Bool
  claimedSupply : Nat
  txCountMatches : Bool
  stateRootMatches : Bool
  kernelRootMatches : Bool
  nullifierRootMatches : Bool
  extrinsicsRootMatches : Bool
  messageRootMatches : Bool
  messageCountMatches : Bool
  headerMmrRootMatches : Bool
  headerMmrLenMatches : Bool
deriving DecidableEq, Repr

structure BlockReplaySummary where
  nextLeafCount : Nat
  importedNullifierCount : Nat
  importedBridgeReplayCount : Nat
  plannedStarts : List Nat
  expectedSupply : Nat
deriving DecidableEq, Repr

def streamInput (input : BlockReplayInput) : ActionStreamInput :=
  {
    leafStart := input.leafStart,
    spentNullifiers := input.spentNullifiers,
    consumedBridgeReplays := input.consumedBridgeReplays,
    actions := input.actions
  }

def expectedSupply (input : BlockReplayInput) : Option Nat :=
  advanceNativeSupplyDigest
    input.parentSupply
    input.height
    input.feeTotal
    input.hasCoinbase

def supplyDigestMatches (input : BlockReplayInput) : Bool :=
  match expectedSupply input with
  | none => false
  | some expected =>
      if expected = input.claimedSupply then true else false

def commitmentInput (input : BlockReplayInput) : CommitmentInput :=
  {
    txCountMatches := input.txCountMatches,
    stateRootMatches := input.stateRootMatches,
    kernelRootMatches := input.kernelRootMatches,
    nullifierRootMatches := input.nullifierRootMatches,
    extrinsicsRootMatches := input.extrinsicsRootMatches,
    messageRootMatches := input.messageRootMatches,
    messageCountMatches := input.messageCountMatches,
    headerMmrRootMatches := input.headerMmrRootMatches,
    headerMmrLenMatches := input.headerMmrLenMatches,
    supplyDigestMatches := supplyDigestMatches input
  }

def mapStreamReject : ActionStreamReject -> BlockReplayReject
  | ActionStreamReject.ciphertextCountMismatch =>
      BlockReplayReject.ciphertextCountMismatch
  | ActionStreamReject.commitmentIndexOverflow =>
      BlockReplayReject.commitmentIndexOverflow
  | ActionStreamReject.nullifierZero => BlockReplayReject.nullifierZero
  | ActionStreamReject.duplicateNullifier =>
      BlockReplayReject.duplicateNullifier
  | ActionStreamReject.bridgeReplayDuplicate =>
      BlockReplayReject.bridgeReplayDuplicate

def mapCommitmentReject : CommitmentReject -> BlockReplayReject
  | CommitmentReject.txCountMismatch => BlockReplayReject.txCountMismatch
  | CommitmentReject.stateRootMismatch => BlockReplayReject.stateRootMismatch
  | CommitmentReject.kernelRootMismatch => BlockReplayReject.kernelRootMismatch
  | CommitmentReject.nullifierRootMismatch => BlockReplayReject.nullifierRootMismatch
  | CommitmentReject.extrinsicsRootMismatch => BlockReplayReject.extrinsicsRootMismatch
  | CommitmentReject.messageRootMismatch => BlockReplayReject.messageRootMismatch
  | CommitmentReject.messageCountMismatch => BlockReplayReject.messageCountMismatch
  | CommitmentReject.headerMmrRootMismatch => BlockReplayReject.headerMmrRootMismatch
  | CommitmentReject.headerMmrLenMismatch => BlockReplayReject.headerMmrLenMismatch
  | CommitmentReject.supplyDigestMismatch => BlockReplayReject.supplyDigestMismatch

def evaluateBlockReplayRefinement
    (input : BlockReplayInput) :
    Except BlockReplayReject BlockReplaySummary :=
  match evaluateActionStreamEffect (streamInput input) with
  | Except.error rejection => Except.error (mapStreamReject rejection)
  | Except.ok effect =>
      match expectedSupply input with
      | none => Except.error BlockReplayReject.supplyDeltaInvalid
      | some supply =>
          match evaluateCommitmentRejection (commitmentInput input) with
          | some rejection => Except.error (mapCommitmentReject rejection)
          | none =>
              Except.ok
                { nextLeafCount := effect.nextLeafCount,
                  importedNullifierCount := effect.importedNullifierCount,
                  importedBridgeReplayCount := effect.importedBridgeReplayCount,
                  plannedStarts := effect.plannedStarts,
                  expectedSupply := supply }

def blockReplayAccepts (input : BlockReplayInput) : Bool :=
  match evaluateBlockReplayRefinement input with
  | Except.ok _ => true
  | Except.error _ => false

def blockReplayPreconditions (input : BlockReplayInput) : Bool :=
  actionStreamAccepts (streamInput input)
    &&
      (match expectedSupply input with
      | none => false
      | some _ => commitmentPreconditions (commitmentInput input))

theorem accepts_iff_block_replay_preconditions
    (input : BlockReplayInput) :
    blockReplayAccepts input = blockReplayPreconditions input := by
  unfold blockReplayAccepts blockReplayPreconditions evaluateBlockReplayRefinement
  cases streamResult : evaluateActionStreamEffect (streamInput input) with
  | error streamRejection =>
      simp [actionStreamAccepts, streamResult]
  | ok effect =>
      cases supplyResult : expectedSupply input with
      | none =>
          simp [actionStreamAccepts, streamResult, supplyResult]
      | some supply =>
          cases commitmentResult :
              evaluateCommitmentRejection (commitmentInput input) with
          | none =>
              have commitmentAcceptsTrue :
                  commitmentAccepts (commitmentInput input) = true := by
                simp [commitmentAccepts, commitmentResult]
              have commitmentPreconditionsTrue :
                  commitmentPreconditions (commitmentInput input) = true :=
                (accepts_iff_commitment_preconditions
                  (input := commitmentInput input)).mp commitmentAcceptsTrue
              simp [
                actionStreamAccepts,
                streamResult,
                supplyResult,
                commitmentResult,
                commitmentPreconditionsTrue
              ]
          | some commitmentRejection =>
              have commitmentPreconditionsFalse :
                  commitmentPreconditions (commitmentInput input) = false := by
                cases h :
                    commitmentPreconditions (commitmentInput input) with
                | false => rfl
                | true =>
                    have commitmentAcceptsTrue :
                        commitmentAccepts (commitmentInput input) = true :=
                      (accepts_iff_commitment_preconditions
                        (input := commitmentInput input)).mpr h
                    simp [commitmentAccepts, commitmentResult] at commitmentAcceptsTrue
              simp [
                actionStreamAccepts,
                streamResult,
                supplyResult,
                commitmentResult,
                commitmentPreconditionsFalse
              ]

theorem accepted_has_action_effect
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    evaluateActionStreamEffect (streamInput input) =
      Except.ok
        { nextLeafCount := summary.nextLeafCount,
          importedNullifierCount := summary.importedNullifierCount,
          importedBridgeReplayCount := summary.importedBridgeReplayCount,
          plannedStarts := summary.plannedStarts } := by
  unfold evaluateBlockReplayRefinement at accepted
  cases streamResult : evaluateActionStreamEffect (streamInput input) with
  | error rejection =>
      simp [streamResult] at accepted
  | ok effect =>
      cases supplyResult : expectedSupply input with
      | none =>
          simp [streamResult, supplyResult] at accepted
      | some supply =>
          cases commitmentResult :
              evaluateCommitmentRejection (commitmentInput input) with
          | some rejection =>
              simp [streamResult, supplyResult, commitmentResult] at accepted
          | none =>
              simp [streamResult, supplyResult, commitmentResult] at accepted
              rw [← accepted]

theorem accepted_has_action_stream_effect
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    evaluateActionStreamEffect (streamInput input) =
      Except.ok
        { nextLeafCount := summary.nextLeafCount,
          importedNullifierCount := summary.importedNullifierCount,
          importedBridgeReplayCount := summary.importedBridgeReplayCount,
          plannedStarts := summary.plannedStarts } :=
  accepted_has_action_effect accepted

theorem accepted_claims_expected_supply
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    expectedSupply input = some summary.expectedSupply
      ∧ summary.expectedSupply = input.claimedSupply := by
  unfold evaluateBlockReplayRefinement at accepted
  cases streamResult : evaluateActionStreamEffect (streamInput input) with
  | error rejection =>
      simp [streamResult] at accepted
  | ok effect =>
      cases supplyResult : expectedSupply input with
      | none =>
          simp [streamResult, supplyResult] at accepted
      | some supply =>
          cases commitmentResult :
              evaluateCommitmentRejection (commitmentInput input) with
          | some rejection =>
              simp [streamResult, supplyResult, commitmentResult] at accepted
          | none =>
              have commitmentAcceptsTrue :
                  commitmentAccepts (commitmentInput input) = true := by
                simp [commitmentAccepts, commitmentResult]
              have commitmentPreconditionsTrue :
                  commitmentPreconditions (commitmentInput input) = true :=
                (accepts_iff_commitment_preconditions
                  (input := commitmentInput input)).mp commitmentAcceptsTrue
              have supplyMatchesTrue :
                  supplyDigestMatches input = true := by
                cases input
                simp [commitmentInput, commitmentPreconditions] at commitmentPreconditionsTrue
                exact commitmentPreconditionsTrue.right
              have expectedEq : supply = input.claimedSupply := by
                unfold supplyDigestMatches at supplyMatchesTrue
                rw [supplyResult] at supplyMatchesTrue
                by_cases eq : supply = input.claimedSupply
                · exact eq
                · simp [eq] at supplyMatchesTrue
              simp [streamResult, supplyResult, commitmentResult] at accepted
              rw [← accepted]
              constructor
              · rfl
              · exact expectedEq

theorem accepted_implies_commitment_preconditions
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    commitmentPreconditions (commitmentInput input) = true := by
  unfold evaluateBlockReplayRefinement at accepted
  cases streamResult : evaluateActionStreamEffect (streamInput input) with
  | error rejection =>
      simp [streamResult] at accepted
  | ok effect =>
      cases supplyResult : expectedSupply input with
      | none =>
          simp [streamResult, supplyResult] at accepted
      | some supply =>
          cases commitmentResult :
              evaluateCommitmentRejection (commitmentInput input) with
          | some rejection =>
              simp [streamResult, supplyResult, commitmentResult] at accepted
          | none =>
              have commitmentAcceptsTrue :
                  commitmentAccepts (commitmentInput input) = true := by
                simp [commitmentAccepts, commitmentResult]
              exact
                (accepts_iff_commitment_preconditions
                  (input := commitmentInput input)).mp commitmentAcceptsTrue

theorem accepted_forbids_counterfeit_state_root
    {input : BlockReplayInput}
    {summary : BlockReplaySummary}
    (accepted : evaluateBlockReplayRefinement input = Except.ok summary) :
    input.stateRootMatches = true := by
  have preconditions := accepted_implies_commitment_preconditions accepted
  cases input
  simp [commitmentInput, commitmentPreconditions] at preconditions
  exact preconditions.left.left.left.left.left.left.left.left.right

def validReplay : BlockReplayInput :=
  {
    leafStart := 10,
    spentNullifiers := [],
    consumedBridgeReplays := [],
    actions := [
      {
        commitmentCount := 2,
        ciphertextCount := 2,
        nullifiers := [1],
        bridgeReplayKey := none
      }
    ],
    parentSupply := 100,
    height := 1,
    feeTotal := 0,
    hasCoinbase := false,
    claimedSupply := 100,
    txCountMatches := true,
    stateRootMatches := true,
    kernelRootMatches := true,
    nullifierRootMatches := true,
    extrinsicsRootMatches := true,
    messageRootMatches := true,
    messageCountMatches := true,
    headerMmrRootMatches := true,
    headerMmrLenMatches := true
  }

theorem valid_replay_accepts :
    evaluateBlockReplayRefinement validReplay =
      Except.ok
        { nextLeafCount := 12,
          importedNullifierCount := 1,
          importedBridgeReplayCount := 0,
          plannedStarts := [10],
          expectedSupply := 100 } := by
  rfl

def validTwoActionReplay : BlockReplayInput :=
  {
    validReplay with
    leafStart := 20,
    actions := [
      {
        commitmentCount := 2,
        ciphertextCount := 2,
        nullifiers := [1],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 1,
        ciphertextCount := 1,
        nullifiers := [2, 3],
        bridgeReplayKey := some 7
      }
    ]
  }

theorem valid_two_action_replay_accepts :
    evaluateBlockReplayRefinement validTwoActionReplay =
      Except.ok
        { nextLeafCount := 23,
          importedNullifierCount := 3,
          importedBridgeReplayCount := 1,
          plannedStarts := [20, 22],
          expectedSupply := 100 } := by
  rfl

def duplicateNullifierReplay : BlockReplayInput :=
  {
    validReplay with
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [4],
        bridgeReplayKey := none
      },
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [4],
        bridgeReplayKey := none
      }
    ]
  }

theorem duplicate_nullifier_replay_rejects :
    evaluateBlockReplayRefinement duplicateNullifierReplay =
      Except.error BlockReplayReject.duplicateNullifier := by
  rfl

def crossActionBridgeReplayDuplicate : BlockReplayInput :=
  {
    validReplay with
    actions := [
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [],
        bridgeReplayKey := some 9
      },
      {
        commitmentCount := 0,
        ciphertextCount := 0,
        nullifiers := [],
        bridgeReplayKey := some 9
      }
    ]
  }

theorem cross_action_bridge_replay_duplicate_rejects :
    evaluateBlockReplayRefinement crossActionBridgeReplayDuplicate =
      Except.error BlockReplayReject.bridgeReplayDuplicate := by
  rfl

def supplyOverflowReplay : BlockReplayInput :=
  {
    validReplay with
    parentSupply := maxSupplyDigest,
    hasCoinbase := true,
    claimedSupply := maxSupplyDigest
  }

theorem supply_overflow_replay_rejects :
    evaluateBlockReplayRefinement supplyOverflowReplay =
      Except.error BlockReplayReject.supplyDeltaInvalid := by
  rfl

def counterfeitSupplyReplay : BlockReplayInput :=
  { validReplay with claimedSupply := 101 }

theorem counterfeit_supply_replay_rejects :
    evaluateBlockReplayRefinement counterfeitSupplyReplay =
      Except.error BlockReplayReject.supplyDigestMismatch := by
  rfl

def counterfeitStateAndSupplyReplay : BlockReplayInput :=
  { counterfeitSupplyReplay with stateRootMatches := false }

theorem state_root_precedes_supply_digest :
    evaluateBlockReplayRefinement counterfeitStateAndSupplyReplay =
      Except.error BlockReplayReject.stateRootMismatch := by
  rfl

end BlockReplayRefinement
end Native
end Hegemon
