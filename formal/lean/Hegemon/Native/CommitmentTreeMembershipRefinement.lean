import Hegemon.Transaction.MerklePath

namespace Hegemon
namespace Native
namespace CommitmentTreeMembershipRefinement

open Hegemon.Transaction

structure MembershipHandoffInput where
  depth : Nat
  leaf : Digest
  position : Nat
  siblings : List Digest
  providedRoot : Digest
  consensusRoot : Digest
  stateMerkleRoot : Digest
  consensusHistoryContainsRoot : Bool
  stateMerklePathExported : Bool
deriving DecidableEq, Repr

def membershipHandoffAccepts (input : MembershipHandoffInput) : Bool :=
  decide (input.consensusRoot = input.stateMerkleRoot)
    && decide (input.providedRoot = input.stateMerkleRoot)
    && input.consensusHistoryContainsRoot
    && input.stateMerklePathExported
    && verifyPathWithDepth
        mockMerkleNode
        input.depth
        input.leaf
        input.position
        input.siblings
        input.providedRoot

structure MembershipHandoffFacts
    (input : MembershipHandoffInput) : Prop where
  consensusRootMatchesStateMerkleRoot :
    input.consensusRoot = input.stateMerkleRoot
  providedRootMatchesStateMerkleRoot :
    input.providedRoot = input.stateMerkleRoot
  consensusHistoryContainsRoot :
    input.consensusHistoryContainsRoot = true
  stateMerklePathExported :
    input.stateMerklePathExported = true
  transactionMerklePathAccepts :
    verifyPathWithDepth
        mockMerkleNode
        input.depth
        input.leaf
        input.position
        input.siblings
        input.providedRoot = true

theorem membership_handoff_accepts_implies_facts
    {input : MembershipHandoffInput}
    (accepted : membershipHandoffAccepts input = true) :
    MembershipHandoffFacts input := by
  unfold membershipHandoffAccepts at accepted
  simp only [Bool.and_eq_true] at accepted
  exact {
    consensusRootMatchesStateMerkleRoot :=
      of_decide_eq_true accepted.left.left.left.left,
    providedRootMatchesStateMerkleRoot :=
      of_decide_eq_true accepted.left.left.left.right,
    consensusHistoryContainsRoot := accepted.left.left.right,
    stateMerklePathExported := accepted.left.right,
    transactionMerklePathAccepts := accepted.right
  }

def validMembershipHandoff : MembershipHandoffInput :=
  let siblings := [20, 30]
  let root := foldPathWith mockMerkleNode 10 1 siblings
  {
    depth := 2,
    leaf := 10,
    position := 1,
    siblings := siblings,
    providedRoot := root,
    consensusRoot := root,
    stateMerkleRoot := root,
    consensusHistoryContainsRoot := true,
    stateMerklePathExported := true
  }

theorem prior_leaf_membership_path_verifies :
    membershipHandoffAccepts validMembershipHandoff = true := by
  decide

theorem consensus_state_root_mismatch_rejects :
    membershipHandoffAccepts
        { validMembershipHandoff with consensusRoot := validMembershipHandoff.consensusRoot + 1 } =
      false := by
  decide

theorem state_path_missing_rejects :
    membershipHandoffAccepts
        { validMembershipHandoff with stateMerklePathExported := false } =
      false := by
  decide

theorem wrong_leaf_membership_rejects :
    membershipHandoffAccepts
        { validMembershipHandoff with leaf := validMembershipHandoff.leaf + 1 } =
      false := by
  decide

def postAppendLeafPriorRootAttempt : MembershipHandoffInput :=
  { validMembershipHandoff with leaf := validMembershipHandoff.leaf + 1 }

theorem post_append_leaf_prior_root_keeps_root_and_export_checks :
    postAppendLeafPriorRootAttempt.consensusRoot =
        postAppendLeafPriorRootAttempt.stateMerkleRoot
      ∧ postAppendLeafPriorRootAttempt.providedRoot =
        postAppendLeafPriorRootAttempt.stateMerkleRoot
      ∧ postAppendLeafPriorRootAttempt.consensusHistoryContainsRoot = true
      ∧ postAppendLeafPriorRootAttempt.stateMerklePathExported = true := by
  decide

theorem post_append_leaf_prior_root_merkle_path_rejects :
    verifyPathWithDepth
        mockMerkleNode
        postAppendLeafPriorRootAttempt.depth
        postAppendLeafPriorRootAttempt.leaf
        postAppendLeafPriorRootAttempt.position
        postAppendLeafPriorRootAttempt.siblings
        postAppendLeafPriorRootAttempt.providedRoot = false := by
  decide

theorem post_append_leaf_not_member_of_prior_root :
    membershipHandoffAccepts postAppendLeafPriorRootAttempt = false := by
  decide

end CommitmentTreeMembershipRefinement
end Native
end Hegemon
