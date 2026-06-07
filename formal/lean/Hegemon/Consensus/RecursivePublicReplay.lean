namespace Hegemon
namespace Consensus
namespace RecursivePublicReplay

inductive ReplayVersion where
  | v1
  | v2
deriving DecidableEq, Repr

inductive ReplayReject where
  | txIndexGap
deriving DecidableEq, Repr

structure SemanticFields where
  txStatementsCommitment : Nat
  startShieldedRoot : Nat
  endShieldedRoot : Nat
  startKernelRoot : Nat
  endKernelRoot : Nat
  nullifierRoot : Nat
  daRoot : Nat
  messageRoot : Nat
  startTreeCommitment : Nat
  endTreeCommitment : Nat
deriving DecidableEq, Repr

structure PublicV1Fields where
  txCount : Nat
  txStatementsCommitment : Nat
  verifiedLeafCommitment : Nat
  verifiedReceiptCommitment : Nat
  startShieldedRoot : Nat
  endShieldedRoot : Nat
  startKernelRoot : Nat
  endKernelRoot : Nat
  nullifierRoot : Nat
  daRoot : Nat
  messageRoot : Nat
  startTreeCommitment : Nat
  endTreeCommitment : Nat
deriving DecidableEq, Repr

structure PublicV2Fields where
  txCount : Nat
  txStatementsCommitment : Nat
  statementTreeDigest : Nat
  verifiedLeafTreeDigest : Nat
  verifiedReceiptTreeDigest : Nat
  startStateDigest : Nat
  endStateDigest : Nat
  startShieldedRoot : Nat
  endShieldedRoot : Nat
  startKernelRoot : Nat
  endKernelRoot : Nat
  nullifierRoot : Nat
  daRoot : Nat
  startTreeCommitment : Nat
  endTreeCommitment : Nat
deriving DecidableEq, Repr

def digest48Len : Nat := 48

def v1PublicBytesLen : Nat := 4 + 12 * digest48Len

def v2PublicBytesLen : Nat := 4 + 14 * digest48Len

def txIndicesContiguous : List Nat -> Bool
  | [] => true
  | [_] => true
  | first :: second :: rest =>
      if second = first + 1 then
        txIndicesContiguous (second :: rest)
      else
        false

def evaluateReplayRejection (txIndices : List Nat) : Option ReplayReject :=
  if txIndicesContiguous txIndices then
    none
  else
    some ReplayReject.txIndexGap

def replayAccepts (txIndices : List Nat) : Bool :=
  evaluateReplayRejection txIndices = none

def buildPublicV1
    (txIndices : List Nat)
    (semantic : SemanticFields)
    (verifiedLeafCommitment verifiedReceiptCommitment : Nat) :
    Option PublicV1Fields :=
  if replayAccepts txIndices then
    some {
      txCount := txIndices.length,
      txStatementsCommitment := semantic.txStatementsCommitment,
      verifiedLeafCommitment,
      verifiedReceiptCommitment,
      startShieldedRoot := semantic.startShieldedRoot,
      endShieldedRoot := semantic.endShieldedRoot,
      startKernelRoot := semantic.startKernelRoot,
      endKernelRoot := semantic.endKernelRoot,
      nullifierRoot := semantic.nullifierRoot,
      daRoot := semantic.daRoot,
      messageRoot := semantic.messageRoot,
      startTreeCommitment := semantic.startTreeCommitment,
      endTreeCommitment := semantic.endTreeCommitment
    }
  else
    none

def buildPublicV2
    (txIndices : List Nat)
    (semantic : SemanticFields)
    (statementTreeDigest verifiedLeafTreeDigest verifiedReceiptTreeDigest
      startStateDigest endStateDigest : Nat) :
    Option PublicV2Fields :=
  if replayAccepts txIndices then
    some {
      txCount := txIndices.length,
      txStatementsCommitment := semantic.txStatementsCommitment,
      statementTreeDigest,
      verifiedLeafTreeDigest,
      verifiedReceiptTreeDigest,
      startStateDigest,
      endStateDigest,
      startShieldedRoot := semantic.startShieldedRoot,
      endShieldedRoot := semantic.endShieldedRoot,
      startKernelRoot := semantic.startKernelRoot,
      endKernelRoot := semantic.endKernelRoot,
      nullifierRoot := semantic.nullifierRoot,
      daRoot := semantic.daRoot,
      startTreeCommitment := semantic.startTreeCommitment,
      endTreeCommitment := semantic.endTreeCommitment
    }
  else
    none

def sampleSemantic : SemanticFields :=
  {
    txStatementsCommitment := 16,
    startShieldedRoot := 32,
    endShieldedRoot := 33,
    startKernelRoot := 48,
    endKernelRoot := 49,
    nullifierRoot := 64,
    daRoot := 80,
    messageRoot := 96,
    startTreeCommitment := 112,
    endTreeCommitment := 113
  }

theorem accepts_iff_contiguous (txIndices : List Nat) :
    replayAccepts txIndices = txIndicesContiguous txIndices := by
  unfold replayAccepts evaluateReplayRejection
  cases txIndicesContiguous txIndices <;> simp

theorem zero_based_contiguous_accepts :
    evaluateReplayRejection [0, 1, 2] = none := by
  native_decide

theorem nonzero_start_contiguous_accepts :
    evaluateReplayRejection [5, 6, 7] = none := by
  native_decide

theorem gap_rejects :
    evaluateReplayRejection [0, 2, 3] = some ReplayReject.txIndexGap := by
  native_decide

theorem duplicate_rejects :
    evaluateReplayRejection [0, 1, 1] = some ReplayReject.txIndexGap := by
  native_decide

theorem decreasing_rejects :
    evaluateReplayRejection [2, 1, 0] = some ReplayReject.txIndexGap := by
  native_decide

theorem valid_v1_public_fields_match_semantic :
    buildPublicV1 [0, 1, 2] sampleSemantic 170 187 =
      some {
        txCount := 3,
        txStatementsCommitment := sampleSemantic.txStatementsCommitment,
        verifiedLeafCommitment := 170,
        verifiedReceiptCommitment := 187,
        startShieldedRoot := sampleSemantic.startShieldedRoot,
        endShieldedRoot := sampleSemantic.endShieldedRoot,
        startKernelRoot := sampleSemantic.startKernelRoot,
        endKernelRoot := sampleSemantic.endKernelRoot,
        nullifierRoot := sampleSemantic.nullifierRoot,
        daRoot := sampleSemantic.daRoot,
        messageRoot := sampleSemantic.messageRoot,
        startTreeCommitment := sampleSemantic.startTreeCommitment,
        endTreeCommitment := sampleSemantic.endTreeCommitment
      } := by
  native_decide

theorem valid_v2_public_fields_match_semantic :
    buildPublicV2 [0, 1, 2] sampleSemantic 128 129 130 131 132 =
      some {
        txCount := 3,
        txStatementsCommitment := sampleSemantic.txStatementsCommitment,
        statementTreeDigest := 128,
        verifiedLeafTreeDigest := 129,
        verifiedReceiptTreeDigest := 130,
        startStateDigest := 131,
        endStateDigest := 132,
        startShieldedRoot := sampleSemantic.startShieldedRoot,
        endShieldedRoot := sampleSemantic.endShieldedRoot,
        startKernelRoot := sampleSemantic.startKernelRoot,
        endKernelRoot := sampleSemantic.endKernelRoot,
        nullifierRoot := sampleSemantic.nullifierRoot,
        daRoot := sampleSemantic.daRoot,
        startTreeCommitment := sampleSemantic.startTreeCommitment,
        endTreeCommitment := sampleSemantic.endTreeCommitment
      } := by
  native_decide

theorem v1_public_byte_length :
    v1PublicBytesLen = 580 := by
  native_decide

theorem v2_public_byte_length :
    v2PublicBytesLen = 676 := by
  native_decide

end RecursivePublicReplay
end Consensus
end Hegemon
