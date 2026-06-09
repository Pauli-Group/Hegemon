namespace Hegemon
namespace Consensus
namespace AggregationV5

def aggregationProofFormatVersionV5 : Nat := 5
def publicValuesEncodingV2 : Nat := 2
def statementCommitmentBytes : Nat := 48

inductive NodeKind where
  | leaf
  | merge
deriving DecidableEq, Repr

inductive HeaderReject where
  | unsupportedVersion
  | unsupportedProofFormat
  | unsupportedPublicValuesEncoding
  | statementCommitmentLength
  | statementCommitmentMismatch
  | childCountOutOfRange
  | subtreeTxCountMismatch
  | treeLevelsMismatch
  | rootLevelOutOfRange
  | fanInZero
  | leafFanInExceedsConfigured
  | multilevelLeafFanInMismatch
  | mergeFanInMismatch
  | innerPublicInputsLenMismatch
deriving DecidableEq, Repr

structure HeaderInput where
  version : Nat
  proofFormat : Nat
  nodeKind : NodeKind
  fanIn : Nat
  childCount : Nat
  subtreeTxCount : Nat
  expectedTxCount : Nat
  treeLevels : Nat
  rootLevel : Nat
  statementCommitmentLen : Nat
  statementCommitmentMatches : Bool
  publicValuesEncoding : Nat
  innerPublicInputsLen : Nat
  packedPublicValuesLen : Nat
  configuredLeafFanIn : Nat
  configuredMergeFanIn : Nat
deriving DecidableEq, Repr

def ceilDiv (n d : Nat) : Nat :=
  if d = 0 then
    0
  else
    (n + d - 1) / d

def leafFanInFloor (fanIn : Nat) : Nat :=
  max fanIn 1

def mergeFanInFloor (fanIn : Nat) : Nat :=
  max fanIn 2

def leafCountForTxCount (txCount leafFanIn : Nat) : Nat :=
  ceilDiv txCount (leafFanInFloor leafFanIn)

def treeLevelsLoop (width levels mergeFanIn fuel : Nat) : Nat :=
  match fuel with
  | 0 => levels
  | fuel' + 1 =>
      if width ≤ 1 then
        levels
      else
        treeLevelsLoop
          (ceilDiv width (mergeFanInFloor mergeFanIn))
          (levels + 1)
          mergeFanIn
          fuel'

def treeLevelsForTxCount (txCount leafFanIn mergeFanIn : Nat) : Nat :=
  if txCount ≤ 1 then
    1
  else
    treeLevelsLoop
      (leafCountForTxCount txCount leafFanIn)
      1
      mergeFanIn
      (txCount + 1)

def evaluateHeader (input : HeaderInput) : Option HeaderReject :=
  if input.version != aggregationProofFormatVersionV5 then
    some HeaderReject.unsupportedVersion
  else if input.proofFormat != aggregationProofFormatVersionV5 then
    some HeaderReject.unsupportedProofFormat
  else if input.publicValuesEncoding != publicValuesEncodingV2 then
    some HeaderReject.unsupportedPublicValuesEncoding
  else if input.statementCommitmentLen != statementCommitmentBytes then
    some HeaderReject.statementCommitmentLength
  else if input.statementCommitmentMatches = false then
    some HeaderReject.statementCommitmentMismatch
  else if input.childCount == 0 || input.childCount > input.fanIn then
    some HeaderReject.childCountOutOfRange
  else if input.subtreeTxCount == 0 || input.subtreeTxCount != input.expectedTxCount then
    some HeaderReject.subtreeTxCountMismatch
  else if input.treeLevels != treeLevelsForTxCount
      input.expectedTxCount
      input.configuredLeafFanIn
      input.configuredMergeFanIn then
    some HeaderReject.treeLevelsMismatch
  else if input.rootLevel >= input.treeLevels then
    some HeaderReject.rootLevelOutOfRange
  else if input.fanIn == 0 then
    some HeaderReject.fanInZero
  else
    match input.nodeKind with
    | NodeKind.leaf =>
        if input.fanIn > input.configuredLeafFanIn then
          some HeaderReject.leafFanInExceedsConfigured
        else if input.treeLevels > 1 && input.fanIn != input.configuredLeafFanIn then
          some HeaderReject.multilevelLeafFanInMismatch
        else if input.innerPublicInputsLen != input.packedPublicValuesLen then
          some HeaderReject.innerPublicInputsLenMismatch
        else
          none
    | NodeKind.merge =>
        if input.fanIn != input.configuredMergeFanIn then
          some HeaderReject.mergeFanInMismatch
        else if input.innerPublicInputsLen != input.packedPublicValuesLen then
          some HeaderReject.innerPublicInputsLenMismatch
        else
          none

def acceptsHeader (input : HeaderInput) : Bool :=
  evaluateHeader input = none

def validLeafSingletonHeader : HeaderInput :=
  {
    version := aggregationProofFormatVersionV5,
    proofFormat := aggregationProofFormatVersionV5,
    nodeKind := NodeKind.leaf,
    fanIn := 1,
    childCount := 1,
    subtreeTxCount := 1,
    expectedTxCount := 1,
    treeLevels := 1,
    rootLevel := 0,
    statementCommitmentLen := statementCommitmentBytes,
    statementCommitmentMatches := true,
    publicValuesEncoding := publicValuesEncodingV2,
    innerPublicInputsLen := 3,
    packedPublicValuesLen := 3,
    configuredLeafFanIn := 1,
    configuredMergeFanIn := 2
  }

def validMergeHeader : HeaderInput :=
  {
    version := aggregationProofFormatVersionV5,
    proofFormat := aggregationProofFormatVersionV5,
    nodeKind := NodeKind.merge,
    fanIn := 2,
    childCount := 2,
    subtreeTxCount := 4,
    expectedTxCount := 4,
    treeLevels := 3,
    rootLevel := 2,
    statementCommitmentLen := statementCommitmentBytes,
    statementCommitmentMatches := true,
    publicValuesEncoding := publicValuesEncodingV2,
    innerPublicInputsLen := 5,
    packedPublicValuesLen := 5,
    configuredLeafFanIn := 1,
    configuredMergeFanIn := 2
  }

theorem valid_leaf_singleton_header_accepts :
    evaluateHeader validLeafSingletonHeader = none := by
  decide

theorem valid_merge_header_accepts :
    evaluateHeader validMergeHeader = none := by
  decide

theorem rejects_bad_version :
    evaluateHeader { validLeafSingletonHeader with version := 4 } =
      some HeaderReject.unsupportedVersion := by
  decide

theorem rejects_bad_proof_format :
    evaluateHeader { validLeafSingletonHeader with proofFormat := 4 } =
      some HeaderReject.unsupportedProofFormat := by
  decide

theorem rejects_bad_public_values_encoding :
    evaluateHeader { validLeafSingletonHeader with publicValuesEncoding := 1 } =
      some HeaderReject.unsupportedPublicValuesEncoding := by
  decide

theorem rejects_statement_commitment_length :
    evaluateHeader { validLeafSingletonHeader with statementCommitmentLen := 47 } =
      some HeaderReject.statementCommitmentLength := by
  decide

theorem rejects_statement_commitment_mismatch :
    evaluateHeader { validLeafSingletonHeader with statementCommitmentMatches := false } =
      some HeaderReject.statementCommitmentMismatch := by
  decide

theorem rejects_zero_child_count :
    evaluateHeader { validLeafSingletonHeader with childCount := 0 } =
      some HeaderReject.childCountOutOfRange := by
  decide

theorem rejects_child_count_above_fan_in :
    evaluateHeader { validLeafSingletonHeader with childCount := 2 } =
      some HeaderReject.childCountOutOfRange := by
  decide

theorem rejects_subtree_tx_count_mismatch :
    evaluateHeader { validLeafSingletonHeader with subtreeTxCount := 2 } =
      some HeaderReject.subtreeTxCountMismatch := by
  decide

theorem rejects_tree_levels_mismatch :
    evaluateHeader { validMergeHeader with treeLevels := 2 } =
      some HeaderReject.treeLevelsMismatch := by
  decide

theorem rejects_root_level_out_of_range :
    evaluateHeader { validLeafSingletonHeader with rootLevel := 1 } =
      some HeaderReject.rootLevelOutOfRange := by
  decide

theorem rejects_zero_fan_in_after_child_bounds :
    evaluateHeader { validLeafSingletonHeader with fanIn := 0, childCount := 0 } =
      some HeaderReject.childCountOutOfRange := by
  decide

theorem rejects_leaf_fan_in_above_configured :
    evaluateHeader
      { validMergeHeader with nodeKind := NodeKind.leaf, fanIn := 2, childCount := 2 } =
      some HeaderReject.leafFanInExceedsConfigured := by
  decide

theorem rejects_multilevel_leaf_fan_in_mismatch :
    evaluateHeader
      { validMergeHeader with
        nodeKind := NodeKind.leaf,
        fanIn := 1,
        childCount := 1,
        treeLevels := 2,
        rootLevel := 1,
        configuredLeafFanIn := 2
      } =
      some HeaderReject.multilevelLeafFanInMismatch := by
  decide

theorem rejects_merge_fan_in_mismatch :
    evaluateHeader { validMergeHeader with fanIn := 1, childCount := 1 } =
      some HeaderReject.mergeFanInMismatch := by
  decide

theorem rejects_inner_public_inputs_len_mismatch :
    evaluateHeader { validLeafSingletonHeader with packedPublicValuesLen := 2 } =
      some HeaderReject.innerPublicInputsLenMismatch := by
  decide

theorem merge_fan_in_floor_is_binary_minimum :
    mergeFanInFloor 1 = 2 := by
  decide

theorem tree_levels_use_binary_merge_floor :
    treeLevelsForTxCount 4 1 1 = 3 := by
  decide

end AggregationV5
end Consensus
end Hegemon
