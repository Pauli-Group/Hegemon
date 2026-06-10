import Hegemon.Bytes
import Hegemon.Native.TxLeafArtifact

namespace Hegemon
namespace Native
namespace ReceiptRoot

def digestWidth : Nat := 48
def shortDigestWidth : Nat := 32
def maxLeaves : Nat := 128
def maxFolds : Nat := maxLeaves - 1
def foldChallengeCount : Nat := 5
def matrixRows : Nat := 11
def matrixCols : Nat := 54

structure FoldSummary where
  challengeCount : Nat
  rowCount : Nat
  rowCoeffCounts : List Nat
deriving DecidableEq, Repr

structure ReceiptRootSummary where
  version : Nat
  leafCount : Nat
  foldCount : Nat
  folds : List FoldSummary
deriving DecidableEq, Repr

def concatByteLists : List (List Byte) -> List Byte
  | [] => []
  | bytes :: rest => bytes ++ concatByteLists rest

def encodeNat64s (values : List Nat) : List Byte :=
  concatByteLists (values.map u64le)

def digest32 (seed : Nat) : List Byte :=
  patternedBytes shortDigestWidth seed

def digest48 (seed : Nat) : List Byte :=
  patternedBytes digestWidth seed

def parseLeaf (input : List Byte) : Option (List Byte) := do
  TxLeafArtifact.skipBytes (digestWidth * 3) input

def parseLeaves : Nat -> List Byte -> Option (List Byte)
  | 0, input => some input
  | count + 1, input => do
      let rest ← parseLeaf input
      parseLeaves count rest

def parseRows : Nat -> List Byte -> Option (List Nat × List Byte)
  | 0, input => some ([], input)
  | count + 1, input => do
      let (coeffCount, rest0) ← TxLeafArtifact.readCappedU32 matrixCols input
      let rest1 ← TxLeafArtifact.skipBytes (coeffCount * 8) rest0
      let (tail, rest2) ← parseRows count rest1
      some (coeffCount :: tail, rest2)

def parseFold (input : List Byte) : Option (FoldSummary × List Byte) := do
  let (challengeCount, rest0) ← TxLeafArtifact.readCappedU32 foldChallengeCount input
  let rest1 ← TxLeafArtifact.skipBytes (challengeCount * 8) rest0
  let rest2 ← TxLeafArtifact.skipBytes digestWidth rest1
  let rest3 ← TxLeafArtifact.skipBytes digestWidth rest2
  let (rowCount, rest4) ← TxLeafArtifact.readCappedU32 matrixRows rest3
  let (rowCoeffCounts, rest5) ← parseRows rowCount rest4
  let rest6 ← TxLeafArtifact.skipBytes digestWidth rest5
  some ({ challengeCount, rowCount, rowCoeffCounts }, rest6)

def parseFolds : Nat -> List Byte -> Option (List FoldSummary × List Byte)
  | 0, input => some ([], input)
  | count + 1, input => do
      let (fold, rest0) ← parseFold input
      let (tail, rest1) ← parseFolds count rest0
      some (fold :: tail, rest1)

def parseNativeReceiptRootArtifact (input : List Byte) : Option ReceiptRootSummary := do
  let (version, rest0) ← TxLeafArtifact.readU16 input
  let rest1 ← TxLeafArtifact.skipBytes digestWidth rest0
  let rest2 ← TxLeafArtifact.skipBytes shortDigestWidth rest1
  let rest3 ← TxLeafArtifact.skipBytes shortDigestWidth rest2
  let rest4 ← TxLeafArtifact.skipBytes shortDigestWidth rest3
  let (leafCount, rest5) ← TxLeafArtifact.readCappedU32 maxLeaves rest4
  let (foldCount, rest6) ← TxLeafArtifact.readCappedU32 maxFolds rest5
  let rest7 ← parseLeaves leafCount rest6
  let (folds, rest8) ← parseFolds foldCount rest7
  let rest9 ← TxLeafArtifact.skipBytes digestWidth rest8
  let rest10 ← TxLeafArtifact.skipBytes digestWidth rest9
  match rest10 with
  | [] => some { version, leafCount, foldCount, folds }
  | _ :: _ => none

def expectedFoldCount (leafCount : Nat) : Nat :=
  leafCount - 1

def rowShapeExact : List Nat -> Bool
  | [] => true
  | coeffCount :: rest => (coeffCount == matrixCols) && rowShapeExact rest

def foldShapeExact (fold : FoldSummary) : Bool :=
  (fold.challengeCount == foldChallengeCount)
    && (fold.rowCount == matrixRows)
    && rowShapeExact fold.rowCoeffCounts

def allFoldShapesExact : List FoldSummary -> Bool
  | [] => true
  | fold :: rest => foldShapeExact fold && allFoldShapesExact rest

def receiptRootScheduleAccepts (expectedLeafCount : Nat) (artifact : List Byte) : Bool :=
  match parseNativeReceiptRootArtifact artifact with
  | none => false
  | some summary =>
      (decide (0 < expectedLeafCount))
        && (summary.leafCount == expectedLeafCount)
        && (summary.foldCount == expectedFoldCount expectedLeafCount)
        && allFoldShapesExact summary.folds

structure FoldWireFields where
  challenges : List Nat
  parentRows : List (List Nat)
  seed : Nat
deriving DecidableEq, Repr

structure ReceiptRootWireFields where
  version : Nat
  leaves : List Nat
  folds : List FoldWireFields
  rootSeed : Nat
deriving DecidableEq, Repr

def fullRow (seed : Nat) : List Nat :=
  (List.range matrixCols).map fun index => seed + index

def fullRows (seed : Nat) : List (List Nat) :=
  (List.range matrixRows).map fun index => fullRow (seed + index * matrixCols)

def validFold (seed : Nat) : FoldWireFields := {
  challenges := [seed, seed + 1, seed + 2, seed + 3, seed + 4],
  parentRows := fullRows (seed + 100),
  seed
}

def encodeLeaf (seed : Nat) : List Byte :=
  digest48 seed ++ digest48 (seed + 1) ++ digest48 (seed + 2)

def encodeRows (rows : List (List Nat)) : List Byte :=
  concatByteLists (rows.map fun row => u32le row.length ++ encodeNat64s row)

def encodeFold (fold : FoldWireFields) : List Byte :=
  u32le fold.challenges.length
    ++ encodeNat64s fold.challenges
    ++ digest48 (fold.seed + 10)
    ++ digest48 (fold.seed + 20)
    ++ u32le fold.parentRows.length
    ++ encodeRows fold.parentRows
    ++ digest48 (fold.seed + 30)

def encodeHeader (fields : ReceiptRootWireFields) : List Byte :=
  u16le fields.version
    ++ digest48 0x10
    ++ digest32 0x20
    ++ digest32 0x30
    ++ digest32 0x40
    ++ u32le fields.leaves.length
    ++ u32le fields.folds.length

def receiptRootArtifactBytes (fields : ReceiptRootWireFields) : List Byte :=
  encodeHeader fields
    ++ concatByteLists (fields.leaves.map encodeLeaf)
    ++ concatByteLists (fields.folds.map encodeFold)
    ++ digest48 fields.rootSeed
    ++ digest48 (fields.rootSeed + 1)

def validSingleFields : ReceiptRootWireFields := {
  version := 3,
  leaves := [1],
  folds := [],
  rootSeed := 0x80
}

def validTwoFields : ReceiptRootWireFields := {
  version := 3,
  leaves := [1, 4],
  folds := [validFold 0x100],
  rootSeed := 0x90
}

def validThreeFields : ReceiptRootWireFields := {
  version := 3,
  leaves := [1, 4, 7],
  folds := [validFold 0x100, validFold 0x200],
  rootSeed := 0xa0
}

def validSingleArtifact : List Byte :=
  receiptRootArtifactBytes validSingleFields

def validTwoArtifact : List Byte :=
  receiptRootArtifactBytes validTwoFields

def validThreeArtifact : List Byte :=
  receiptRootArtifactBytes validThreeFields

def validSingleSummary : ReceiptRootSummary := {
  version := 3,
  leafCount := 1,
  foldCount := 0,
  folds := []
}

def validTwoFoldSummary : FoldSummary := {
  challengeCount := foldChallengeCount,
  rowCount := matrixRows,
  rowCoeffCounts := List.replicate matrixRows matrixCols
}

def validTwoSummary : ReceiptRootSummary := {
  version := 3,
  leafCount := 2,
  foldCount := 1,
  folds := [validTwoFoldSummary]
}

def validThreeSummary : ReceiptRootSummary := {
  version := 3,
  leafCount := 3,
  foldCount := 2,
  folds := [validTwoFoldSummary, validTwoFoldSummary]
}

def zeroLeafArtifact : List Byte :=
  receiptRootArtifactBytes { validSingleFields with leaves := [] }

def leafMismatchArtifact : List Byte :=
  validTwoArtifact

def missingFoldArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [] }

def extraFoldArtifact : List Byte :=
  receiptRootArtifactBytes { validSingleFields with folds := [validFold 0x300] }

def tooFewChallengesArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with challenges := [1, 2, 3, 4] }] }

def tooManyChallengesArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with challenges := [1, 2, 3, 4, 5, 6] }] }

def tooFewRowsArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with parentRows := List.replicate (matrixRows - 1) (fullRow 0) }] }

def tooManyRowsArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with parentRows := List.replicate (matrixRows + 1) (fullRow 0) }] }

def tooFewCoefficientsArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with parentRows := [List.range (matrixCols - 1)] ++ List.replicate (matrixRows - 1) (fullRow 0) }] }

def tooManyCoefficientsArtifact : List Byte :=
  receiptRootArtifactBytes { validTwoFields with folds := [{ validFold 0x100 with parentRows := [List.range (matrixCols + 1)] ++ List.replicate (matrixRows - 1) (fullRow 0) }] }

def invalidCountHeader (leafCount foldCount : Nat) : List Byte :=
  u16le 3
    ++ digest48 0x10
    ++ digest32 0x20
    ++ digest32 0x30
    ++ digest32 0x40
    ++ u32le leafCount
    ++ u32le foldCount
    ++ digest48 0x80
    ++ digest48 0x81

def tooManyLeavesArtifact : List Byte :=
  invalidCountHeader (maxLeaves + 1) 0

def tooManyFoldsArtifact : List Byte :=
  invalidCountHeader 1 (maxFolds + 1)

def trailingArtifact : List Byte :=
  validSingleArtifact ++ [0]

def truncatedArtifact : List Byte :=
  validTwoArtifact.take (validTwoArtifact.length - 8)

theorem valid_single_parses :
    parseNativeReceiptRootArtifact validSingleArtifact = some validSingleSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem valid_two_parses :
    parseNativeReceiptRootArtifact validTwoArtifact = some validTwoSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem valid_three_parses :
    parseNativeReceiptRootArtifact validThreeArtifact = some validThreeSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem single_leaf_schedule_accepts :
    receiptRootScheduleAccepts 1 validSingleArtifact = true := by
  set_option maxRecDepth 50000 in
  decide

theorem two_leaf_schedule_accepts :
    receiptRootScheduleAccepts 2 validTwoArtifact = true := by
  set_option maxRecDepth 50000 in
  decide

theorem three_leaf_schedule_accepts :
    receiptRootScheduleAccepts 3 validThreeArtifact = true := by
  set_option maxRecDepth 50000 in
  decide

theorem zero_expected_leaves_rejected :
    receiptRootScheduleAccepts 0 validSingleArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem artifact_leaf_mismatch_rejected :
    receiptRootScheduleAccepts 1 leafMismatchArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem missing_fold_rejected :
    receiptRootScheduleAccepts 2 missingFoldArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem extra_fold_rejected :
    receiptRootScheduleAccepts 1 extraFoldArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem too_few_challenges_rejected :
    receiptRootScheduleAccepts 2 tooFewChallengesArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem too_many_challenges_rejected :
    parseNativeReceiptRootArtifact tooManyChallengesArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem too_few_rows_rejected :
    receiptRootScheduleAccepts 2 tooFewRowsArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem too_many_rows_rejected :
    parseNativeReceiptRootArtifact tooManyRowsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem too_few_coefficients_rejected :
    receiptRootScheduleAccepts 2 tooFewCoefficientsArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem too_many_coefficients_rejected :
    parseNativeReceiptRootArtifact tooManyCoefficientsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem zero_artifact_leaves_rejected :
    receiptRootScheduleAccepts 0 zeroLeafArtifact = false := by
  set_option maxRecDepth 50000 in
  decide

theorem too_many_leaves_rejected :
    parseNativeReceiptRootArtifact tooManyLeavesArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem too_many_folds_rejected :
    parseNativeReceiptRootArtifact tooManyFoldsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem trailing_bytes_rejected :
    parseNativeReceiptRootArtifact trailingArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem truncated_artifact_rejected :
    parseNativeReceiptRootArtifact truncatedArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

end ReceiptRoot
end Native
end Hegemon
