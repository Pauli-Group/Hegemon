import Hegemon.Bytes

namespace Hegemon
namespace Native
namespace TxLeafArtifact

def digestWidth : Nat := 48
def shortDigestWidth : Nat := 32
def maxInputs : Nat := 2
def maxOutputs : Nat := 2
def balanceSlots : Nat := 4
def matrixRows : Nat := 11
def matrixCols : Nat := 54
def maxNativeTxStarkProofBytes : Nat := 512 * 1024

def txProofBackendPlonky3 : Nat := 1
def txProofBackendSmallwood : Nat := 2
def circuitV2 : Nat := 2
def cryptoSuiteBeta : Nat := 2
def cryptoSuiteGamma : Nat := 3

structure SerializedSummary where
  inputFlagCount : Nat
  outputFlagCount : Nat
  balanceSlotCount : Nat
deriving DecidableEq, Repr

structure PublicTxSummary where
  nullifierCount : Nat
  commitmentCount : Nat
  ciphertextHashCount : Nat
  circuitVersion : Nat
  cryptoSuite : Nat
deriving DecidableEq, Repr

structure CommitmentSummary where
  rowCount : Nat
  rowCoeffCounts : List Nat
deriving DecidableEq, Repr

structure TxLeafSummary where
  version : Nat
  serialized : SerializedSummary
  publicTx : PublicTxSummary
  starkProofLen : Nat
  commitment : CommitmentSummary
  leafVersion : Nat
  hasExplicitBackend : Bool
  proofBackend : Nat
deriving DecidableEq, Repr

structure TxLeafProjectionCountCase where
  name : String
  inputFlags : List Byte
  outputFlags : List Byte
  nullifierCount : Nat
  commitmentCount : Nat
  ciphertextHashCount : Nat
deriving DecidableEq, Repr

def leValue : List Byte -> Nat
  | [] => 0
  | byteValue :: rest => byte byteValue + 256 * leValue rest

def takeBytes (count : Nat) (input : List Byte) : Option (List Byte × List Byte) :=
  if count <= input.length then
    some (input.take count, input.drop count)
  else
    none

def skipBytes (count : Nat) (input : List Byte) : Option (List Byte) := do
  let (_, rest) ← takeBytes count input
  some rest

def readNat (width : Nat) (input : List Byte) : Option (Nat × List Byte) := do
  let (raw, rest) ← takeBytes width input
  some (leValue raw, rest)

def readU8 : List Byte -> Option (Nat × List Byte) :=
  readNat 1

def readU16 : List Byte -> Option (Nat × List Byte) :=
  readNat 2

def readU32 : List Byte -> Option (Nat × List Byte) :=
  readNat 4

def readCappedU32 (cap : Nat) (input : List Byte) : Option (Nat × List Byte) := do
  let (value, rest) ← readU32 input
  if value <= cap then
    some (value, rest)
  else
    none

def skipFixedItems : Nat -> Nat -> List Byte -> Option (List Byte)
  | 0, _, input => some input
  | count + 1, width, input => do
      let rest ← skipBytes width input
      skipFixedItems count width rest

def parseSerializedInputs (input : List Byte) : Option (SerializedSummary × List Byte) := do
  let (inputFlagCount, rest0) ← readCappedU32 maxInputs input
  let rest1 ← skipBytes inputFlagCount rest0
  let (outputFlagCount, rest2) ← readCappedU32 maxOutputs rest1
  let rest3 ← skipBytes outputFlagCount rest2
  let rest4 ← skipBytes 8 rest3
  let rest5 ← skipBytes 1 rest4
  let rest6 ← skipBytes 8 rest5
  let rest7 ← skipBytes digestWidth rest6
  let (balanceSlotCount, rest8) ← readCappedU32 balanceSlots rest7
  let rest9 ← skipBytes (balanceSlotCount * 8) rest8
  let rest10 ← skipBytes 1 rest9
  let rest11 ← skipBytes 8 rest10
  let rest12 ← skipBytes 4 rest11
  let rest13 ← skipBytes 1 rest12
  let rest14 ← skipBytes 8 rest13
  let rest15 ← skipBytes (digestWidth * 3) rest14
  some ({ inputFlagCount, outputFlagCount, balanceSlotCount }, rest15)

def parsePublicTx (input : List Byte) : Option (PublicTxSummary × List Byte) := do
  let (nullifierCount, rest0) ← readCappedU32 maxInputs input
  let rest1 ← skipFixedItems nullifierCount digestWidth rest0
  let (commitmentCount, rest2) ← readCappedU32 maxOutputs rest1
  let rest3 ← skipFixedItems commitmentCount digestWidth rest2
  let (ciphertextHashCount, rest4) ← readCappedU32 maxOutputs rest3
  let rest5 ← skipFixedItems ciphertextHashCount digestWidth rest4
  let rest6 ← skipBytes digestWidth rest5
  let (circuitVersion, rest7) ← readU16 rest6
  let (cryptoSuite, rest8) ← readU16 rest7
  some ({ nullifierCount, commitmentCount, ciphertextHashCount, circuitVersion, cryptoSuite }, rest8)

def parseRows : Nat -> List Byte -> Option (List Nat × List Byte)
  | 0, input => some ([], input)
  | count + 1, input => do
      let (coeffCount, rest0) ← readCappedU32 matrixCols input
      let rest1 ← skipBytes (coeffCount * 8) rest0
      let (tail, rest2) ← parseRows count rest1
      some (coeffCount :: tail, rest2)

def parseCommitment (input : List Byte) : Option (CommitmentSummary × List Byte) := do
  let rest0 ← skipBytes digestWidth input
  let (rowCount, rest1) ← readCappedU32 matrixRows rest0
  let (rowCoeffCounts, rest2) ← parseRows rowCount rest1
  some ({ rowCount, rowCoeffCounts }, rest2)

def parseLeafArtifact (input : List Byte) : Option (Nat × List Byte) := do
  let (leafVersion, rest0) ← readU16 input
  let rest1 ← skipBytes shortDigestWidth rest0
  let rest2 ← skipBytes shortDigestWidth rest1
  let rest3 ← skipBytes digestWidth rest2
  let rest4 ← skipBytes digestWidth rest3
  let rest5 ← skipBytes digestWidth rest4
  some (leafVersion, rest5)

def validBackendWire (wire : Nat) : Bool :=
  wire = txProofBackendPlonky3 || wire = txProofBackendSmallwood

def defaultBackendForVersion (circuitVersion cryptoSuite : Nat) : Nat :=
  if circuitVersion = circuitV2 && cryptoSuite = cryptoSuiteGamma then
    txProofBackendPlonky3
  else if circuitVersion = circuitV2 && cryptoSuite = cryptoSuiteBeta then
    txProofBackendSmallwood
  else
    txProofBackendSmallwood

def parseBackend (defaultBackend : Nat) (input : List Byte) : Option (Bool × Nat) :=
  match input with
  | [] => some (false, defaultBackend)
  | [wire] =>
      if validBackendWire wire then
        some (true, wire)
      else
        none
  | _ :: _ :: _ => none

def parseNativeTxLeafArtifact (input : List Byte) : Option TxLeafSummary := do
  let (version, rest0) ← readU16 input
  let rest1 ← skipBytes digestWidth rest0
  let rest2 ← skipBytes shortDigestWidth rest1
  let rest3 ← skipBytes shortDigestWidth rest2
  let rest4 ← skipBytes shortDigestWidth rest3
  let rest5 ← skipBytes digestWidth rest4
  let rest6 ← skipBytes (digestWidth * 4) rest5
  let (serialized, rest7) ← parseSerializedInputs rest6
  let (publicTx, rest8) ← parsePublicTx rest7
  let (starkProofLen, rest9) ← readCappedU32 maxNativeTxStarkProofBytes rest8
  let rest10 ← skipBytes starkProofLen rest9
  let (commitment, rest11) ← parseCommitment rest10
  let (leafVersion, rest12) ← parseLeafArtifact rest11
  let defaultBackend := defaultBackendForVersion publicTx.circuitVersion publicTx.cryptoSuite
  let (hasExplicitBackend, proofBackend) ← parseBackend defaultBackend rest12
  some {
    version,
    serialized,
    publicTx,
    starkProofLen,
    commitment,
    leafVersion,
    hasExplicitBackend,
    proofBackend
  }

def parseNativeTxLeafArtifactStrict (input : List Byte) : Option TxLeafSummary := do
  let summary ← parseNativeTxLeafArtifact input
  if summary.hasExplicitBackend then
    some summary
  else
    none

def activeBinaryFlagCount : List Byte -> Option Nat
  | [] => some 0
  | flag :: rest => do
      let tail ← activeBinaryFlagCount rest
      if flag = 0 then
        some tail
      else if flag = 1 then
        some (tail + 1)
      else
        none

def txLeafProjectionCountAccepts
    (case : TxLeafProjectionCountCase) : Bool :=
  match activeBinaryFlagCount case.inputFlags,
      activeBinaryFlagCount case.outputFlags with
  | some inputActive, some outputActive =>
      inputActive == case.nullifierCount
        && outputActive == case.commitmentCount
        && outputActive == case.ciphertextHashCount
  | _, _ => false

structure TxLeafWireFields where
  version : Nat
  inputFlags : List Byte
  outputFlags : List Byte
  fee : Nat
  valueBalanceSign : Nat
  valueBalanceMagnitude : Nat
  balanceSlotAssetIds : List Nat
  stablecoinEnabled : Nat
  stablecoinAssetId : Nat
  stablecoinPolicyVersion : Nat
  stablecoinIssuanceSign : Nat
  stablecoinIssuanceMagnitude : Nat
  nullifiers : List (List Byte)
  commitments : List (List Byte)
  ciphertextHashes : List (List Byte)
  circuitVersion : Nat
  cryptoSuite : Nat
  starkProofLen : Nat
  starkProofBytes : List Byte
  commitmentRows : List (List Nat)
  leafVersion : Nat
  proofBackend : Option Nat
deriving DecidableEq, Repr

def digest32 (seed : Nat) : List Byte :=
  patternedBytes shortDigestWidth seed

def digest48 (seed : Nat) : List Byte :=
  patternedBytes digestWidth seed

def concatByteLists : List (List Byte) -> List Byte
  | [] => []
  | bytes :: rest => bytes ++ concatByteLists rest

def encodeNat64s (values : List Nat) : List Byte :=
  concatByteLists (values.map u64le)

def encodeDigests (values : List (List Byte)) : List Byte :=
  concatByteLists values

def encodeSerializedInputs (fields : TxLeafWireFields) : List Byte :=
  u32le fields.inputFlags.length
    ++ fields.inputFlags
    ++ u32le fields.outputFlags.length
    ++ fields.outputFlags
    ++ u64le fields.fee
    ++ [byte fields.valueBalanceSign]
    ++ u64le fields.valueBalanceMagnitude
    ++ digest48 0x90
    ++ u32le fields.balanceSlotAssetIds.length
    ++ encodeNat64s fields.balanceSlotAssetIds
    ++ [byte fields.stablecoinEnabled]
    ++ u64le fields.stablecoinAssetId
    ++ u32le fields.stablecoinPolicyVersion
    ++ [byte fields.stablecoinIssuanceSign]
    ++ u64le fields.stablecoinIssuanceMagnitude
    ++ digest48 0xa0
    ++ digest48 0xb0
    ++ digest48 0xc0

def encodePublicTx (fields : TxLeafWireFields) : List Byte :=
  u32le fields.nullifiers.length
    ++ encodeDigests fields.nullifiers
    ++ u32le fields.commitments.length
    ++ encodeDigests fields.commitments
    ++ u32le fields.ciphertextHashes.length
    ++ encodeDigests fields.ciphertextHashes
    ++ digest48 0xd0
    ++ u16le fields.circuitVersion
    ++ u16le fields.cryptoSuite

def encodeRows (rows : List (List Nat)) : List Byte :=
  concatByteLists (rows.map fun row => u32le row.length ++ encodeNat64s row)

def encodeCommitment (fields : TxLeafWireFields) : List Byte :=
  digest48 0xe0
    ++ u32le fields.commitmentRows.length
    ++ encodeRows fields.commitmentRows

def encodeLeafArtifact (fields : TxLeafWireFields) : List Byte :=
  u16le fields.leafVersion
    ++ digest32 0xf0
    ++ digest32 0xf1
    ++ digest48 0xf2
    ++ digest48 0xf3
    ++ digest48 0xf4

def encodeBackend (fields : TxLeafWireFields) : List Byte :=
  match fields.proofBackend with
  | none => []
  | some wire => [byte wire]

def artifactBytes (fields : TxLeafWireFields) : List Byte :=
  u16le fields.version
    ++ digest48 0x10
    ++ digest32 0x20
    ++ digest32 0x30
    ++ digest32 0x40
    ++ digest48 0x50
    ++ digest48 0x60
    ++ digest48 0x61
    ++ digest48 0x62
    ++ digest48 0x63
    ++ encodeSerializedInputs fields
    ++ encodePublicTx fields
    ++ u32le fields.starkProofLen
    ++ fields.starkProofBytes
    ++ encodeCommitment fields
    ++ encodeLeafArtifact fields
    ++ encodeBackend fields

def validFields : TxLeafWireFields := {
  version := 7,
  inputFlags := [1, 0],
  outputFlags := [1],
  fee := 99,
  valueBalanceSign := 1,
  valueBalanceMagnitude := 5,
  balanceSlotAssetIds := [3, 4],
  stablecoinEnabled := 1,
  stablecoinAssetId := 77,
  stablecoinPolicyVersion := 2,
  stablecoinIssuanceSign := 0,
  stablecoinIssuanceMagnitude := 11,
  nullifiers := [digest48 0x70, digest48 0x71],
  commitments := [digest48 0x72],
  ciphertextHashes := [digest48 0x73, digest48 0x74],
  circuitVersion := 13,
  cryptoSuite := 21,
  starkProofLen := 3,
  starkProofBytes := [0xaa, 0xbb, 0xcc],
  commitmentRows := [[1, 2, 3], [4]],
  leafVersion := 5,
  proofBackend := some txProofBackendSmallwood
}

def validSummary : TxLeafSummary := {
  version := 7,
  serialized := {
    inputFlagCount := 2,
    outputFlagCount := 1,
    balanceSlotCount := 2
  },
  publicTx := {
    nullifierCount := 2,
    commitmentCount := 1,
    ciphertextHashCount := 2,
    circuitVersion := 13,
    cryptoSuite := 21
  },
  starkProofLen := 3,
  commitment := {
    rowCount := 2,
    rowCoeffCounts := [3, 1]
  },
  leafVersion := 5,
  hasExplicitBackend := true,
  proofBackend := txProofBackendSmallwood
}

def validArtifact : List Byte :=
  artifactBytes validFields

def missingBackendArtifact : List Byte :=
  artifactBytes { validFields with proofBackend := none }

def missingBackendSummary : TxLeafSummary :=
  { validSummary with hasExplicitBackend := false, proofBackend := txProofBackendSmallwood }

def legacyMissingBackendArtifact : List Byte :=
  artifactBytes { validFields with
    circuitVersion := circuitV2,
    cryptoSuite := cryptoSuiteGamma,
    proofBackend := none
  }

def legacyMissingBackendSummary : TxLeafSummary :=
  { validSummary with
    publicTx := { validSummary.publicTx with circuitVersion := circuitV2, cryptoSuite := cryptoSuiteGamma },
    hasExplicitBackend := false,
    proofBackend := txProofBackendPlonky3
  }

def badBackendArtifact : List Byte :=
  artifactBytes { validFields with proofBackend := some 9 }

def trailingArtifact : List Byte :=
  validArtifact ++ [0]

def tooManyInputFlagsArtifact : List Byte :=
  artifactBytes { validFields with inputFlags := [0, 1, 0] }

def tooManyOutputFlagsArtifact : List Byte :=
  artifactBytes { validFields with outputFlags := [0, 1, 0] }

def tooManyBalanceSlotsArtifact : List Byte :=
  artifactBytes { validFields with balanceSlotAssetIds := [1, 2, 3, 4, 5] }

def tooManyNullifiersArtifact : List Byte :=
  artifactBytes { validFields with nullifiers := [digest48 1, digest48 2, digest48 3] }

def tooManyCommitmentsArtifact : List Byte :=
  artifactBytes { validFields with commitments := [digest48 1, digest48 2, digest48 3] }

def tooManyCiphertextHashesArtifact : List Byte :=
  artifactBytes { validFields with ciphertextHashes := [digest48 1, digest48 2, digest48 3] }

def tooManyRowsArtifact : List Byte :=
  artifactBytes { validFields with commitmentRows := List.replicate 12 [] }

def tooManyRowCoeffsArtifact : List Byte :=
  artifactBytes { validFields with commitmentRows := [List.range 55] }

def oversizedProofLenArtifact : List Byte :=
  artifactBytes { validFields with starkProofLen := maxNativeTxStarkProofBytes + 1, starkProofBytes := [] }

def truncatedArtifact : List Byte :=
  validArtifact.take (validArtifact.length - 2)

def validProjectionCounts : TxLeafProjectionCountCase := {
  name := "active-counts-match",
  inputFlags := [1, 0],
  outputFlags := [1, 0],
  nullifierCount := 1,
  commitmentCount := 1,
  ciphertextHashCount := 1
}

def inputCountMismatchProjectionCounts : TxLeafProjectionCountCase :=
  { validProjectionCounts with
    name := "input-active-count-mismatch",
    nullifierCount := 2 }

def outputCommitmentCountMismatchProjectionCounts : TxLeafProjectionCountCase :=
  { validProjectionCounts with
    name := "output-commitment-count-mismatch",
    commitmentCount := 0 }

def outputCiphertextCountMismatchProjectionCounts : TxLeafProjectionCountCase :=
  { validProjectionCounts with
    name := "output-ciphertext-count-mismatch",
    ciphertextHashCount := 2 }

def nonbinaryInputFlagProjectionCounts : TxLeafProjectionCountCase :=
  { validProjectionCounts with
    name := "nonbinary-input-flag-rejected",
    inputFlags := [2, 0] }

def nonbinaryOutputFlagProjectionCounts : TxLeafProjectionCountCase :=
  { validProjectionCounts with
    name := "nonbinary-output-flag-rejected",
    outputFlags := [1, 2] }

def allProjectionCountCases : List TxLeafProjectionCountCase :=
  [ validProjectionCounts,
    inputCountMismatchProjectionCounts,
    outputCommitmentCountMismatchProjectionCounts,
    outputCiphertextCountMismatchProjectionCounts,
    nonbinaryInputFlagProjectionCounts,
    nonbinaryOutputFlagProjectionCounts
  ]

theorem valid_artifact_parses :
    parseNativeTxLeafArtifact validArtifact = some validSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem missing_backend_defaults_to_current_backend :
    parseNativeTxLeafArtifact missingBackendArtifact = some missingBackendSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem legacy_missing_backend_defaults_to_plonky3 :
    parseNativeTxLeafArtifact legacyMissingBackendArtifact = some legacyMissingBackendSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem strict_valid_artifact_parses :
    parseNativeTxLeafArtifactStrict validArtifact = some validSummary := by
  set_option maxRecDepth 50000 in
  decide

theorem strict_missing_backend_rejects :
    parseNativeTxLeafArtifactStrict missingBackendArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem strict_legacy_missing_backend_rejects :
    parseNativeTxLeafArtifactStrict legacyMissingBackendArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_trailing_after_backend :
    parseNativeTxLeafArtifact trailingArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_bad_backend :
    parseNativeTxLeafArtifact badBackendArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_input_flags :
    parseNativeTxLeafArtifact tooManyInputFlagsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_output_flags :
    parseNativeTxLeafArtifact tooManyOutputFlagsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_balance_slots :
    parseNativeTxLeafArtifact tooManyBalanceSlotsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_nullifiers :
    parseNativeTxLeafArtifact tooManyNullifiersArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_commitments :
    parseNativeTxLeafArtifact tooManyCommitmentsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_ciphertext_hashes :
    parseNativeTxLeafArtifact tooManyCiphertextHashesArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_rows :
    parseNativeTxLeafArtifact tooManyRowsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_too_many_row_coefficients :
    parseNativeTxLeafArtifact tooManyRowCoeffsArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_oversized_proof_len :
    parseNativeTxLeafArtifact oversizedProofLenArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem rejects_truncated_artifact :
    parseNativeTxLeafArtifact truncatedArtifact = none := by
  set_option maxRecDepth 50000 in
  decide

theorem valid_projection_counts_accept :
    txLeafProjectionCountAccepts validProjectionCounts = true := by
  decide

theorem input_count_mismatch_projection_rejects :
    txLeafProjectionCountAccepts inputCountMismatchProjectionCounts = false := by
  decide

theorem output_commitment_count_mismatch_projection_rejects :
    txLeafProjectionCountAccepts
      outputCommitmentCountMismatchProjectionCounts = false := by
  decide

theorem output_ciphertext_count_mismatch_projection_rejects :
    txLeafProjectionCountAccepts
      outputCiphertextCountMismatchProjectionCounts = false := by
  decide

theorem nonbinary_input_flag_projection_rejects :
    txLeafProjectionCountAccepts nonbinaryInputFlagProjectionCounts = false := by
  decide

theorem nonbinary_output_flag_projection_rejects :
    txLeafProjectionCountAccepts nonbinaryOutputFlagProjectionCounts = false := by
  decide

end TxLeafArtifact
end Native
end Hegemon
