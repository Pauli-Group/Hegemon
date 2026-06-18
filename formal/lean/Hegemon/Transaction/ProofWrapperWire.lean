import Hegemon.Bytes

namespace Hegemon
namespace Transaction
namespace ProofWrapperWire

inductive ProofWrapperWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

structure ProofWrapperWireCase where
  name : String
  rawBytes : List Byte
  canonicalBytes : List Byte
  parserAccepts : Bool
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

def canonicalBytesMatch (case : ProofWrapperWireCase) : Bool :=
  case.rawBytes == case.canonicalBytes

def evaluateProofWrapperWireRejection
    (case : ProofWrapperWireCase) : Option ProofWrapperWireReject :=
  if case.parserAccepts = false then
    some ProofWrapperWireReject.parserRejected
  else if case.consumedAllBytes = false then
    some ProofWrapperWireReject.trailingBytes
  else if case.canonicalReencodeMatches = false then
    some ProofWrapperWireReject.nonCanonicalEncoding
  else if canonicalBytesMatch case = false then
    some ProofWrapperWireReject.nonCanonicalEncoding
  else
    none

def proofWrapperWireAccepts (case : ProofWrapperWireCase) : Bool :=
  evaluateProofWrapperWireRejection case = none

def concatByteLists : List (List Byte) -> List Byte
  | [] => []
  | bytes :: rest => bytes ++ concatByteLists rest

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def zeroBytes (length : Nat) : List Byte :=
  repeated length 0

def bincodeBytes (bytes : List Byte) : List Byte :=
  u64le bytes.length ++ bytes

def bincodeVecU8 (bytes : List Byte) : List Byte :=
  bincodeBytes bytes

def bincodeBool (value : Bool) : List Byte :=
  if value then [1] else [0]

def bincodeEnumVariant (index : Nat) : List Byte :=
  u32le index

def bincodeOption : Option (List Byte) -> List Byte
  | none => [0]
  | some payload => [1] ++ payload

def bincodeVecU64 (values : List Nat) : List Byte :=
  u64le values.length ++ concatByteLists (values.map u64le)

def bincodeBalanceSlots (assetIds : List Nat) : List Byte :=
  u64le assetIds.length ++
    concatByteLists (assetIds.map fun assetId => u64le assetId ++ u128le 0)

def digest48 : List Byte :=
  zeroBytes 48

def digest48Bytes : List Byte :=
  bincodeBytes digest48

def maxInputs : Nat := 2
def maxOutputs : Nat := 2
def balanceSlots : Nat := 4
def paddingAssetId : Nat := 18446744073709551615
def paddingFieldId : Nat := 4294967294
def legacyPlonky3CircuitVersion : Nat := 2
def legacyPlonky3CryptoSuite : Nat := 3
def plonky3BackendVariant : Nat := 0
def invalidBackendVariant : Nat := 99

def defaultBalanceSlotAssetIds : List Nat :=
  [0, paddingAssetId, paddingAssetId, paddingAssetId]

def serializedBalanceSlotAssetIds : List Nat :=
  [0, paddingFieldId, paddingFieldId, paddingFieldId]

def defaultStablecoinBindingBytes : List Byte :=
  bincodeBool false
    ++ u64le 0
    ++ digest48Bytes
    ++ digest48Bytes
    ++ digest48Bytes
    ++ u128le 0
    ++ u32le 0

def transactionPublicInputsBytes : List Byte :=
  digest48Bytes
    ++ bincodeBytes (zeroBytes (maxInputs * 48))
    ++ bincodeBytes (zeroBytes (maxOutputs * 48))
    ++ bincodeBytes (zeroBytes (maxOutputs * 48))
    ++ bincodeBalanceSlots defaultBalanceSlotAssetIds
    ++ u64le 0
    ++ u128le 0
    ++ defaultStablecoinBindingBytes
    ++ digest48Bytes
    ++ u16le legacyPlonky3CircuitVersion
    ++ u16le legacyPlonky3CryptoSuite

def serializedStarkInputsBytes : List Byte :=
  bincodeVecU8 [0, 0]
    ++ bincodeVecU8 [0, 0]
    ++ u64le 0
    ++ [0]
    ++ u64le 0
    ++ digest48Bytes
    ++ bincodeVecU64 serializedBalanceSlotAssetIds
    ++ [0]
    ++ u64le 0
    ++ u32le 0
    ++ [0]
    ++ u64le 0
    ++ digest48Bytes
    ++ digest48Bytes
    ++ digest48Bytes

def transactionProofWrapperPrefixBeforeBackend : List Byte :=
  transactionPublicInputsBytes
    ++ bincodeBytes (zeroBytes (maxInputs * 48))
    ++ bincodeBytes (zeroBytes (maxOutputs * 48))
    ++ bincodeBalanceSlots defaultBalanceSlotAssetIds

def transactionProofWrapperSuffixAfterBackend : List Byte :=
  bincodeVecU8 [1, 2, 3, 4]
    ++ bincodeOption (some serializedStarkInputsBytes)

def transactionProofWrapperBytesWithBackendVariant
    (variant : Nat) : List Byte :=
  transactionProofWrapperPrefixBeforeBackend
    ++ bincodeEnumVariant variant
    ++ transactionProofWrapperSuffixAfterBackend

def canonicalDummyProofWrapperBytes : List Byte :=
  transactionProofWrapperBytesWithBackendVariant plonky3BackendVariant

def trailingDummyProofWrapperBytes : List Byte :=
  canonicalDummyProofWrapperBytes ++ [0xaa, 0xbb]

def invalidBackendProofWrapperBytes : List Byte :=
  transactionProofWrapperBytesWithBackendVariant invalidBackendVariant

def truncatedProofWrapperBytes : List Byte :=
  canonicalDummyProofWrapperBytes.take 32

def malformedProofWrapperBytes : List Byte :=
  [0xff, 0x00, 0x01]

def validDummyProofWrapper : ProofWrapperWireCase :=
  { name := "valid-dummy-proof-wrapper"
    rawBytes := canonicalDummyProofWrapperBytes
    canonicalBytes := canonicalDummyProofWrapperBytes
    parserAccepts := true
    consumedAllBytes := true
    canonicalReencodeMatches := true }

def trailingDummyProofWrapper : ProofWrapperWireCase :=
  { name := "trailing-dummy-proof-wrapper"
    rawBytes := trailingDummyProofWrapperBytes
    canonicalBytes := canonicalDummyProofWrapperBytes
    parserAccepts := true
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def invalidBackendProofWrapper : ProofWrapperWireCase :=
  { name := "invalid-backend-proof-wrapper"
    rawBytes := invalidBackendProofWrapperBytes
    canonicalBytes := canonicalDummyProofWrapperBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def truncatedProofWrapper : ProofWrapperWireCase :=
  { name := "truncated-proof-wrapper"
    rawBytes := truncatedProofWrapperBytes
    canonicalBytes := canonicalDummyProofWrapperBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def malformedProofWrapper : ProofWrapperWireCase :=
  { name := "malformed-proof-wrapper"
    rawBytes := malformedProofWrapperBytes
    canonicalBytes := canonicalDummyProofWrapperBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def allCases : List ProofWrapperWireCase :=
  [ validDummyProofWrapper
  , trailingDummyProofWrapper
  , invalidBackendProofWrapper
  , truncatedProofWrapper
  , malformedProofWrapper
  ]

set_option maxRecDepth 200000 in
theorem valid_dummy_proof_wrapper_accepts :
    proofWrapperWireAccepts validDummyProofWrapper = true := by
  decide

set_option maxRecDepth 200000 in
theorem trailing_dummy_proof_wrapper_rejects :
    evaluateProofWrapperWireRejection trailingDummyProofWrapper =
      some ProofWrapperWireReject.trailingBytes := by
  decide

set_option maxRecDepth 200000 in
theorem invalid_backend_proof_wrapper_rejects :
    evaluateProofWrapperWireRejection invalidBackendProofWrapper =
      some ProofWrapperWireReject.parserRejected := by
  decide

set_option maxRecDepth 200000 in
theorem truncated_proof_wrapper_rejects :
    evaluateProofWrapperWireRejection truncatedProofWrapper =
      some ProofWrapperWireReject.parserRejected := by
  decide

set_option maxRecDepth 200000 in
theorem malformed_proof_wrapper_rejects :
    evaluateProofWrapperWireRejection malformedProofWrapper =
      some ProofWrapperWireReject.parserRejected := by
  decide

end ProofWrapperWire
end Transaction
end Hegemon
