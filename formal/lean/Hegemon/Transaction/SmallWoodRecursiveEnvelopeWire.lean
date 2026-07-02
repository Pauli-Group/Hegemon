import Hegemon.Bytes

namespace Hegemon
namespace Transaction
namespace SmallWoodRecursiveEnvelopeWire

inductive RecursiveEnvelopeWireReject where
  | parserRejected
  | trailingBytes
  | nonCanonicalEncoding
deriving DecidableEq, Repr

inductive RecursiveEnvelopeAdmissionReject where
  | descriptorMismatch
deriving DecidableEq, Repr

structure RecursiveEnvelopeWireCase where
  name : String
  rawBytes : List Byte
  canonicalBytes : List Byte
  parserAccepts : Bool
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
deriving DecidableEq, Repr

structure RecursiveEnvelopeAdmissionCase where
  name : String
  rawBytes : List Byte
  expectedDescriptorBytes : List Byte
  wireAccepts : Bool
  descriptorMatches : Bool
  expectedAdmissionReject : Option RecursiveEnvelopeAdmissionReject
deriving DecidableEq, Repr

def canonicalBytesMatch (case : RecursiveEnvelopeWireCase) : Bool :=
  case.rawBytes == case.canonicalBytes

def evaluateRecursiveEnvelopeWire
    (case : RecursiveEnvelopeWireCase) :
    Option RecursiveEnvelopeWireReject :=
  if case.parserAccepts = false then
    some RecursiveEnvelopeWireReject.parserRejected
  else if case.consumedAllBytes = false then
    some RecursiveEnvelopeWireReject.trailingBytes
  else if case.canonicalReencodeMatches = false then
    some RecursiveEnvelopeWireReject.nonCanonicalEncoding
  else if canonicalBytesMatch case = false then
    some RecursiveEnvelopeWireReject.nonCanonicalEncoding
  else
    none

def recursiveEnvelopeWireAccepts
    (case : RecursiveEnvelopeWireCase) : Bool :=
  evaluateRecursiveEnvelopeWire case = none

def evaluateRecursiveEnvelopeAdmission
    (case : RecursiveEnvelopeAdmissionCase) :
    Option RecursiveEnvelopeAdmissionReject :=
  if case.wireAccepts = false then
    none
  else if case.descriptorMatches = false then
    some RecursiveEnvelopeAdmissionReject.descriptorMismatch
  else
    none

def recursiveEnvelopeAdmissionAccepts
    (case : RecursiveEnvelopeAdmissionCase) : Bool :=
  case.wireAccepts = true
    && evaluateRecursiveEnvelopeAdmission case = none

def concatByteLists : List (List Byte) -> List Byte
  | [] => []
  | bytes :: rest => bytes ++ concatByteLists rest

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def patterned (length seed : Nat) : List Byte :=
  patternedBytes length seed

def bincodeVecU8 (bytes : List Byte) : List Byte :=
  u64le bytes.length ++ bytes

def bincodeEnumVariant (index : Nat) : List Byte :=
  u32le index

def versionBindingBytes (circuit crypto : Nat) : List Byte :=
  u16le circuit ++ u16le crypto

def smallwoodRecursiveProfileA : Nat := 0
def smallwoodRecursiveProfileB : Nat := 1
def smallwoodRecursiveRelationBaseA : Nat := 0
def smallwoodRecursiveRelationStepB : Nat := 2
def smallwoodArithmetizationBridge64V1 : Nat := 0

def descriptorBytes
    (circuit crypto arith profile relation : Nat)
    (relationId shapeDigest vkDigest : List Byte) : List Byte :=
  versionBindingBytes circuit crypto
    ++ bincodeEnumVariant arith
    ++ bincodeEnumVariant profile
    ++ bincodeEnumVariant relation
    ++ relationId
    ++ shapeDigest
    ++ vkDigest

def envelopeBytes
    (descriptor proofBytes : List Byte) : List Byte :=
  descriptor ++ bincodeVecU8 proofBytes

def defaultDescriptor : List Byte :=
  descriptorBytes
    2
    2
    smallwoodArithmetizationBridge64V1
    smallwoodRecursiveProfileB
    smallwoodRecursiveRelationStepB
    (repeated 32 4)
    (repeated 32 5)
    (repeated 32 6)

def baseDescriptor : List Byte :=
  descriptorBytes
    2
    2
    smallwoodArithmetizationBridge64V1
    smallwoodRecursiveProfileA
    smallwoodRecursiveRelationBaseA
    (repeated 32 9)
    (repeated 32 10)
    (repeated 32 11)

def defaultProofBytes : List Byte :=
  repeated 17 7

def alternateProofBytes : List Byte :=
  patterned 19 0x21

def validEnvelopeBytes : List Byte :=
  envelopeBytes defaultDescriptor defaultProofBytes

def alternateEnvelopeBytes : List Byte :=
  envelopeBytes baseDescriptor alternateProofBytes

def trailingEnvelopeBytes : List Byte :=
  validEnvelopeBytes ++ [0xaa, 0xbb]

def truncatedEnvelopeBytes : List Byte :=
  validEnvelopeBytes.take 40

def invalidProfileEnvelopeBytes : List Byte :=
  envelopeBytes
    (descriptorBytes
      2
      2
      smallwoodArithmetizationBridge64V1
      99
      smallwoodRecursiveRelationStepB
      (repeated 32 4)
      (repeated 32 5)
      (repeated 32 6))
    defaultProofBytes

def truncatedProofVectorEnvelopeBytes : List Byte :=
  defaultDescriptor ++ u64le 64 ++ repeated 3 0x44

def validRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "valid-recursive-envelope"
    rawBytes := validEnvelopeBytes
    canonicalBytes := validEnvelopeBytes
    parserAccepts := true
    consumedAllBytes := true
    canonicalReencodeMatches := true }

def alternateRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "alternate-recursive-envelope"
    rawBytes := alternateEnvelopeBytes
    canonicalBytes := alternateEnvelopeBytes
    parserAccepts := true
    consumedAllBytes := true
    canonicalReencodeMatches := true }

def trailingRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "trailing-recursive-envelope"
    rawBytes := trailingEnvelopeBytes
    canonicalBytes := validEnvelopeBytes
    parserAccepts := true
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def truncatedRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "truncated-recursive-envelope"
    rawBytes := truncatedEnvelopeBytes
    canonicalBytes := validEnvelopeBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def invalidProfileRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "invalid-profile-recursive-envelope"
    rawBytes := invalidProfileEnvelopeBytes
    canonicalBytes := validEnvelopeBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def truncatedProofVectorRecursiveEnvelope : RecursiveEnvelopeWireCase :=
  { name := "truncated-proof-vector-recursive-envelope"
    rawBytes := truncatedProofVectorEnvelopeBytes
    canonicalBytes := validEnvelopeBytes
    parserAccepts := false
    consumedAllBytes := false
    canonicalReencodeMatches := false }

def allWireCases : List RecursiveEnvelopeWireCase :=
  [ validRecursiveEnvelope
  , alternateRecursiveEnvelope
  , trailingRecursiveEnvelope
  , truncatedRecursiveEnvelope
  , invalidProfileRecursiveEnvelope
  , truncatedProofVectorRecursiveEnvelope
  ]

def matchingDescriptorAdmission : RecursiveEnvelopeAdmissionCase :=
  { name := "matching-descriptor-admission"
    rawBytes := validEnvelopeBytes
    expectedDescriptorBytes := defaultDescriptor
    wireAccepts := true
    descriptorMatches := true
    expectedAdmissionReject := none }

def mismatchedDescriptorAdmission : RecursiveEnvelopeAdmissionCase :=
  { name := "mismatched-descriptor-admission"
    rawBytes := validEnvelopeBytes
    expectedDescriptorBytes := baseDescriptor
    wireAccepts := true
    descriptorMatches := false
    expectedAdmissionReject :=
      some RecursiveEnvelopeAdmissionReject.descriptorMismatch }

def allAdmissionCases : List RecursiveEnvelopeAdmissionCase :=
  [ matchingDescriptorAdmission
  , mismatchedDescriptorAdmission
  ]

set_option maxRecDepth 200000 in
theorem valid_recursive_envelope_accepts :
    recursiveEnvelopeWireAccepts validRecursiveEnvelope = true := by
  decide

set_option maxRecDepth 200000 in
theorem alternate_recursive_envelope_accepts :
    recursiveEnvelopeWireAccepts alternateRecursiveEnvelope = true := by
  decide

set_option maxRecDepth 200000 in
theorem trailing_recursive_envelope_rejects :
    evaluateRecursiveEnvelopeWire trailingRecursiveEnvelope =
      some RecursiveEnvelopeWireReject.trailingBytes := by
  decide

set_option maxRecDepth 200000 in
theorem truncated_recursive_envelope_rejects :
    evaluateRecursiveEnvelopeWire truncatedRecursiveEnvelope =
      some RecursiveEnvelopeWireReject.parserRejected := by
  decide

set_option maxRecDepth 200000 in
theorem invalid_profile_recursive_envelope_rejects :
    evaluateRecursiveEnvelopeWire invalidProfileRecursiveEnvelope =
      some RecursiveEnvelopeWireReject.parserRejected := by
  decide

set_option maxRecDepth 200000 in
theorem truncated_proof_vector_recursive_envelope_rejects :
    evaluateRecursiveEnvelopeWire truncatedProofVectorRecursiveEnvelope =
      some RecursiveEnvelopeWireReject.parserRejected := by
  decide

set_option maxRecDepth 200000 in
theorem matching_descriptor_admission_accepts :
    recursiveEnvelopeAdmissionAccepts matchingDescriptorAdmission = true := by
  decide

set_option maxRecDepth 200000 in
theorem mismatched_descriptor_admission_rejects :
    evaluateRecursiveEnvelopeAdmission mismatchedDescriptorAdmission =
      some RecursiveEnvelopeAdmissionReject.descriptorMismatch := by
  decide

end SmallWoodRecursiveEnvelopeWire
end Transaction
end Hegemon
