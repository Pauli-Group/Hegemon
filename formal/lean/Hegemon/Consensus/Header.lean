import Hegemon.Bytes

namespace Hegemon
namespace Consensus
namespace Header

structure DaParams where
  chunkSize : Nat
  sampleCount : Nat
  deriving Repr, DecidableEq

structure PowSeal where
  nonce : List Byte
  powBits : Nat
  deriving Repr, DecidableEq

structure BlockHeader where
  version : Nat
  height : Nat
  view : Nat
  timestampMs : Nat
  parentHash : List Byte
  stateRoot : List Byte
  kernelRoot : List Byte
  nullifierRoot : List Byte
  proofCommitment : List Byte
  daRoot : List Byte
  daParams : DaParams
  versionCommitment : List Byte
  txCount : Nat
  feeCommitment : List Byte
  supplyDigest : Nat
  validatorSetCommitment : List Byte
  signatureAggregate : List Byte
  signatureBitmap : Option (List Byte)
  pow : Option PowSeal
  deriving Repr, DecidableEq

def encodeSigningFields (header : BlockHeader) : List Byte :=
  u32le header.version
    ++ u64le header.height
    ++ u64le header.view
    ++ u64le header.timestampMs
    ++ header.parentHash
    ++ header.stateRoot
    ++ header.kernelRoot
    ++ header.nullifierRoot
    ++ header.proofCommitment
    ++ header.daRoot
    ++ u32le header.daParams.chunkSize
    ++ u32le header.daParams.sampleCount
    ++ header.versionCommitment
    ++ u32le header.txCount
    ++ header.feeCommitment
    ++ u128le header.supplyDigest
    ++ header.validatorSetCommitment

def signingPreimage (header : BlockHeader) : List Byte :=
  asciiBytes "block" ++ encodeSigningFields header

def encodeOptionalBitmap : Option (List Byte) -> List Byte
  | none => [0]
  | some bitmap => [1] ++ u32le bitmap.length ++ bitmap

def encodeOptionalPow : Option PowSeal -> List Byte
  | none => [0]
  | some powSeal => [1] ++ powSeal.nonce ++ u32le powSeal.powBits

def fullHeaderPreimage (header : BlockHeader) : List Byte :=
  encodeSigningFields header
    ++ u32le header.signatureAggregate.length
    ++ header.signatureAggregate
    ++ encodeOptionalBitmap header.signatureBitmap
    ++ encodeOptionalPow header.pow

def sampleHeader : BlockHeader := {
  version := 16909060,
  height := 72623859790382856,
  view := 9,
  timestampMs := 1700000123456,
  parentHash := patternedBytes 32 1,
  stateRoot := patternedBytes 48 3,
  kernelRoot := patternedBytes 48 5,
  nullifierRoot := patternedBytes 48 7,
  proofCommitment := patternedBytes 48 11,
  daRoot := patternedBytes 48 13,
  daParams := { chunkSize := 4096, sampleCount := 16 },
  versionCommitment := patternedBytes 48 17,
  txCount := 3,
  feeCommitment := patternedBytes 48 19,
  supplyDigest := 3333333333333333333,
  validatorSetCommitment := patternedBytes 48 23,
  signatureAggregate := patternedBytes 4 29,
  signatureBitmap := none,
  pow := some { nonce := patternedBytes 32 31, powBits := 505515503 }
}

def bftHeader : BlockHeader := {
  sampleHeader with
  signatureAggregate := patternedBytes 6 101,
  signatureBitmap := some (patternedBytes 3 131),
  pow := none
}

def unsignedHeader : BlockHeader := {
  sampleHeader with
  signatureAggregate := [],
  signatureBitmap := none,
  pow := none
}

theorem signingPreimage_independent_of_auth_payloads
    (header : BlockHeader)
    (signatureAggregate : List Byte)
    (signatureBitmap : Option (List Byte))
    (pow : Option PowSeal) :
    signingPreimage {
      header with
      signatureAggregate := signatureAggregate,
      signatureBitmap := signatureBitmap,
      pow := pow
    } = signingPreimage header := by
  rfl

theorem sample_signing_preimage_length :
    (signingPreimage sampleHeader).length = 477 := by
  native_decide

theorem sample_pow_full_header_length :
    (fullHeaderPreimage sampleHeader).length = 518 := by
  native_decide

theorem bft_full_header_length :
    (fullHeaderPreimage bftHeader).length = 491 := by
  native_decide

theorem unsigned_full_header_length :
    (fullHeaderPreimage unsignedHeader).length = 478 := by
  native_decide

theorem pow_header_has_pow_tag :
    encodeOptionalPow sampleHeader.pow =
      [1] ++ patternedBytes 32 31 ++ u32le 505515503 := by
  native_decide

theorem bft_header_has_bitmap_tag :
    encodeOptionalBitmap bftHeader.signatureBitmap =
      [1] ++ u32le 3 ++ patternedBytes 3 131 := by
  native_decide

theorem unsigned_header_has_absent_auth_tags :
    encodeOptionalBitmap unsignedHeader.signatureBitmap
      ++ encodeOptionalPow unsignedHeader.pow = [0, 0] := by
  native_decide

end Header
end Consensus
end Hegemon
