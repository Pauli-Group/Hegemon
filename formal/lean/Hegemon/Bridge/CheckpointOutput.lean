import Hegemon.Bytes

namespace Hegemon
namespace Bridge
namespace CheckpointOutput

def checkpointOutputDomain : List Byte :=
  asciiBytes "hegemon.bridge.checkpoint-output-v1"

def wireLength : Nat := 404

def canonicalPreimageLength : Nat :=
  checkpointOutputDomain.length + wireLength

structure OutputInput where
  sourceChainId : List Byte
  rulesHash : List Byte
  checkpointHeight : Nat
  checkpointHeaderHash : List Byte
  checkpointCumulativeWork : List Byte
  canonicalTipHeight : Nat
  canonicalTipHeaderHash : List Byte
  canonicalTipCumulativeWork : List Byte
  messageRoot : List Byte
  messageHash : List Byte
  messageNonce : Nat
  confirmationsChecked : Nat
  minWorkChecked : List Byte
deriving DecidableEq, Repr

def wireBytes (output : OutputInput) : List Byte :=
  output.sourceChainId
    ++ output.rulesHash
    ++ u64le output.checkpointHeight
    ++ output.checkpointHeaderHash
    ++ output.checkpointCumulativeWork
    ++ u64le output.canonicalTipHeight
    ++ output.canonicalTipHeaderHash
    ++ output.canonicalTipCumulativeWork
    ++ output.messageRoot
    ++ output.messageHash
    ++ u128le output.messageNonce
    ++ u32le output.confirmationsChecked
    ++ output.minWorkChecked

def canonicalPreimage (output : OutputInput) : List Byte :=
  checkpointOutputDomain ++ wireBytes output

def sampleMessageNonce : Nat :=
  88962710306127702866241727433142015

def sampleOutput : OutputInput :=
  {
    sourceChainId := patternedBytes 32 21,
    rulesHash := patternedBytes 32 22,
    checkpointHeight := 72623859790382856,
    checkpointHeaderHash := patternedBytes 32 23,
    checkpointCumulativeWork := patternedBytes 48 24,
    canonicalTipHeight := 1230066625199609624,
    canonicalTipHeaderHash := patternedBytes 32 25,
    canonicalTipCumulativeWork := patternedBytes 48 26,
    messageRoot := patternedBytes 48 27,
    messageHash := patternedBytes 48 28,
    messageNonce := sampleMessageNonce,
    confirmationsChecked := 16909060,
    minWorkChecked := patternedBytes 48 29
  }

def maxScalarOutput : OutputInput :=
  {
    sourceChainId := patternedBytes 32 41,
    rulesHash := patternedBytes 32 42,
    checkpointHeight := 18446744073709551615,
    checkpointHeaderHash := patternedBytes 32 43,
    checkpointCumulativeWork := patternedBytes 48 44,
    canonicalTipHeight := 18446744073709551615,
    canonicalTipHeaderHash := patternedBytes 32 45,
    canonicalTipCumulativeWork := patternedBytes 48 46,
    messageRoot := patternedBytes 48 47,
    messageHash := patternedBytes 48 48,
    messageNonce := 340282366920938463463374607431768211455,
    confirmationsChecked := 4294967295,
    minWorkChecked := patternedBytes 48 49
  }

theorem checkpoint_output_domain_bytes :
    checkpointOutputDomain =
      [104, 101, 103, 101, 109, 111, 110, 46, 98, 114, 105, 100, 103,
       101, 46, 99, 104, 101, 99, 107, 112, 111, 105, 110, 116, 45,
       111, 117, 116, 112, 117, 116, 45, 118, 49] := by
  decide

theorem checkpoint_output_domain_length :
    checkpointOutputDomain.length = 35 := by
  decide

theorem canonical_preimage_is_domain_prefixed_wire
    (output : OutputInput) :
    canonicalPreimage output = checkpointOutputDomain ++ wireBytes output := by
  rfl

theorem sample_wire_length :
    (wireBytes sampleOutput).length = wireLength := by
  simp [wireBytes, sampleOutput, wireLength, patternedBytes_length, u64le_length,
    u128le_length, u32le_length]

theorem sample_canonical_length :
    (canonicalPreimage sampleOutput).length = canonicalPreimageLength := by
  simp [canonicalPreimage, canonicalPreimageLength, sample_wire_length,
    checkpoint_output_domain_length]

theorem sample_canonical_length_exact :
    (canonicalPreimage sampleOutput).length = 439 := by
  simp [canonicalPreimage, sample_wire_length, checkpoint_output_domain_length, wireLength]

theorem max_scalar_wire_length :
    (wireBytes maxScalarOutput).length = wireLength := by
  simp [wireBytes, maxScalarOutput, wireLength, patternedBytes_length, u64le_length,
    u128le_length, u32le_length]

theorem max_scalar_canonical_length_exact :
    (canonicalPreimage maxScalarOutput).length = 439 := by
  simp [canonicalPreimage, max_scalar_wire_length, checkpoint_output_domain_length, wireLength]

theorem sample_wire_omits_domain :
    wireBytes sampleOutput ≠ canonicalPreimage sampleOutput := by
  intro h
  have lengths := congrArg List.length h
  simp [sample_wire_length, canonicalPreimage, checkpoint_output_domain_length, wireLength] at lengths

theorem sample_checkpoint_height_little_endian :
    u64le sampleOutput.checkpointHeight = [8, 7, 6, 5, 4, 3, 2, 1] := by
  decide

theorem sample_canonical_tip_height_little_endian :
    u64le sampleOutput.canonicalTipHeight =
      [24, 23, 22, 21, 20, 19, 18, 17] := by
  decide

theorem sample_message_nonce_little_endian :
    u128le sampleOutput.messageNonce =
      [255, 238, 221, 204, 187, 170, 153, 136,
       119, 102, 85, 68, 51, 34, 17, 0] := by
  decide

theorem sample_confirmations_little_endian :
    u32le sampleOutput.confirmationsChecked = [4, 3, 2, 1] := by
  decide

theorem max_scalar_height_little_endian :
    u64le maxScalarOutput.checkpointHeight =
      [255, 255, 255, 255, 255, 255, 255, 255] := by
  decide

theorem max_scalar_nonce_little_endian :
    u128le maxScalarOutput.messageNonce =
      [255, 255, 255, 255, 255, 255, 255, 255,
       255, 255, 255, 255, 255, 255, 255, 255] := by
  decide

theorem max_scalar_confirmations_little_endian :
    u32le maxScalarOutput.confirmationsChecked =
      [255, 255, 255, 255] := by
  decide

end CheckpointOutput
end Bridge
end Hegemon
