import Hegemon.Bytes

namespace Hegemon
namespace Bridge
namespace FlyClient

def sampleDomain : List Byte :=
  asciiBytes "hegemon.flyclient.sample-v1"

structure TranscriptInput where
  mmrRoot : List Byte
  tipHash : List Byte
  messageHeaderHash : List Byte
  startInclusive : Nat
  endExclusive : Nat
  sampleIndex : Nat
deriving DecidableEq, Repr

def validHash32 (bytes : List Byte) : Bool :=
  bytes.length == 32

def transcriptPreimage (input : TranscriptInput) : List Byte :=
  sampleDomain
    ++ input.mmrRoot
    ++ input.tipHash
    ++ input.messageHeaderHash
    ++ u64le input.startInclusive
    ++ u64le input.endExclusive
    ++ u32le input.sampleIndex

def sampleHeight (startInclusive endExclusive digestPrefix : Nat) : Option Nat :=
  if startInclusive ≥ endExclusive then
    none
  else
    let span := endExclusive - startInclusive
    some (startInclusive + (digestPrefix % span))

def sampleHeightsFromPrefixes
    (startInclusive endExclusive sampleCount : Nat)
    (digestPrefixes : List Nat) : List Nat :=
  if startInclusive ≥ endExclusive || sampleCount = 0 then
    []
  else
    (digestPrefixes.take sampleCount).filterMap
      fun digestPrefix => sampleHeight startInclusive endExclusive digestPrefix

def validTranscript : TranscriptInput :=
  {
    mmrRoot := patternedBytes 32 1,
    tipHash := patternedBytes 32 2,
    messageHeaderHash := patternedBytes 32 3,
    startInclusive := 11,
    endExclusive := 14,
    sampleIndex := 2
  }

def maxIndexTranscript : TranscriptInput :=
  {
    mmrRoot := patternedBytes 32 9,
    tipHash := patternedBytes 32 10,
    messageHeaderHash := patternedBytes 32 11,
    startInclusive := 0,
    endExclusive := 4294967296,
    sampleIndex := 4294967295
  }

theorem sample_domain_bytes :
    sampleDomain =
      [104, 101, 103, 101, 109, 111, 110, 46, 102, 108, 121, 99, 108, 105,
       101, 110, 116, 46, 115, 97, 109, 112, 108, 101, 45, 118, 49] := by
  decide

theorem valid_transcript_length :
    (transcriptPreimage validTranscript).length = 143 := by
  simp [transcriptPreimage, validTranscript, sampleDomain, asciiBytes, patternedBytes,
    u64le, u32le, littleEndianBytes]

theorem valid_transcript_hex :
    hexBytes (transcriptPreimage validTranscript) =
      "0x686567656d6f6e2e666c79636c69656e742e73616d706c652d76310112233445566778899aabbccddeef00112233445566778899aabbccddeeff1002132435465768798a9bacbdcedff00112233445566778899aabbccddeef0011031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff001120b000000000000000e0000000000000002000000" := by
  set_option maxRecDepth 5000 in
  decide

theorem max_index_transcript_hex :
    hexBytes (transcriptPreimage maxIndexTranscript) =
      "0x686567656d6f6e2e666c79636c69656e742e73616d706c652d7631091a2b3c4d5e6f8091a2b3c4d5e6f708192a3b4c5d6e7f90a1b2c3d4e5f607180a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4d5e6f708190b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a00000000000000000000000001000000ffffffff" := by
  set_option maxRecDepth 8000 in
  decide

theorem sample_height_modulo :
    sampleHeight 11 14 5 = some 13 := by
  decide

theorem sample_height_zero_prefix :
    sampleHeight 10 20 0 = some 10 := by
  decide

theorem sample_height_large_prefix :
    sampleHeight 10 20 18446744073709551615 = some 15 := by
  decide

theorem sample_height_rejects_equal_range :
    sampleHeight 10 10 7 = none := by
  decide

theorem sample_height_rejects_reversed_range :
    sampleHeight 20 10 7 = none := by
  decide

theorem sample_heights_allow_duplicates :
    sampleHeightsFromPrefixes 10 20 3 [0, 10, 20] = [10, 10, 10] := by
  decide

theorem sample_heights_truncate_to_sample_count :
    sampleHeightsFromPrefixes 10 20 2 [0, 1, 2] = [10, 11] := by
  decide

theorem sample_heights_zero_count_empty :
    sampleHeightsFromPrefixes 10 20 0 [0, 1, 2] = [] := by
  decide

theorem sample_heights_invalid_range_empty :
    sampleHeightsFromPrefixes 20 10 3 [0, 1, 2] = [] := by
  decide

end FlyClient
end Bridge
end Hegemon
