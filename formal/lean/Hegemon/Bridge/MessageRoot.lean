import Hegemon.Bytes

namespace Hegemon
namespace Bridge
namespace MessageRoot

def domain : List Byte :=
  asciiBytes "hegemon.bridge.message-root-v1"

def lengthPrefixed (bytes : List Byte) : List Byte :=
  u32le bytes.length ++ bytes

def concatLengthPrefixed : List (List Byte) -> List Byte
  | [] => []
  | hash :: rest => lengthPrefixed hash ++ concatLengthPrefixed rest

def transcriptFromHashes (hashes : List (List Byte)) : List Byte :=
  domain ++ lengthPrefixed (u32le hashes.length) ++ concatLengthPrefixed hashes

def validHash (hash : List Byte) : Bool :=
  hash.length == 48

def validInput (hashes : List (List Byte)) : Bool :=
  hashes.length < 2 ^ 32 && hashes.all validHash

def hashA : List Byte :=
  patternedBytes 48 0x31

def hashB : List Byte :=
  patternedBytes 48 0xa7

def shortHash : List Byte :=
  patternedBytes 47 0x31

def longHash : List Byte :=
  patternedBytes 49 0x31

theorem empty_valid :
    validInput [] = true := by
  native_decide

theorem single_valid :
    validInput [hashA] = true := by
  native_decide

theorem ordered_pair_valid :
    validInput [hashA, hashB] = true := by
  native_decide

theorem short_hash_rejected :
    validInput [shortHash] = false := by
  native_decide

theorem long_hash_rejected :
    validInput [longHash] = false := by
  native_decide

theorem empty_transcript :
    transcriptFromHashes [] = domain ++ u32le 4 ++ u32le 0 := by
  native_decide

theorem single_transcript :
    transcriptFromHashes [hashA] = domain ++ u32le 4 ++ u32le 1 ++ u32le 48 ++ hashA := by
  native_decide

theorem ordered_pair_transcript :
    transcriptFromHashes [hashA, hashB] =
      domain ++ u32le 4 ++ u32le 2 ++ u32le 48 ++ hashA ++ u32le 48 ++ hashB := by
  native_decide

theorem ordered_pair_differs_from_reversed :
    transcriptFromHashes [hashA, hashB] != transcriptFromHashes [hashB, hashA] := by
  native_decide

theorem count_binds_prefix :
    (transcriptFromHashes [hashA]).take (domain.length + 8) !=
      (transcriptFromHashes [hashA, hashB]).take (domain.length + 8) := by
  native_decide

end MessageRoot
end Bridge
end Hegemon
