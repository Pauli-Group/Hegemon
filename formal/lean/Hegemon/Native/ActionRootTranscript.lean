import Hegemon.Bytes

namespace Hegemon
namespace Native
namespace ActionRootTranscript

def actionRootDomain : List Byte :=
  asciiBytes "hegemon-native-extrinsics-v1"

def actionHashWidth : Nat := 32

def actionRootPreimage (actionHashes : List (List Byte)) : List Byte :=
  actionRootDomain
    ++ u32le actionHashes.length
    ++ actionHashes.foldl (fun acc actionHash => acc ++ actionHash) []

def sampleHashA : List Byte :=
  patternedBytes actionHashWidth 1

def sampleHashB : List Byte :=
  patternedBytes actionHashWidth 2

def maxHash : List Byte :=
  List.replicate actionHashWidth 255

theorem action_root_domain_hex :
    hexBytes actionRootDomain = "0x686567656d6f6e2d6e61746976652d65787472696e736963732d7631" := by
  decide

theorem empty_action_root_preimage_hex :
    hexBytes (actionRootPreimage []) =
      "0x686567656d6f6e2d6e61746976652d65787472696e736963732d763100000000" := by
  decide

theorem empty_action_root_preimage_length :
    (actionRootPreimage []).length = actionRootDomain.length + 4 := by
  simp [actionRootPreimage]
  simp [u32le, littleEndianBytes]

theorem one_action_root_preimage_length :
    (actionRootPreimage [sampleHashA]).length =
      actionRootDomain.length + 4 + actionHashWidth := by
  decide

theorem two_action_root_preimage_length :
    (actionRootPreimage [sampleHashA, sampleHashB]).length =
      actionRootDomain.length + 4 + actionHashWidth * 2 := by
  decide

theorem action_root_count_is_little_endian :
    ((actionRootPreimage [sampleHashA, sampleHashB]).drop actionRootDomain.length).take 4 =
      u32le 2 := by
  decide

theorem action_root_order_binds_hashes :
    actionRootPreimage [sampleHashA, sampleHashB] ≠
      actionRootPreimage [sampleHashB, sampleHashA] := by
  decide

theorem action_root_hash_bytes_are_unmodified :
    (actionRootPreimage [sampleHashA]).drop (actionRootDomain.length + 4) =
      sampleHashA := by
  decide

theorem max_hash_preimage_hex :
    hexBytes (actionRootPreimage [maxHash]) =
      "0x686567656d6f6e2d6e61746976652d65787472696e736963732d763101000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" := by
  native_decide

end ActionRootTranscript
end Native
end Hegemon
