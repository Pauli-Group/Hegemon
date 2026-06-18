import Hegemon.Bytes

namespace Hegemon
namespace Consensus
namespace DaRoot

def leafDomain : List Byte :=
  asciiBytes "da-leaf"

def nodeDomain : List Byte :=
  asciiBytes "da-node"

def maxShards : Nat := 255

def maxChunkMerklePathLen : Nat := 8

def maxPageMerklePathLen : Nat := 32

structure DaParams where
  chunkSize : Nat
  sampleCount : Nat
deriving DecidableEq, Repr

structure ShardCount where
  dataShards : Nat
  parityShards : Nat
  totalShards : Nat
deriving DecidableEq, Repr

structure TxDaPayload where
  ciphertexts : List (List Byte)
deriving DecidableEq, Repr

def ciphertextBytes (ciphertext : List Byte) : List Byte :=
  u32le ciphertext.length ++ ciphertext

def transactionBytes (tx : TxDaPayload) : List Byte :=
  u32le tx.ciphertexts.length ++ tx.ciphertexts.foldl (fun acc ct => acc ++ ciphertextBytes ct) []

def daBlob (transactions : List TxDaPayload) : List Byte :=
  u32le transactions.length ++ transactions.foldl (fun acc tx => acc ++ transactionBytes tx) []

def ceilDiv (n d : Nat) : Nat :=
  if d = 0 then
    0
  else
    (n + d - 1) / d

def dataShardsForLen (blobLen chunkSize : Nat) : Nat :=
  max (ceilDiv blobLen chunkSize) 1

def parityShardsForData (dataShards : Nat) : Nat :=
  max ((dataShards + 1) / 2) 1

def shardCountForBlob (blobLen : Nat) (params : DaParams) : Option ShardCount :=
  if params.chunkSize = 0 then
    none
  else if params.sampleCount = 0 then
    none
  else
    let data := dataShardsForLen blobLen params.chunkSize
    let parity := parityShardsForData data
    let total := data + parity
    if total > maxShards then
      none
    else
      some { dataShards := data, parityShards := parity, totalShards := total }

def validChunkProofPathLen (pathLen : Nat) : Bool :=
  pathLen <= maxChunkMerklePathLen

def validPageProofPathLen (pathLen : Nat) : Bool :=
  pathLen <= maxPageMerklePathLen

def leafPreimage (index : Nat) (data : List Byte) : List Byte :=
  leafDomain ++ u32le index ++ data

def nodePreimage (left right : List Byte) : List Byte :=
  nodeDomain ++ left ++ right

def merkleStepPreimage (nodeIndex : Nat) (current sibling : List Byte) : List Byte :=
  if nodeIndex % 2 = 0 then
    nodePreimage current sibling
  else
    nodePreimage sibling current

def sampleTransactions : List TxDaPayload :=
  [
    { ciphertexts := [[1, 2, 3], [4]] },
    { ciphertexts := [[170, 187, 204, 221, 238]] }
  ]

def emptyCiphertextTransaction : List TxDaPayload :=
  [
    { ciphertexts := [[], [0, 255]] }
  ]

def sampleLeft : List Byte :=
  patternedBytes 48 1

def sampleRight : List Byte :=
  patternedBytes 48 2

def sampleCurrent : List Byte :=
  patternedBytes 48 3

def sampleSibling : List Byte :=
  patternedBytes 48 4

theorem leaf_domain_bytes :
    leafDomain = [100, 97, 45, 108, 101, 97, 102] := by
  decide

theorem node_domain_bytes :
    nodeDomain = [100, 97, 45, 110, 111, 100, 101] := by
  decide

theorem empty_block_blob_hex :
    hexBytes (daBlob []) = "0x00000000" := by
  decide

theorem sample_blob_hex :
    hexBytes (daBlob sampleTransactions) =
      "0x02000000020000000300000001020301000000040100000005000000aabbccddee" := by
  decide

theorem empty_ciphertext_blob_hex :
    hexBytes (daBlob emptyCiphertextTransaction) =
      "0x0100000002000000000000000200000000ff" := by
  decide

theorem leaf_zero_preimage_hex :
    hexBytes (leafPreimage 0 [1, 2, 3]) =
      "0x64612d6c65616600000000010203" := by
  decide

theorem leaf_max_index_preimage_hex :
    hexBytes (leafPreimage 4294967295 (patternedBytes 4 9)) =
      "0x64612d6c656166ffffffff091a2b3c" := by
  decide

theorem node_preimage_length :
    (nodePreimage sampleLeft sampleRight).length = 103 := by
  decide

theorem node_preimage_hex :
    hexBytes (nodePreimage sampleLeft sampleRight) =
      "0x64612d6e6f64650112233445566778899aabbccddeef00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f2002132435465768798a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899aabbccddeeff1021" := by
  set_option maxRecDepth 6000 in
  decide

theorem node_preimage_order_binds_children :
    nodePreimage sampleLeft sampleRight ≠ nodePreimage sampleRight sampleLeft := by
  decide

theorem shard_count_empty_blob :
    shardCountForBlob 0 { chunkSize := 8, sampleCount := 1 } =
      some { dataShards := 1, parityShards := 1, totalShards := 2 } := by
  decide

theorem shard_count_partial_third_blob :
    shardCountForBlob 17 { chunkSize := 8, sampleCount := 1 } =
      some { dataShards := 3, parityShards := 2, totalShards := 5 } := by
  decide

theorem shard_count_max_accepts :
    shardCountForBlob 1360 { chunkSize := 8, sampleCount := 1 } =
      some { dataShards := 170, parityShards := 85, totalShards := 255 } := by
  decide

theorem shard_count_rejects_zero_chunk :
    shardCountForBlob 1 { chunkSize := 0, sampleCount := 1 } = none := by
  decide

theorem shard_count_rejects_zero_sample :
    shardCountForBlob 1 { chunkSize := 8, sampleCount := 0 } = none := by
  decide

theorem shard_count_rejects_too_many :
    shardCountForBlob 1361 { chunkSize := 8, sampleCount := 1 } = none := by
  decide

theorem chunk_proof_path_len_empty_accepts :
    validChunkProofPathLen 0 = true := by
  decide

theorem chunk_proof_path_len_max_accepts :
    validChunkProofPathLen 8 = true := by
  decide

theorem chunk_proof_path_len_over_cap_rejects :
    validChunkProofPathLen 9 = false := by
  decide

theorem page_proof_path_len_empty_accepts :
    validPageProofPathLen 0 = true := by
  decide

theorem page_proof_path_len_max_accepts :
    validPageProofPathLen 32 = true := by
  decide

theorem page_proof_path_len_over_cap_rejects :
    validPageProofPathLen 33 = false := by
  decide

theorem even_merkle_step_uses_current_left :
    merkleStepPreimage 2 sampleCurrent sampleSibling =
      nodePreimage sampleCurrent sampleSibling := by
  decide

theorem odd_merkle_step_uses_sibling_left :
    merkleStepPreimage 3 sampleCurrent sampleSibling =
      nodePreimage sampleSibling sampleCurrent := by
  decide

theorem even_merkle_step_hex :
    hexBytes (merkleStepPreimage 2 sampleCurrent sampleSibling) =
      "0x64612d6e6f6465031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef0011220415263748596a7b8c9daebfd0e1f2031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff0011223" := by
  set_option maxRecDepth 6000 in
  decide

theorem odd_merkle_step_hex :
    hexBytes (merkleStepPreimage 3 sampleCurrent sampleSibling) =
      "0x64612d6e6f64650415263748596a7b8c9daebfd0e1f2031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff0011223031425364758697a8b9cadbecfe0f102132435465768798a9bacbdcedff00112233445566778899aabbccddeef001122" := by
  set_option maxRecDepth 6000 in
  decide

end DaRoot
end Consensus
end Hegemon
