import Hegemon.Consensus.DaRoot

open Hegemon
open Hegemon.Consensus.DaRoot

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def stringArrayJson : List String -> String
  | [] => "[]"
  | first :: rest =>
      "[\"" ++ first ++ "\"" ++ rest.foldl (fun acc value => acc ++ ", \"" ++ value ++ "\"") "" ++ "]"

def nestedStringArrayJson : List (List String) -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ stringArrayJson first ++ rest.foldl (fun acc value => acc ++ ", " ++ stringArrayJson value) "" ++ "]"

def txPayloadJson (txs : List TxDaPayload) : String :=
  nestedStringArrayJson (txs.map fun tx => tx.ciphertexts.map hexBytes)

def blobCaseJson (name : String) (txs : List TxDaPayload) : String :=
  let blob := daBlob txs
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"ciphertexts_hex\": " ++ txPayloadJson txs ++ ",\n"
    ++ "      \"expected_blob_hex\": \"" ++ hexBytes blob ++ "\",\n"
    ++ "      \"expected_blob_len\": " ++ toString blob.length ++ "\n"
    ++ "    }"

def leafCaseJson (name : String) (index : Nat) (data : List Byte) : String :=
  let preimage := leafPreimage index data
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"index\": " ++ toString index ++ ",\n"
    ++ "      \"data_hex\": \"" ++ hexBytes data ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def nodeCaseJson (name : String) (left right : List Byte) : String :=
  let preimage := nodePreimage left right
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"left_hex\": \"" ++ hexBytes left ++ "\",\n"
    ++ "      \"right_hex\": \"" ++ hexBytes right ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def shardCountCaseJson (name : String) (blobLen : Nat) (params : DaParams) : String :=
  let result := shardCountForBlob blobLen params
  let expectedValid := result.isSome
  let dataShards := result.map ShardCount.dataShards |>.getD 0
  let parityShards := result.map ShardCount.parityShards |>.getD 0
  let totalShards := result.map ShardCount.totalShards |>.getD 0
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"blob_len\": " ++ toString blobLen ++ ",\n"
    ++ "      \"chunk_size\": " ++ toString params.chunkSize ++ ",\n"
    ++ "      \"sample_count\": " ++ toString params.sampleCount ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson expectedValid ++ ",\n"
    ++ "      \"expected_data_shards\": " ++ toString dataShards ++ ",\n"
    ++ "      \"expected_parity_shards\": " ++ toString parityShards ++ ",\n"
    ++ "      \"expected_total_shards\": " ++ toString totalShards ++ "\n"
    ++ "    }"

def proofPathLenCaseJson (name kind : String) (pathLen : Nat) (expectedValid : Bool) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": \"" ++ kind ++ "\",\n"
    ++ "      \"path_len\": " ++ toString pathLen ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson expectedValid ++ "\n"
    ++ "    }"

def merkleStepCaseJson (name : String) (nodeIndex : Nat) (current sibling : List Byte) : String :=
  let preimage := merkleStepPreimage nodeIndex current sibling
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"node_index\": " ++ toString nodeIndex ++ ",\n"
    ++ "      \"current_hex\": \"" ++ hexBytes current ++ "\",\n"
    ++ "      \"sibling_hex\": \"" ++ hexBytes sibling ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \"" ++ hexBytes preimage ++ "\",\n"
    ++ "      \"expected_preimage_len\": " ++ toString preimage.length ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"da_blob_cases\": [\n"
    ++ blobCaseJson "empty-block" [] ++ ",\n"
    ++ blobCaseJson "two-transactions-mixed-ciphertexts" sampleTransactions ++ ",\n"
    ++ blobCaseJson "empty-ciphertext-is-length-prefixed" emptyCiphertextTransaction ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_leaf_preimage_cases\": [\n"
    ++ leafCaseJson "leaf-index-zero" 0 [1, 2, 3] ++ ",\n"
    ++ leafCaseJson "leaf-max-u32-index" 4294967295 (patternedBytes 4 9) ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_node_preimage_cases\": [\n"
    ++ nodeCaseJson "ordered-node" sampleLeft sampleRight ++ ",\n"
    ++ nodeCaseJson "reversed-node" sampleRight sampleLeft ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_shard_count_cases\": [\n"
    ++ shardCountCaseJson "empty-blob-two-shards" 0 { chunkSize := 8, sampleCount := 1 } ++ ",\n"
    ++ shardCountCaseJson "partial-third-data-shard" 17 { chunkSize := 8, sampleCount := 1 } ++ ",\n"
    ++ shardCountCaseJson "max-total-shards" 1360 { chunkSize := 8, sampleCount := 1 } ++ ",\n"
    ++ shardCountCaseJson "reject-zero-chunk-size" 1 { chunkSize := 0, sampleCount := 1 } ++ ",\n"
    ++ shardCountCaseJson "reject-oversized-chunk-size" 1
      { chunkSize := 262145, sampleCount := 1 } ++ ",\n"
    ++ shardCountCaseJson "reject-zero-sample-count" 1 { chunkSize := 8, sampleCount := 0 } ++ ",\n"
    ++ shardCountCaseJson "reject-too-many-shards" 1361 { chunkSize := 8, sampleCount := 1 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_proof_path_len_cases\": [\n"
    ++ proofPathLenCaseJson "chunk-empty-path-length-valid" "chunk" 0 (validChunkProofPathLen 0) ++ ",\n"
    ++ proofPathLenCaseJson "chunk-max-path-length-valid" "chunk" maxChunkMerklePathLen (validChunkProofPathLen maxChunkMerklePathLen) ++ ",\n"
    ++ proofPathLenCaseJson "chunk-over-cap-path-length-rejected" "chunk" (maxChunkMerklePathLen + 1) (validChunkProofPathLen (maxChunkMerklePathLen + 1)) ++ ",\n"
    ++ proofPathLenCaseJson "page-empty-path-length-valid" "page" 0 (validPageProofPathLen 0) ++ ",\n"
    ++ proofPathLenCaseJson "page-max-path-length-valid" "page" maxPageMerklePathLen (validPageProofPathLen maxPageMerklePathLen) ++ ",\n"
    ++ proofPathLenCaseJson "page-over-cap-path-length-rejected" "page" (maxPageMerklePathLen + 1) (validPageProofPathLen (maxPageMerklePathLen + 1)) ++ "\n"
    ++ "  ],\n"
    ++ "  \"da_merkle_step_cases\": [\n"
    ++ merkleStepCaseJson "even-index-current-left" 2 sampleCurrent sampleSibling ++ ",\n"
    ++ merkleStepCaseJson "odd-index-sibling-left" 3 sampleCurrent sampleSibling ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
