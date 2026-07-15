import Hegemon.Consensus.AcceptedSmallWoodBlockComposition

open Hegemon.Consensus.AcceptedSmallWoodBlockComposition

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def stringArrayJson (values : List String) : String :=
  "[" ++ String.intercalate "," (values.map fun value => "\"" ++ value ++ "\"") ++ "]"

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def identityCaseJson (layer name : String) (block : AcceptedCanonicalBlock) : String :=
  "    {\"layer\":\"" ++ layer ++ "\",\"name\":\"" ++ name ++ "\",\"expected_valid\":"
    ++ boolJson (vectorCanonicalBlockAccepts block) ++ "}"

def omittedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with claims := validVectorBlock.claims.tail }

def reorderedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with claims := validVectorBlock.claims.reverse }

def substitutedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    claims := { vectorTxA.claim with fee := 4 } :: validVectorBlock.claims.tail }

def duplicatedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with claims := vectorTxA.claim :: validVectorBlock.claims }

def wrappedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    identityProjection :=
      { validVectorBlock.identityProjection with
        orderedTxIds := [] :: validVectorBlock.identityProjection.orderedTxIds } }

def truncatedBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    identityProjection :=
      { validVectorBlock.identityProjection with
        orderedProofDigests := validVectorBlock.identityProjection.orderedProofDigests.tail } }

def daMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    provenBatch := { validVectorBlock.provenBatch with daRoot := 0 } }

def headerParentMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    header := { validVectorBlock.header with parentBlockHash := 0 } }

def headerActionCountMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    header := { validVectorBlock.header with actionCount := 4 } }

def headerDaMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    header := { validVectorBlock.header with daRoot := 0 } }

def supplyParentMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    supply := { validVectorSupply with parentBlockHash := 0 } }

def feeOrderMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    supply := { validVectorSupply with orderedFees := [5, 3] } }

def coinbaseMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    supply := { validVectorSupply with observedCoinbaseAmount := some 0 } }

def supplyMismatchBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    supply := { validVectorSupply with claimedSupply := validVectorSupply.claimedSupply + 1 } }

def shiftedEmbeddedParentAndSupplyBlock : AcceptedCanonicalBlock :=
  shiftedEmbeddedParentAndSupplyVectorBlock

def identityCasesJson : String :=
  String.intercalate ",\n"
    [ identityCaseJson "identity" "valid" validVectorBlock,
      identityCaseJson "identity" "omitted" omittedBlock,
      identityCaseJson "identity" "reordered" reorderedBlock,
      identityCaseJson "identity" "substituted" substitutedBlock,
      identityCaseJson "identity" "duplicated" duplicatedBlock,
      identityCaseJson "identity" "transaction_preimage_substituted"
        transactionPreimageSubstitutedVectorBlock,
      identityCaseJson "identity" "wrapped" wrappedBlock,
      identityCaseJson "identity" "truncated" truncatedBlock,
      identityCaseJson "identity" "da_mismatched" daMismatchBlock,
      identityCaseJson "identity" "header_parent_mismatched" headerParentMismatchBlock,
      identityCaseJson "identity" "header_action_count_mismatched" headerActionCountMismatchBlock,
      identityCaseJson "identity" "header_da_mismatched" headerDaMismatchBlock,
      identityCaseJson "supply" "fee_order_mismatched" feeOrderMismatchBlock,
      identityCaseJson "supply" "coinbase_mismatched" coinbaseMismatchBlock,
      identityCaseJson "supply" "parent_mismatched" supplyParentMismatchBlock,
      identityCaseJson "supply" "paired_parent_supply_shift"
        shiftedEmbeddedParentAndSupplyBlock,
      identityCaseJson "supply" "supply_mismatched" supplyMismatchBlock ]

def proofArtifactCaseJson
    (name : String)
    (proofBytes publicInputBytes : List Nat)
    (profile : Nat) : String :=
  "    {\"name\":\"" ++ name ++ "\",\"proof_bytes\":" ++ natArrayJson proofBytes
    ++ ",\"public_input_bytes\":" ++ natArrayJson publicInputBytes
    ++ ",\"verifier_profile\":" ++ toString profile ++ ",\"expected_valid\":"
    ++ boolJson (vectorProofVerifier.accepts proofBytes publicInputBytes profile
      Hegemon.Transaction.ProofWrapperAdmission.validWrapper) ++ "}"

def proofArtifactCasesJson : String :=
  String.intercalate ",\n"
    [ proofArtifactCaseJson "valid" [1, 2, 3] [4, 5] 6,
      proofArtifactCaseJson "proof_bytes_mutated" [1, 2, 4] [4, 5] 6,
      proofArtifactCaseJson "public_inputs_mutated" [1, 2, 3] [4, 6] 6,
      proofArtifactCaseJson "verifier_profile_mutated" [1, 2, 3] [4, 5] 7 ]

def claimScopeCaseJson (name : String) (circuitVersion cryptoSuite : Nat) : String :=
  "    {\"name\":\"" ++ name ++ "\",\"circuit_version\":"
    ++ toString circuitVersion ++ ",\"crypto_suite\":" ++ toString cryptoSuite
    ++ ",\"expected_valid\":"
    ++ boolJson (activeSmallWoodVersionAccepts circuitVersion cryptoSuite) ++ "}"

def claimScopeCasesJson : String :=
  String.intercalate ",\n"
    [ claimScopeCaseJson "active_v3_beta" 3 2,
      claimScopeCaseJson "legacy_v2_beta" 2 2,
      claimScopeCaseJson "wrong_crypto_suite" 3 3 ]

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"production_fields\": " ++ stringArrayJson productionCompositionFieldMap ++ ",\n"
    ++ "  \"claim_scope_cases\": [\n" ++ claimScopeCasesJson ++ "\n  ],\n"
    ++ "  \"expected_da_blob_hex\": \""
    ++ Hegemon.hexBytes (canonicalBlockDaBlob vectorTransactions) ++ "\",\n"
    ++ "  \"canonical_transactions\": [\n"
    ++ "    {\"expected_tx_id_hex\":\"" ++ Hegemon.hexBytes vectorTxIdA ++ "\","
    ++ "\"expected_transaction_hash_preimage_hex\":\""
    ++ Hegemon.hexBytes (transactionHashPreimage vectorTxA) ++ "\","
    ++ "\"expected_ciphertext_hashes_hex\":[\""
    ++ Hegemon.hexBytes vectorCiphertextHashA ++ "\"],"
    ++ "\"statement_hash\":3,\"proof_digest\":4,"
    ++ "\"public_inputs_digest\":5,\"verifier_profile\":6,\"anchor_root\":7,"
    ++ "\"fee\":3,\"binding_circuit_version\":3,"
    ++ "\"transaction_circuit_version\":3,\"transaction_crypto_suite\":2,"
    ++ "\"transaction\":{\"nullifier_tags\":[1],\"commitment_tags\":[2],"
    ++ "\"balance_tag\":3,\"circuit_version\":3,\"crypto_suite\":2,"
    ++ "\"da_payload\":[[8,9]]},"
    ++ "\"claim\":{\"statement_hash_tag\":3,\"proof_digest_tag\":4,"
    ++ "\"public_inputs_digest_tag\":5,\"verifier_profile_tag\":6,"
    ++ "\"anchor_tag\":7,\"fee\":3,\"circuit_version\":3}},\n"
    ++ "    {\"expected_tx_id_hex\":\"" ++ Hegemon.hexBytes vectorTxIdB ++ "\","
    ++ "\"expected_transaction_hash_preimage_hex\":\""
    ++ Hegemon.hexBytes (transactionHashPreimage vectorTxB) ++ "\","
    ++ "\"expected_ciphertext_hashes_hex\":[\""
    ++ Hegemon.hexBytes vectorCiphertextHashB ++ "\"],"
    ++ "\"statement_hash\":10,\"proof_digest\":13,"
    ++ "\"public_inputs_digest\":14,\"verifier_profile\":6,\"anchor_root\":15,"
    ++ "\"fee\":5,\"binding_circuit_version\":3,"
    ++ "\"transaction_circuit_version\":3,\"transaction_crypto_suite\":2,"
    ++ "\"transaction\":{\"nullifier_tags\":[6],\"commitment_tags\":[7],"
    ++ "\"balance_tag\":8,\"circuit_version\":3,\"crypto_suite\":2,"
    ++ "\"da_payload\":[[16]]},"
    ++ "\"claim\":{\"statement_hash_tag\":10,\"proof_digest_tag\":13,"
    ++ "\"public_inputs_digest_tag\":14,\"verifier_profile_tag\":6,"
    ++ "\"anchor_tag\":15,\"fee\":5,\"circuit_version\":3}}\n"
    ++ "  ],\n"
    ++ "  \"canonical_actions\": ["
    ++ "{\"kind\":\"transfer\",\"transaction_index\":0,\"action_bytes\":[1]},"
    ++ "{\"kind\":\"transfer\",\"transaction_index\":1,\"action_bytes\":[2]},"
    ++ "{\"kind\":\"coinbase\",\"amount\":"
    ++ toString (validVectorSupply.observedCoinbaseAmount.getD 0)
    ++ ",\"action_bytes\":[3]}],\n"
    ++ "  \"proof_artifact_cases\": [\n" ++ proofArtifactCasesJson ++ "\n  ],\n"
    ++ "  \"header_fixture\": {"
    ++ "\"height\":" ++ toString validVectorBlock.header.height ++ ","
    ++ "\"parent_block_hash\":" ++ toString validVectorBlock.header.parentBlockHash ++ ","
    ++ "\"action_count\":" ++ toString validVectorBlock.header.actionCount ++ ","
    ++ "\"tx_statements_commitment\":"
    ++ toString validVectorBlock.header.txStatementsCommitment ++ ","
    ++ "\"da_root\":" ++ toString validVectorBlock.header.daRoot ++ ","
    ++ "\"da_chunk_count\":" ++ toString validVectorBlock.header.daChunkCount ++ ","
    ++ "\"claimed_supply\":\"" ++ toString validVectorBlock.header.claimedSupply ++ "\"},\n"
    ++ "  \"accepted_parent_fixture\": {"
    ++ "\"block_hash\":" ++ toString validVectorParent.blockHash ++ ","
    ++ "\"height\":" ++ toString validVectorParent.height ++ ","
    ++ "\"supply\":\"" ++ toString validVectorParent.supply ++ "\"},\n"
    ++ "  \"supply_fixture\": {\n"
    ++ "    \"height\": " ++ toString validVectorSupply.height ++ ",\n"
    ++ "    \"parent_block_hash\": " ++ toString validVectorSupply.parentBlockHash ++ ",\n"
    ++ "    \"parent_supply\": \"" ++ toString validVectorSupply.parentSupply ++ "\",\n"
    ++ "    \"ordered_transfer_fees\": "
    ++ natArrayJson validVectorSupply.orderedFees ++ ",\n"
    ++ "    \"exact_transfer_fee_total\": "
    ++ toString validVectorSupply.exactFeeTotal ++ ",\n"
    ++ "    \"checked_transfer_fee_total\": "
    ++ optionNatJson validVectorSupply.checkedFeeTotal ++ ",\n"
    ++ "    \"accepted_burn_amounts\": "
    ++ natArrayJson validVectorSupply.acceptedBurns ++ ",\n"
    ++ "    \"coinbase_count\": " ++ toString validVectorSupply.coinbaseCount ++ ",\n"
    ++ "    \"observed_coinbase_amount\": "
    ++ optionNatJson validVectorSupply.observedCoinbaseAmount ++ ",\n"
    ++ "    \"expected_coinbase_amount\": "
    ++ optionNatJson validVectorSupply.expectedCoinbaseAmount ++ ",\n"
    ++ "    \"has_coinbase\": " ++ boolJson validVectorSupply.hasCoinbase ++ ",\n"
    ++ "    \"supply_delta\": \"" ++ toString validVectorSupply.supplyDelta ++ "\",\n"
    ++ "    \"claimed_supply\": \"" ++ toString validVectorSupply.claimedSupply ++ "\"\n"
    ++ "  },\n"
    ++ "  \"identity_cases\": [\n" ++ identityCasesJson ++ "\n  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
