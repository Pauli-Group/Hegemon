import Hegemon.Native.CanonicalReorgChainAdmission

open Hegemon.Native.CanonicalReorgChainAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CanonicalReorgChainReject -> String
  | none => "null"
  | some CanonicalReorgChainReject.chainEmpty => "\"chain_empty\""
  | some CanonicalReorgChainReject.genesisMismatch => "\"genesis_mismatch\""
  | some CanonicalReorgChainReject.bestMetadataMismatch =>
      "\"best_metadata_mismatch\""
  | some CanonicalReorgChainReject.canonicalHeightMismatch =>
      "\"canonical_height_mismatch\""
  | some CanonicalReorgChainReject.chainIdMismatch => "\"chain_id_mismatch\""
  | some CanonicalReorgChainReject.rulesHashMismatch => "\"rules_hash_mismatch\""
  | some CanonicalReorgChainReject.hashWorkHashMismatch =>
      "\"hash_work_hash_mismatch\""
  | some CanonicalReorgChainReject.parentHashMismatch =>
      "\"parent_hash_mismatch\""
  | some CanonicalReorgChainReject.blockRecordCountMismatch =>
      "\"block_record_count_mismatch\""
  | some CanonicalReorgChainReject.blockRecordMismatch =>
      "\"block_record_mismatch\""
  | some CanonicalReorgChainReject.heightEntryCountMismatch =>
      "\"height_entry_count_mismatch\""
  | some CanonicalReorgChainReject.heightEntryMismatch =>
      "\"height_entry_mismatch\""

def canonicalReorgCaseJson
    (name : String)
    (input : CanonicalReorgChainInput) : String :=
  let result := evaluateCanonicalReorgChainRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"chain_nonempty\": " ++ boolJson input.chainNonempty ++ ",\n"
    ++ "      \"genesis_matches_expected\": " ++ boolJson input.genesisMatchesExpected ++ ",\n"
    ++ "      \"best_metadata_matches_chain\": " ++ boolJson input.bestMetadataMatchesChain ++ ",\n"
    ++ "      \"canonical_heights_contiguous\": " ++ boolJson input.canonicalHeightsContiguous ++ ",\n"
    ++ "      \"canonical_chain_ids_match\": " ++ boolJson input.canonicalChainIdsMatch ++ ",\n"
    ++ "      \"canonical_rules_hashes_match\": " ++ boolJson input.canonicalRulesHashesMatch ++ ",\n"
    ++ "      \"canonical_hashes_match_work_hashes\": " ++ boolJson input.canonicalHashesMatchWorkHashes ++ ",\n"
    ++ "      \"canonical_parent_hashes_contiguous\": " ++ boolJson input.canonicalParentHashesContiguous ++ ",\n"
    ++ "      \"block_record_count_matches_chain\": " ++ boolJson input.blockRecordCountMatchesChain ++ ",\n"
    ++ "      \"block_records_match_chain\": " ++ boolJson input.blockRecordsMatchChain ++ ",\n"
    ++ "      \"height_entry_count_matches_chain\": " ++ boolJson input.heightEntryCountMatchesChain ++ ",\n"
    ++ "      \"height_entries_match_chain\": " ++ boolJson input.heightEntriesMatchChain ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"canonical_reorg_chain_admission_cases\": [\n"
    ++ canonicalReorgCaseJson "valid-canonical-reorg-chain" valid ++ ",\n"
    ++ canonicalReorgCaseJson "empty-chain-rejected" chainEmpty ++ ",\n"
    ++ canonicalReorgCaseJson "genesis-mismatch-rejected" genesisMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "best-metadata-mismatch-rejected"
      bestMetadataMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "canonical-height-mismatch-rejected"
      canonicalHeightMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "chain-id-mismatch-rejected" chainIdMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "rules-hash-mismatch-rejected" rulesHashMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "hash-work-hash-mismatch-rejected"
      hashWorkHashMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "parent-hash-mismatch-rejected"
      parentHashMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "block-record-count-mismatch-rejected"
      blockRecordCountMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "block-record-mismatch-rejected"
      blockRecordMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "height-entry-count-mismatch-rejected"
      heightEntryCountMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "height-entry-mismatch-rejected"
      heightEntryMismatch ++ ",\n"
    ++ canonicalReorgCaseJson "structural-precedes-write-projection"
      structuralBeforeWriteProjection ++ ",\n"
    ++ canonicalReorgCaseJson "block-record-count-precedes-record-mismatch"
      blockRecordCountPrecedence ++ ",\n"
    ++ canonicalReorgCaseJson "height-entry-count-precedes-height-entry-mismatch"
      heightEntryCountPrecedence ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
