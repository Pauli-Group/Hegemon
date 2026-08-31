import Hegemon.Native.CanonicalReorgPersistenceAdmission

open Hegemon.Native.CanonicalReorgPersistenceAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natJson (value : Nat) : String :=
  toString value

def classificationStatusJson : SuppliedBlockRecordStatus -> String
  | .knownExact => "\"known_exact\""
  | .missing => "\"missing\""

def classificationRejectJson :
    SuppliedBlockRecordClassificationReject -> String
  | .knownRecordMismatch => "\"known_record_mismatch\""

def classificationCaseJson
    (name : String)
    (input : SuppliedBlockRecordClassificationInput) : String :=
  let result := evaluateSuppliedBlockRecordClassification input
  let expectedValid := match result with | .ok _ => true | .error _ => false
  let expectedStatus := match result with
    | .ok status => classificationStatusJson status
    | .error _ => "null"
  let expectedRejection := match result with
    | .ok _ => "null"
    | .error rejection => classificationRejectJson rejection
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"stored_record_present\": "
      ++ boolJson input.storedRecordPresent ++ ",\n"
    ++ "      \"stored_record_exact\": "
      ++ boolJson input.storedRecordExact ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson expectedValid ++ ",\n"
    ++ "      \"expected_status\": " ++ expectedStatus ++ ",\n"
    ++ "      \"expected_rejection\": " ++ expectedRejection ++ "\n"
    ++ "    }"

def persistenceRejectJson : Option CanonicalReorgPersistenceReject -> String
  | none => "null"
  | some .knownCountExceedsReplacement =>
      "\"known_count_exceeds_replacement\""
  | some .classifiedMissingCountMismatch =>
      "\"classified_missing_count_mismatch\""
  | some .suppliedMissingCountMismatch =>
      "\"supplied_missing_count_mismatch\""
  | some .connectedExactKnownRowsMissing =>
      "\"connected_exact_known_rows_missing\""
  | some .suffixNotFullyValidated => "\"suffix_not_fully_validated\""
  | some .noncanonicalBatchWriteCountMismatch =>
      "\"noncanonical_batch_write_count_mismatch\""
  | some .noncanonicalBatchNotDurable =>
      "\"noncanonical_batch_not_durable\""
  | some .durableRecordsMismatchReplacement =>
      "\"durable_records_mismatch_replacement\""
  | some .canonicalTransactionWritesBlockRecords =>
      "\"canonical_transaction_writes_block_records\""

def persistenceCaseJson
    (name : String)
    (input : CanonicalReorgPersistenceInput) : String :=
  let rejection := evaluateCanonicalReorgPersistenceRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"replacement_block_count\": "
      ++ natJson input.replacementBlockCount ++ ",\n"
    ++ "      \"known_block_count\": "
      ++ natJson input.knownBlockCount ++ ",\n"
    ++ "      \"classified_missing_block_count\": "
      ++ natJson input.classifiedMissingBlockCount ++ ",\n"
    ++ "      \"supplied_missing_block_count\": "
      ++ natJson input.suppliedMissingBlockCount ++ ",\n"
    ++ "      \"connected_exact_known_rows\": "
      ++ boolJson input.connectedExactKnownRows ++ ",\n"
    ++ "      \"suffix_fully_validated\": "
      ++ boolJson input.suffixFullyValidated ++ ",\n"
    ++ "      \"noncanonical_batch_block_record_writes\": "
      ++ natJson input.noncanonicalBatchBlockRecordWrites ++ ",\n"
    ++ "      \"noncanonical_batch_durability_flushed\": "
      ++ boolJson input.noncanonicalBatchDurabilityFlushed ++ ",\n"
    ++ "      \"durable_records_match_replacement\": "
      ++ boolJson input.durableRecordsMatchReplacement ++ ",\n"
    ++ "      \"canonical_transaction_block_record_writes\": "
      ++ natJson input.canonicalTransactionBlockRecordWrites ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (canonicalReorgPersistenceAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ persistenceRejectJson rejection ++ "\n"
    ++ "    }"

def allKnown : CanonicalReorgPersistenceInput :=
  { valid with
    knownBlockCount := 4,
    classifiedMissingBlockCount := 0,
    suppliedMissingBlockCount := 0,
    noncanonicalBatchBlockRecordWrites := 0 }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"supplied_block_record_classification_cases\": [\n"
    ++ classificationCaseJson "missing-record"
      { storedRecordPresent := false, storedRecordExact := false } ++ ",\n"
    ++ classificationCaseJson "known-exact-record"
      { storedRecordPresent := true, storedRecordExact := true } ++ ",\n"
    ++ classificationCaseJson "known-mismatched-record"
      { storedRecordPresent := true, storedRecordExact := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"canonical_reorg_persistence_cases\": [\n"
    ++ persistenceCaseJson "valid-selective-prestorage" valid ++ ",\n"
    ++ persistenceCaseJson "valid-all-known-no-prestorage" allKnown ++ ",\n"
    ++ persistenceCaseJson "known-count-exceeds-replacement"
      { valid with knownBlockCount := 5 } ++ ",\n"
    ++ persistenceCaseJson "classified-missing-count-mismatch"
      { valid with classifiedMissingBlockCount := 1 } ++ ",\n"
    ++ persistenceCaseJson "supplied-missing-count-mismatch"
      { valid with suppliedMissingBlockCount := 1 } ++ ",\n"
    ++ persistenceCaseJson "connected-exact-known-rows-missing"
      { valid with connectedExactKnownRows := false } ++ ",\n"
    ++ persistenceCaseJson "suffix-not-fully-validated"
      { valid with suffixFullyValidated := false } ++ ",\n"
    ++ persistenceCaseJson "noncanonical-batch-write-count-mismatch"
      { valid with noncanonicalBatchBlockRecordWrites := 1 } ++ ",\n"
    ++ persistenceCaseJson "noncanonical-batch-not-durable"
      { valid with noncanonicalBatchDurabilityFlushed := false } ++ ",\n"
    ++ persistenceCaseJson "durable-records-mismatch-replacement"
      { valid with durableRecordsMatchReplacement := false } ++ ",\n"
    ++ persistenceCaseJson "canonical-transaction-writes-block-records"
      { valid with canonicalTransactionBlockRecordWrites := 1 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
