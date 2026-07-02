import Hegemon.Native.AnnouncedBlockAdmission

open Hegemon.Native.AnnouncedBlockAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option AnnouncedBlockReject -> String
  | none => "null"
  | some AnnouncedBlockReject.heightNotNext => "\"height_not_next\""
  | some AnnouncedBlockReject.parentHashMismatch => "\"parent_hash_mismatch\""
  | some AnnouncedBlockReject.timestampDidNotAdvance => "\"timestamp_did_not_advance\""
  | some AnnouncedBlockReject.futureSkew => "\"future_skew\""
  | some AnnouncedBlockReject.hashWorkHashMismatch => "\"hash_work_hash_mismatch\""

def announcedBlockCaseJson (name : String) (input : AnnouncedBlockInput) : String :=
  let result := evaluateAnnouncedBlockRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"parent_height\": " ++ toString input.parentHeight ++ ",\n"
    ++ "      \"announced_height\": " ++ toString input.announcedHeight ++ ",\n"
    ++ "      \"parent_hash_matches\": " ++ boolJson input.parentHashMatches ++ ",\n"
    ++ "      \"parent_timestamp_ms\": " ++ toString input.parentTimestampMs ++ ",\n"
    ++ "      \"announced_timestamp_ms\": " ++ toString input.announcedTimestampMs ++ ",\n"
    ++ "      \"now_ms\": " ++ toString input.nowMs ++ ",\n"
    ++ "      \"max_future_skew_ms\": " ++ toString input.maxFutureSkewMs ++ ",\n"
    ++ "      \"hash_matches_work_hash\": " ++ boolJson input.hashMatchesWorkHash ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"announced_block_admission_cases\": [\n"
    ++ announcedBlockCaseJson "valid-announced-block" valid ++ ",\n"
    ++ announcedBlockCaseJson "height-mismatch-rejected" heightMismatch ++ ",\n"
    ++ announcedBlockCaseJson "height-overflow-rejected" heightOverflow ++ ",\n"
    ++ announcedBlockCaseJson "parent-hash-mismatch-rejected" parentMismatch ++ ",\n"
    ++ announcedBlockCaseJson "timestamp-did-not-advance-rejected"
      timestampDidNotAdvance ++ ",\n"
    ++ announcedBlockCaseJson "future-skew-rejected" futureSkew ++ ",\n"
    ++ announcedBlockCaseJson "hash-work-hash-mismatch-rejected"
      hashWorkHashMismatch ++ ",\n"
    ++ announcedBlockCaseJson "parent-mismatch-precedes-timestamp-failure"
      parent_mismatch_precedes_timestamp_failure_input ++ ",\n"
    ++ announcedBlockCaseJson "saturated-future-limit-accepts-max-timestamp"
      saturatedFutureLimitAcceptsMaxTimestamp ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
