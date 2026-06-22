import Hegemon.Native.SyncAdmission

open Hegemon.Native.SyncAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natJson (value : Nat) : String :=
  toString value

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => natJson value

def responseRangeCaseJson (name : String) (input : SyncResponseRangeInput) : String :=
  let result := responseRange input
  let expectedFrom := result.map Prod.fst
  let expectedTo := result.map Prod.snd
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"from_height\": " ++ natJson input.fromHeight ++ ",\n"
    ++ "      \"to_height\": " ++ natJson input.toHeight ++ ",\n"
    ++ "      \"best_height\": " ++ natJson input.bestHeight ++ ",\n"
    ++ "      \"max_blocks\": " ++ natJson input.maxBlocks ++ ",\n"
    ++ "      \"expected_has_range\": " ++ boolJson (result.isSome) ++ ",\n"
    ++ "      \"expected_from_height\": " ++ optionNatJson expectedFrom ++ ",\n"
    ++ "      \"expected_to_height\": " ++ optionNatJson expectedTo ++ "\n"
    ++ "    }"

def missingRequestCaseJson (name : String) (input : SyncMissingRequestInput) : String :=
  let result := missingRequestRange input
  let expectedFrom := result.map Prod.fst
  let expectedTo := result.map Prod.snd
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"best_height\": " ++ natJson input.bestHeight ++ ",\n"
    ++ "      \"announced_height\": " ++ natJson input.announcedHeight ++ ",\n"
    ++ "      \"max_blocks\": " ++ natJson input.maxBlocks ++ ",\n"
    ++ "      \"expected_has_request\": " ++ boolJson (result.isSome) ++ ",\n"
    ++ "      \"expected_from_height\": " ++ optionNatJson expectedFrom ++ ",\n"
    ++ "      \"expected_to_height\": " ++ optionNatJson expectedTo ++ "\n"
    ++ "    }"

def responseCountCaseJson (name : String) (input : SyncResponseCountInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"block_count\": " ++ natJson input.blockCount ++ ",\n"
    ++ "      \"max_blocks\": " ++ natJson input.maxBlocks ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (responseCountAccepts input) ++ "\n"
    ++ "    }"

def responseRangeToBeforeFrom : SyncResponseRangeInput :=
  {
    fromHeight := 100,
    toHeight := 90,
    bestHeight := 200,
    maxBlocks := 512
  }

def responseRangeZeroMax : SyncResponseRangeInput :=
  {
    fromHeight := 100,
    toHeight := 100,
    bestHeight := 200,
    maxBlocks := 0
  }

def missingRequestSaturating : SyncMissingRequestInput :=
  {
    bestHeight := u64Max - 5,
    announcedHeight := u64Max,
    maxBlocks := 512
  }

def missingRequestZeroMax : SyncMissingRequestInput :=
  {
    bestHeight := 50,
    announcedHeight := 55,
    maxBlocks := 0
  }

def responseCountUnderLimit : SyncResponseCountInput :=
  {
    blockCount := 7,
    maxBlocks := 512
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sync_response_range_cases\": [\n"
    ++ responseRangeCaseJson "response-range-valid" responseRangeValid ++ ",\n"
    ++ responseRangeCaseJson "response-range-caps-at-best" responseRangeCapsAtBest ++ ",\n"
    ++ responseRangeCaseJson "response-range-caps-at-max-blocks"
      responseRangeCapsAtMaxBlocks ++ ",\n"
    ++ responseRangeCaseJson "response-range-empty-from-past-best"
      responseRangeEmptyWhenFromPastBest ++ ",\n"
    ++ responseRangeCaseJson "response-range-empty-to-before-from"
      responseRangeToBeforeFrom ++ ",\n"
    ++ responseRangeCaseJson "response-range-empty-zero-max" responseRangeZeroMax ++ ",\n"
    ++ responseRangeCaseJson "response-range-saturating" responseRangeSaturatingInput ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_missing_request_cases\": [\n"
    ++ missingRequestCaseJson "missing-request-noop" missingRequestNoop ++ ",\n"
    ++ missingRequestCaseJson "missing-request-short" missingRequestShort ++ ",\n"
    ++ missingRequestCaseJson "missing-request-caps-at-max-blocks"
      missingRequestCapsAtMaxBlocks ++ ",\n"
    ++ missingRequestCaseJson "missing-request-bootstrap-fork"
      missingRequestBootstrapFork ++ ",\n"
    ++ missingRequestCaseJson "missing-request-at-u64-max"
      missingRequestAtU64Max ++ ",\n"
    ++ missingRequestCaseJson "missing-request-saturating" missingRequestSaturating ++ ",\n"
    ++ missingRequestCaseJson "missing-request-zero-max" missingRequestZeroMax ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_response_count_cases\": [\n"
    ++ responseCountCaseJson "response-count-under-limit" responseCountUnderLimit ++ ",\n"
    ++ responseCountCaseJson "response-count-exact-limit" responseCountExactLimit ++ ",\n"
    ++ responseCountCaseJson "response-count-over-limit" responseCountOverLimit ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
