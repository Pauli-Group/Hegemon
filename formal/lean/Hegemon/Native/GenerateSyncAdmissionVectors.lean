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

def requestRateCaseJson (name : String) (input : SyncRequestRateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"requests_in_window\": " ++ natJson input.requestsInWindow ++ ",\n"
    ++ "      \"max_requests\": " ++ natJson input.maxRequests ++ ",\n"
    ++ "      \"window_elapsed_ms\": " ++ natJson input.windowElapsedMs ++ ",\n"
    ++ "      \"window_ms\": " ++ natJson input.windowMs ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (requestRateAccepts input) ++ "\n"
    ++ "    }"

def requestRateStateCaseJson
    (name : String)
    (input : SyncRequestRateStateBoundInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_entries\": " ++ natJson input.currentEntries ++ ",\n"
    ++ "      \"max_entries\": " ++ natJson input.maxEntries ++ ",\n"
    ++ "      \"expected_retained_before_insert\": "
      ++ natJson (requestRateStateRetainedBeforeInsert input) ++ ",\n"
    ++ "      \"expected_entries_after_insert\": "
      ++ natJson (requestRateStateEntriesAfterInsert input) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (requestRateStateAccepts input) ++ "\n"
    ++ "    }"

def miningSyncEvidenceCaseJson
    (name : String)
    (input : MiningSyncEvidenceInput) : String :=
  let observed := miningSyncObservedPeerHeight input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"verified_new_progress\": " ++ boolJson input.verifiedNewProgress ++ ",\n"
    ++ "      \"verified_known_at_or_below_local_best\": "
      ++ boolJson input.verifiedKnownAtOrBelowLocalBest ++ ",\n"
    ++ "      \"local_best_height\": " ++ natJson input.localBestHeight ++ ",\n"
    ++ "      \"peer_best_height\": " ++ natJson input.peerBestHeight ++ ",\n"
    ++ "      \"stopped_on_error\": " ++ boolJson input.stoppedOnError ++ ",\n"
    ++ "      \"expected_observed_height\": " ++ optionNatJson observed ++ "\n"
    ++ "    }"

def miningGateCaseJson
    (name : String)
    (input : MiningGateInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"has_seeds\": " ++ boolJson input.hasSeeds ++ ",\n"
    ++ "      \"dev\": " ++ boolJson input.dev ++ ",\n"
    ++ "      \"bootstrap_authoring\": " ++ boolJson input.bootstrapAuthoring ++ ",\n"
    ++ "      \"observed_gate_open\": " ++ boolJson input.observedGateOpen ++ ",\n"
    ++ "      \"expected_allows_work\": " ++ boolJson (miningGateAllowsWork input) ++ "\n"
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
    ++ "  ],\n"
    ++ "  \"sync_request_rate_cases\": [\n"
    ++ requestRateCaseJson "request-rate-under-limit" requestRateUnderLimit ++ ",\n"
    ++ requestRateCaseJson "request-rate-full-window-rejected" requestRateFullWindow ++ ",\n"
    ++ requestRateCaseJson "request-rate-elapsed-window-accepted" requestRateElapsedWindow ++ ",\n"
    ++ requestRateCaseJson "request-rate-zero-cap-rejected" requestRateZeroCap ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_request_rate_state_cases\": [\n"
    ++ requestRateStateCaseJson "request-rate-state-below-cap" requestRateStateBelowCap ++ ",\n"
    ++ requestRateStateCaseJson "request-rate-state-at-cap" requestRateStateAtCap ++ ",\n"
    ++ requestRateStateCaseJson "request-rate-state-over-cap" requestRateStateOverCap ++ ",\n"
    ++ requestRateStateCaseJson "request-rate-state-zero-cap" requestRateStateZeroCap ++ "\n"
    ++ "  ],\n"
    ++ "  \"mining_sync_evidence_cases\": [\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-imported-progress"
      miningEvidenceImportedProgress ++ ",\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-known-equal-tip"
      miningEvidenceKnownEqualTip ++ ",\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-known-below-tip"
      miningEvidenceKnownBelowTip ++ ",\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-known-ahead-rejects"
      miningEvidenceKnownAheadRejects ++ ",\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-missing-parent-rejects"
      miningEvidenceMissingParentRejects ++ ",\n"
    ++ miningSyncEvidenceCaseJson "mining-evidence-error-rejects"
      miningEvidenceErrorRejects ++ "\n"
    ++ "  ],\n"
    ++ "  \"mining_gate_cases\": [\n"
    ++ miningGateCaseJson "mining-gate-live-empty-no-bootstrap-rejects"
      miningGateLiveEmptyNoBootstrap ++ ",\n"
    ++ miningGateCaseJson "mining-gate-dev-empty-allows" miningGateDevEmpty ++ ",\n"
    ++ miningGateCaseJson "mining-gate-bootstrap-empty-allows"
      miningGateBootstrapEmpty ++ ",\n"
    ++ miningGateCaseJson "mining-gate-seeded-closed-rejects"
      miningGateSeededClosed ++ ",\n"
    ++ miningGateCaseJson "mining-gate-seeded-open-allows"
      miningGateSeededOpen ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
