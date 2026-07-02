import Hegemon.Consensus.PowRules

open Hegemon.Consensus

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def resultLabel : Except PowAdmissionReject Nat -> String
  | Except.ok _ => "accepted"
  | Except.error PowAdmissionReject.heightMismatch => "height_mismatch"
  | Except.error PowAdmissionReject.powBitsMismatch => "pow_bits_mismatch"
  | Except.error PowAdmissionReject.timestampNotAdvanced => "timestamp_not_advanced"
  | Except.error PowAdmissionReject.timestampNotAfterMedian => "timestamp_not_after_median"
  | Except.error PowAdmissionReject.timestampFutureSkew => "timestamp_future_skew"
  | Except.error PowAdmissionReject.invalidCompactTarget => "invalid_compact_target"
  | Except.error PowAdmissionReject.insufficientWork => "insufficient_work"
  | Except.error PowAdmissionReject.cumulativeWorkOverflow => "cumulative_work_overflow"
  | Except.error PowAdmissionReject.cumulativeWorkMismatch => "cumulative_work_mismatch"

def scheduleResultLabel : Except PowBitsScheduleReject Nat -> String
  | Except.ok _ => "accepted"
  | Except.error PowBitsScheduleReject.insufficientHistory => "insufficient_history"
  | Except.error PowBitsScheduleReject.invalidCompactTarget => "invalid_compact_target"

def expectedCumulative : PowAdmissionInput -> Option Nat
  | input =>
    match compactTargetValue input.powBits with
    | none => none
    | some target => checkedWorkAdd input.parentWork (targetWork target)

def powCaseJson (name : String) (input : PowAdmissionInput) : String :=
  let target := compactTargetValue input.powBits
  let blockWork := target.map targetWork
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"parent_height\": " ++ toString input.parentHeight ++ ",\n"
    ++ "      \"header_height\": " ++ toString input.headerHeight ++ ",\n"
    ++ "      \"expected_pow_bits\": " ++ toString input.expectedPowBits ++ ",\n"
    ++ "      \"pow_bits\": " ++ toString input.powBits ++ ",\n"
    ++ "      \"parent_timestamp_ms\": " ++ toString input.parentTimestamp ++ ",\n"
    ++ "      \"median_time_past_ms\": " ++ toString input.medianTimePast ++ ",\n"
    ++ "      \"now_ms\": " ++ toString input.nowMs ++ ",\n"
    ++ "      \"header_timestamp_ms\": " ++ toString input.headerTimestamp ++ ",\n"
    ++ "      \"work_hash_value\": \"" ++ toString input.workHashValue ++ "\",\n"
    ++ "      \"parent_work\": \"" ++ toString input.parentWork ++ "\",\n"
    ++ "      \"claimed_cumulative_work\": \"" ++ toString input.claimedCumulativeWork ++ "\",\n"
    ++ "      \"expected_target\": " ++ optionNatJson target ++ ",\n"
    ++ "      \"expected_block_work\": " ++ optionNatJson blockWork ++ ",\n"
    ++ "      \"expected_cumulative_work\": " ++ optionNatJson (expectedCumulative input) ++ ",\n"
    ++ "      \"expected_result\": \"" ++ resultLabel (evaluatePowAdmission input) ++ "\"\n"
    ++ "    }"

def retargetCaseJson
    (name : String)
    (prevTarget actualTimespanMs : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"prev_target\": \"" ++ toString prevTarget ++ "\",\n"
    ++ "      \"actual_timespan_ms\": " ++ toString actualTimespanMs ++ ",\n"
    ++ "      \"expected_adjusted_timespan_ms\": " ++ toString (adjustedTimespan actualTimespanMs) ++ ",\n"
    ++ "      \"expected_target\": \"" ++ toString (retargetTarget prevTarget actualTimespanMs) ++ "\"\n"
    ++ "    }"

def compactRoundtripCaseJson
    (name : String)
    (target : Nat) : String :=
  let bits := targetToCompact target
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"target\": \"" ++ toString target ++ "\",\n"
    ++ "      \"expected_bits\": " ++ toString bits ++ ",\n"
    ++ "      \"expected_roundtrip_target\": "
    ++ optionNatJson (compactTargetValue bits) ++ "\n"
    ++ "    }"

def retargetBitsCaseJson
    (name : String)
    (prevBits actualTimespanMs : Nat) : String :=
  let prevTarget := compactTargetValue prevBits
  let newTarget := prevTarget.map (fun target => retargetTarget target actualTimespanMs)
  let newBits := retargetBits prevBits actualTimespanMs
  let encodedTarget :=
    match newBits with
    | none => none
    | some bits => compactTargetValue bits
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"prev_bits\": " ++ toString prevBits ++ ",\n"
    ++ "      \"actual_timespan_ms\": " ++ toString actualTimespanMs ++ ",\n"
    ++ "      \"expected_prev_target\": " ++ optionNatJson prevTarget ++ ",\n"
    ++ "      \"expected_target\": " ++ optionNatJson newTarget ++ ",\n"
    ++ "      \"expected_bits\": " ++ optionNatJson newBits ++ ",\n"
    ++ "      \"expected_encoded_target\": " ++ optionNatJson encodedTarget ++ "\n"
    ++ "    }"

def powBitsScheduleCaseJson
    (name : String)
    (genesisBits parentBits parentHeight newHeight parentTimestamp : Nat)
    (anchorTimestamp : Option Nat) : String :=
  let result :=
    expectedPowBitsSchedule
      genesisBits
      parentBits
      parentHeight
      newHeight
      parentTimestamp
      anchorTimestamp
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"genesis_pow_bits\": " ++ toString genesisBits ++ ",\n"
    ++ "      \"parent_pow_bits\": " ++ toString parentBits ++ ",\n"
    ++ "      \"parent_height\": " ++ toString parentHeight ++ ",\n"
    ++ "      \"new_height\": " ++ toString newHeight ++ ",\n"
    ++ "      \"parent_timestamp_ms\": " ++ toString parentTimestamp ++ ",\n"
    ++ "      \"anchor_timestamp_ms\": " ++ optionNatJson anchorTimestamp ++ ",\n"
    ++ "      \"expected_anchor_steps\": "
    ++ optionNatJson (retargetAnchorSteps parentHeight newHeight) ++ ",\n"
    ++ "      \"expected_bits\": "
    ++ optionNatJson (match result with | Except.ok bits => some bits | Except.error _ => none) ++ ",\n"
    ++ "      \"expected_result\": \"" ++ scheduleResultLabel result ++ "\"\n"
    ++ "    }"

def easyPowBits : Nat := 545259519
def maxPowHeightPredecessor : Nat := maxPowHeight - 1
def invalidZeroMantissaBits : Nat := 536870912
def invalidShiftedZeroTargetBits : Nat := 16777217
def invalidLargeExponentBits : Nat := 570425343
def easyTarget : Nat :=
  match compactTargetValue easyPowBits with
  | some target => target
  | none => 0
def easyWork : Nat := targetWork easyTarget

def validInput : PowAdmissionInput := {
  parentHeight := 41,
  headerHeight := 42,
  expectedPowBits := easyPowBits,
  powBits := easyPowBits,
  parentTimestamp := 100000,
  medianTimePast := 99000,
  nowMs := 105000,
  headerTimestamp := 100001,
  workHashValue := easyTarget,
  parentWork := 7,
  claimedCumulativeWork := 7 + easyWork
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"compact_roundtrip_cases\": [\n"
    ++ compactRoundtripCaseJson "zero-target-encodes-zero-bits" 0 ++ ",\n"
    ++ compactRoundtripCaseJson "one-target-roundtrips" 1 ++ ",\n"
    ++ compactRoundtripCaseJson "three-byte-target-roundtrips" 66051 ++ ",\n"
    ++ compactRoundtripCaseJson "easy-target-roundtrips" easyTarget ++ "\n"
    ++ "  ],\n"
    ++ "  \"retarget_cases\": [\n"
    ++ retargetCaseJson "zero-previous-target-stays-zero" 0 retargetTimespanMs ++ ",\n"
    ++ retargetCaseJson "expected-timespan-keeps-target" 1000000 retargetTimespanMs ++ ",\n"
    ++ retargetCaseJson "fast-timespan-clamps-to-quarter" 1000000 0 ++ ",\n"
    ++ retargetCaseJson "slow-timespan-clamps-to-four-x" 1000000 (retargetTimespanMs * 10) ++ ",\n"
    ++ retargetCaseJson "small-target-retarget-never-drops-to-zero" 1 0 ++ "\n"
    ++ "  ],\n"
    ++ "  \"retarget_bits_cases\": [\n"
    ++ retargetBitsCaseJson "expected-timespan-keeps-compact-bits" easyPowBits retargetTimespanMs ++ ",\n"
    ++ retargetBitsCaseJson "fast-timespan-reencodes-quarter-target" easyPowBits 0 ++ ",\n"
    ++ retargetBitsCaseJson "slow-timespan-reencodes-four-x-target" easyPowBits (retargetTimespanMs * 10) ++ ",\n"
    ++ retargetBitsCaseJson "invalid-previous-bits-rejected" invalidShiftedZeroTargetBits retargetTimespanMs ++ "\n"
    ++ "  ],\n"
    ++ "  \"pow_bits_schedule_cases\": [\n"
    ++ powBitsScheduleCaseJson "genesis-height-uses-genesis-bits" 123 456 0 0 0 none ++ ",\n"
    ++ powBitsScheduleCaseJson "non-boundary-inherits-parent-bits" 123 easyPowBits 8 9 100000 none ++ ",\n"
    ++ powBitsScheduleCaseJson "early-boundary-inherits-parent-bits" 123 easyPowBits 0 retargetWindow 100000 none ++ ",\n"
    ++ powBitsScheduleCaseJson "first-boundary-inherits-parent-bits" 123 easyPowBits 9 retargetWindow retargetTimespanMs none ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-missing-history-rejected" 123 easyPowBits 19 (retargetWindow * 2) retargetTimespanMs none ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-expected-timespan-keeps-bits" 123 easyPowBits 19 (retargetWindow * 2) retargetTimespanMs (some 0) ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-fast-timespan-reencodes-bits" 123 easyPowBits 19 (retargetWindow * 2) 0 (some 0) ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-slow-timespan-reencodes-bits" 123 easyPowBits 19 (retargetWindow * 2) (retargetTimespanMs * 10) (some 0) ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-reversed-timestamp-saturates" 123 easyPowBits 19 (retargetWindow * 2) 100 (some 200) ++ ",\n"
    ++ powBitsScheduleCaseJson "boundary-invalid-previous-bits-rejected" 123 invalidShiftedZeroTargetBits 19 (retargetWindow * 2) retargetTimespanMs (some 0) ++ "\n"
    ++ "  ],\n"
    ++ "  \"pow_admission_cases\": [\n"
    ++ powCaseJson "valid-boundary-hash-accepted" validInput ++ ",\n"
    ++ powCaseJson "height-mismatch-rejected" { validInput with headerHeight := 43 } ++ ",\n"
    ++ powCaseJson "height-overflow-rejected" { validInput with parentHeight := maxPowHeight, headerHeight := maxPowHeight } ++ ",\n"
    ++ powCaseJson "max-predecessor-height-accepted" { validInput with parentHeight := maxPowHeightPredecessor, headerHeight := maxPowHeight } ++ ",\n"
    ++ powCaseJson "pow-bits-mismatch-rejected" { validInput with powBits := 545259518 } ++ ",\n"
    ++ powCaseJson "timestamp-equal-parent-rejected" { validInput with headerTimestamp := validInput.parentTimestamp } ++ ",\n"
    ++ powCaseJson "timestamp-equal-median-rejected" { validInput with parentTimestamp := 10, medianTimePast := 20, headerTimestamp := 20 } ++ ",\n"
    ++ powCaseJson "timestamp-future-skew-rejected" { validInput with parentTimestamp := 1000, medianTimePast := 900, nowMs := 1000, headerTimestamp := 92001 } ++ ",\n"
    ++ powCaseJson "zero-mantissa-target-rejected" { validInput with expectedPowBits := invalidZeroMantissaBits, powBits := invalidZeroMantissaBits } ++ ",\n"
    ++ powCaseJson "shifted-zero-target-rejected" { validInput with expectedPowBits := invalidShiftedZeroTargetBits, powBits := invalidShiftedZeroTargetBits, workHashValue := 0 } ++ ",\n"
    ++ powCaseJson "large-exponent-target-rejected" { validInput with expectedPowBits := invalidLargeExponentBits, powBits := invalidLargeExponentBits } ++ ",\n"
    ++ powCaseJson "insufficient-work-rejected" { validInput with workHashValue := easyTarget + 1 } ++ ",\n"
    ++ powCaseJson "cumulative-work-mismatch-rejected" { validInput with claimedCumulativeWork := easyWork } ++ ",\n"
    ++ powCaseJson "cumulative-work-overflow-rejected" { validInput with parentWork := maxWork48, claimedCumulativeWork := maxWork48 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
