import Hegemon.Consensus.PowRulesV3

open Hegemon.Consensus.PowRulesV3

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => "\"" ++ toString value ++ "\""

def admissionLabel : Except PowAdmissionReject Nat -> String
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

def compactCaseJson (name : String) (bits : Nat) : String :=
  let target := compactTargetValue bits
  let roundtrip := target.bind targetToCompact
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"bits\": " ++ toString bits ++ ",\n"
    ++ "      \"expected_target\": " ++ optionNatJson target ++ ",\n"
    ++ "      \"expected_roundtrip_bits\": " ++ optionNatJson roundtrip ++ "\n"
    ++ "    }"

def workCaseJson (name : String) (bits : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"bits\": " ++ toString bits ++ ",\n"
    ++ "      \"expected_target\": " ++ optionNatJson (compactTargetValue bits) ++ ",\n"
    ++ "      \"expected_block_work\": " ++ optionNatJson (blockWorkFromBits bits) ++ "\n"
    ++ "    }"

def retargetCaseJson (name : String) (bits actualMs : Nat) : String :=
  let previous := compactTargetValue bits
  let target := previous.map (fun value => retargetTarget value actualMs)
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"previous_bits\": " ++ toString bits ++ ",\n"
    ++ "      \"actual_timespan_ms\": " ++ toString actualMs ++ ",\n"
    ++ "      \"expected_target\": " ++ optionNatJson target ++ ",\n"
    ++ "      \"expected_bits\": " ++ optionNatJson (retargetBits bits actualMs) ++ "\n"
    ++ "    }"

def expectedCumulativeWork (input : PowAdmissionInput) : Option Nat :=
  match compactTargetValue input.powBits with
  | none => none
  | some target => checkedWorkAdd input.parentWork (targetWork target)

def admissionCaseJson (name : String) (input : PowAdmissionInput) : String :=
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
    ++ "      \"expected_target\": " ++ optionNatJson (compactTargetValue input.powBits) ++ ",\n"
    ++ "      \"expected_block_work\": " ++ optionNatJson (blockWorkFromBits input.powBits) ++ ",\n"
    ++ "      \"expected_cumulative_work\": " ++ optionNatJson (expectedCumulativeWork input) ++ ",\n"
    ++ "      \"expected_result\": \"" ++ admissionLabel (evaluatePowAdmission input) ++ "\"\n"
    ++ "    }"

def katBits : Nat := 756167766 -- 0x2d12_3456
def equalTarget : Nat := (compactTargetValue katBits).getD 0
def katBlockWork : Nat := targetWork equalTarget

def validInput : PowAdmissionInput := {
  parentHeight := 41,
  headerHeight := 42,
  expectedPowBits := katBits,
  powBits := katBits,
  parentTimestamp := 100000,
  medianTimePast := 99000,
  nowMs := 105000,
  headerTimestamp := 100001,
  workHashValue := equalTarget,
  parentWork := 7,
  claimedCumulativeWork := 7 + katBlockWork
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"target_bits\": " ++ toString targetBits ++ ",\n"
    ++ "  \"work_bits\": " ++ toString workBits ++ ",\n"
    ++ "  \"target_bytes\": " ++ toString targetBytes ++ ",\n"
    ++ "  \"work_bytes\": " ++ toString workBytes ++ ",\n"
    ++ "  \"pow_limit_bits\": " ++ toString powLimitBits ++ ",\n"
    ++ "  \"pow_limit_target\": \"" ++ toString powLimitTarget ++ "\",\n"
    ++ "  \"compact_cases\": [\n"
    ++ compactCaseJson "kat-target-roundtrip" katBits ++ ",\n"
    ++ compactCaseJson "one-target-roundtrip" 16842752 ++ ",\n" -- 0x0101_0000
    ++ compactCaseJson "exponent-48-pow-limit" powLimitBits ++ ",\n"
    ++ compactCaseJson "zero-mantissa-rejected" 805306368 ++ ",\n" -- 0x3000_0000
    ++ compactCaseJson "shifted-zero-rejected" 16777217 ++ ",\n"
    ++ compactCaseJson "exponent-49-rejected" 822149120 ++ "\n"
    ++ "  ],\n"
    ++ "  \"work_cases\": [\n"
    ++ workCaseJson "kat-work" katBits ++ ",\n"
    ++ workCaseJson "pow-limit-work-is-one" powLimitBits ++ "\n"
    ++ "  ],\n"
    ++ "  \"retarget_cases\": [\n"
    ++ retargetCaseJson "expected-timespan-keeps-target" katBits retargetTimespanMs ++ ",\n"
    ++ retargetCaseJson "fast-timespan-clamps-quarter" katBits 0 ++ ",\n"
    ++ retargetCaseJson "slow-timespan-clamps-four-x" katBits (retargetTimespanMs * 10) ++ ",\n"
    ++ retargetCaseJson "pow-limit-slow-timespan-clamps-limit" powLimitBits (retargetTimespanMs * 10) ++ "\n"
    ++ "  ],\n"
    ++ "  \"admission_cases\": [\n"
    ++ admissionCaseJson "target-equality-accepted" validInput ++ ",\n"
    ++ admissionCaseJson "height-precedes-bits" { validInput with headerHeight := 43, powBits := 0 } ++ ",\n"
    ++ admissionCaseJson "height-overflow-rejected" { validInput with parentHeight := maxHeight, headerHeight := maxHeight } ++ ",\n"
    ++ admissionCaseJson "bits-precede-timestamp" { validInput with powBits := powLimitBits, headerTimestamp := validInput.parentTimestamp } ++ ",\n"
    ++ admissionCaseJson "timestamp-equal-parent-rejected" { validInput with headerTimestamp := validInput.parentTimestamp } ++ ",\n"
    ++ admissionCaseJson "timestamp-equal-median-rejected" { validInput with parentTimestamp := 10, medianTimePast := 20, headerTimestamp := 20 } ++ ",\n"
    ++ admissionCaseJson "timestamp-future-skew-rejected" { validInput with parentTimestamp := 1000, medianTimePast := 900, nowMs := 1000, headerTimestamp := 92001 } ++ ",\n"
    ++ admissionCaseJson "invalid-target-rejected" { validInput with expectedPowBits := 805306368, powBits := 805306368 } ++ ",\n"
    ++ admissionCaseJson "target-successor-rejected" { validInput with workHashValue := equalTarget + 1 } ++ ",\n"
    ++ admissionCaseJson "cumulative-mismatch-rejected" { validInput with claimedCumulativeWork := katBlockWork } ++ ",\n"
    ++ admissionCaseJson "work64-overflow-rejected" { validInput with parentWork := maxWorkValue, claimedCumulativeWork := maxWorkValue } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit := IO.print vectorJson
