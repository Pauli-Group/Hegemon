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

def easyPowBits : Nat := 545259519
def maxPowHeightPredecessor : Nat := maxPowHeight - 1
def invalidZeroMantissaBits : Nat := 536870912
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
    ++ powCaseJson "large-exponent-target-rejected" { validInput with expectedPowBits := invalidLargeExponentBits, powBits := invalidLargeExponentBits } ++ ",\n"
    ++ powCaseJson "insufficient-work-rejected" { validInput with workHashValue := easyTarget + 1 } ++ ",\n"
    ++ powCaseJson "cumulative-work-mismatch-rejected" { validInput with claimedCumulativeWork := easyWork } ++ ",\n"
    ++ powCaseJson "cumulative-work-overflow-rejected" { validInput with parentWork := maxWork48, claimedCumulativeWork := maxWork48 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
