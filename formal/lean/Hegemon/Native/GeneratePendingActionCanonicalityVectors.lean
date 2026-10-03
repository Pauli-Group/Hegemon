import Hegemon.Native.PendingActionCanonicality

open Hegemon.Native.PendingActionCanonicality

def boolJson (value : Bool) : String := if value then "true" else "false"

def wireEraLabel : WireEra -> String
  | .activeV3 => "active_v3"
  | .legacyV2ReceivedMs => "legacy_v2_received_ms"
  | .legacyV1ActionId32ReceivedMs => "legacy_v1_action_id_32_received_ms"
  | .malformed => "malformed"

def rejectLabel : Reject -> String
  | .retiredV2ReceivedMs => "retired_v2_received_ms"
  | .retiredV1ActionId32 => "retired_v1_action_id_32"
  | .malformed => "malformed"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def caseJson (name : String) (wireEra : WireEra) (receivedMs : Option Nat) : String :=
  let result := evaluate { wireEra := wireEra, receivedMs := receivedMs }
  let valid := result.isOk
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ rejectLabel reject ++ "\""
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"wire_era\":\"" ++ wireEraLabel wireEra ++ "\","
    ++ "\"received_ms\":" ++ optionNatJson receivedMs ++ ","
    ++ "\"expected_valid\":" ++ boolJson valid ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def vectorJson : String :=
  let cases := [
    caseJson "active-v3-field-absent" .activeV3 none,
    caseJson "legacy-v2-zero-rejected" .legacyV2ReceivedMs (some 0),
    caseJson "legacy-v2-minimum-nonzero-rejected" .legacyV2ReceivedMs (some 1),
    caseJson "legacy-v2-maximum-u64-rejected" .legacyV2ReceivedMs (some u64Max),
    caseJson "legacy-v1-zero-rejected" .legacyV1ActionId32ReceivedMs (some 0),
    caseJson "legacy-v1-maximum-u64-rejected" .legacyV1ActionId32ReceivedMs (some u64Max),
    caseJson "malformed-rejected" .malformed none
  ]
  "{\n  \"schema\":2,\n  \"cases\":[\n"
    ++ String.intercalate ",\n" cases
    ++ "\n  ]\n}"

def main : IO Unit := IO.println vectorJson
