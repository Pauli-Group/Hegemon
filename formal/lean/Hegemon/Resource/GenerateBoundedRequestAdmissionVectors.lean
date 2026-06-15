import Hegemon.Resource.BoundedRequestAdmission

open Hegemon.Resource.BoundedRequestAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natJson (value : Nat) : String :=
  toString value

def rejectionJson : Option ResourceReject -> String
  | none => "null"
  | some ResourceReject.rawBytesExceeded => "\"raw_bytes_exceeded\""
  | some ResourceReject.decodedBytesExceeded => "\"decoded_bytes_exceeded\""
  | some ResourceReject.itemCountExceeded => "\"item_count_exceeded\""
  | some ResourceReject.itemBytesExceeded => "\"item_bytes_exceeded\""
  | some ResourceReject.aggregateBytesExceeded =>
      "\"aggregate_bytes_exceeded\""
  | some ResourceReject.workUnitsExceeded => "\"work_units_exceeded\""

def caseJson
    (name : String)
    (policy : ResourcePolicy)
    (request : ResourceRequest) : String :=
  let result := evaluateBoundedRequest policy request
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"raw_byte_cap\": " ++ natJson policy.rawByteCap ++ ",\n"
    ++ "      \"decoded_byte_cap\": " ++ natJson policy.decodedByteCap ++ ",\n"
    ++ "      \"item_count_cap\": " ++ natJson policy.itemCountCap ++ ",\n"
    ++ "      \"item_byte_cap\": " ++ natJson policy.itemByteCap ++ ",\n"
    ++ "      \"aggregate_byte_cap\": " ++ natJson policy.aggregateByteCap ++ ",\n"
    ++ "      \"work_unit_cap\": " ++ natJson policy.workUnitCap ++ ",\n"
    ++ "      \"raw_bytes\": " ++ natJson request.rawBytes ++ ",\n"
    ++ "      \"decoded_bytes\": " ++ natJson request.decodedBytes ++ ",\n"
    ++ "      \"item_count\": " ++ natJson request.itemCount ++ ",\n"
    ++ "      \"max_item_bytes\": " ++ natJson request.maxItemBytes ++ ",\n"
    ++ "      \"aggregate_bytes\": " ++ natJson request.aggregateBytes ++ ",\n"
    ++ "      \"work_units\": " ++ natJson request.workUnits ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def multiOverRequest : ResourceRequest :=
  {
    rawBytes := 4097,
    decodedBytes := 2049,
    itemCount := 33,
    maxItemBytes := 513,
    aggregateBytes := 8193,
    workUnits := 1001
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bounded_request_cases\": [\n"
    ++ caseJson "exact-limit-accepted" examplePolicy exactLimitRequest
      ++ ",\n"
    ++ caseJson "raw-bytes-over-limit-rejected" examplePolicy
      rawBytesOverLimitRequest ++ ",\n"
    ++ caseJson "decoded-bytes-over-limit-rejected" examplePolicy
      decodedBytesOverLimitRequest ++ ",\n"
    ++ caseJson "item-count-over-limit-rejected" examplePolicy
      itemCountOverLimitRequest ++ ",\n"
    ++ caseJson "item-bytes-over-limit-rejected" examplePolicy
      itemBytesOverLimitRequest ++ ",\n"
    ++ caseJson "aggregate-bytes-over-limit-rejected" examplePolicy
      aggregateBytesOverLimitRequest ++ ",\n"
    ++ caseJson "work-units-over-limit-rejected" examplePolicy
      workUnitsOverLimitRequest ++ ",\n"
    ++ caseJson "first-rejection-precedence-raw-before-later-caps"
      examplePolicy multiOverRequest ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
