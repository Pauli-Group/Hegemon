import Hegemon.Bridge.HeaderMmr

open Hegemon.Bridge.HeaderMmr

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def boolArrayJson : List Bool -> String
  | [] => "[]"
  | first :: rest =>
      "[" ++ boolJson first ++ rest.foldl (fun acc value => acc ++ ", " ++ boolJson value) "" ++ "]"

def rejectJson : Reject -> String
  | Reject.headerMmrMismatch => "\"header_mmr_mismatch\""
  | Reject.leafOutOfRange => "\"header_mmr_leaf_out_of_range\""
  | Reject.openingMismatch => "\"header_mmr_opening_mismatch\""
  | Reject.peakMismatch => "\"header_mmr_peak_mismatch\""

def nullableNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def nullableBoolArrayJson : Option (List Bool) -> String
  | none => "null"
  | some value => boolArrayJson value

def shapeCaseJson (name : String) (input : ShapeInput) : String :=
  let shape := acceptedShape input
  let expectedValid := shape.isSome
  let expectedReject := match rejection input with
    | none => "null"
    | some reject => rejectJson reject
  let expectedPeakIndex := shape.map (fun value => value.peakIndex)
  let expectedPeakStart := shape.map (fun value => value.peakStart)
  let expectedPeakSize := shape.map (fun value => value.peakSize)
  let expectedSiblings := shape.map (fun value => value.expectedSiblings)
  let expectedLocalIndex := shape.map (fun value => value.localIndex)
  let expectedCurrentIsLeft := shape.map (fun value => value.currentIsLeft)
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"context_matches\": " ++ boolJson input.contextMatches ++ ",\n"
    ++ "      \"leaf_index\": " ++ toString input.leafIndex ++ ",\n"
    ++ "      \"leaf_count\": " ++ toString input.leafCount ++ ",\n"
    ++ "      \"sibling_count\": " ++ toString input.siblingCount ++ ",\n"
    ++ "      \"peak_count\": " ++ toString input.peakCount ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson expectedValid ++ ",\n"
    ++ "      \"expected_rejection\": " ++ expectedReject ++ ",\n"
    ++ "      \"expected_peak_index\": " ++ nullableNatJson expectedPeakIndex ++ ",\n"
    ++ "      \"expected_peak_start\": " ++ nullableNatJson expectedPeakStart ++ ",\n"
    ++ "      \"expected_peak_size\": " ++ nullableNatJson expectedPeakSize ++ ",\n"
    ++ "      \"expected_siblings\": " ++ nullableNatJson expectedSiblings ++ ",\n"
    ++ "      \"expected_local_index\": " ++ nullableNatJson expectedLocalIndex ++ ",\n"
    ++ "      \"expected_current_is_left\": " ++ nullableBoolArrayJson expectedCurrentIsLeft ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"header_mmr_shape_cases\": [\n"
    ++ shapeCaseJson "valid-six-leaf-second-peak" validShape ++ ",\n"
    ++ shapeCaseJson "singleton-zero-siblings" singletonShape ++ ",\n"
    ++ shapeCaseJson "four-leaf-left-orientation" fourLeafLeftShape ++ ",\n"
    ++ shapeCaseJson "four-leaf-right-orientation" fourLeafRightShape ++ ",\n"
    ++ shapeCaseJson "context-mismatch-rejected"
      { validShape with contextMatches := false } ++ ",\n"
    ++ shapeCaseJson "leaf-oob-rejected"
      { validShape with leafIndex := 6 } ++ ",\n"
    ++ shapeCaseJson "empty-leaf-set-rejected"
      { singletonShape with leafCount := 0, peakCount := 0 } ++ ",\n"
    ++ shapeCaseJson "peak-count-mismatch-rejected"
      { validShape with peakCount := 1 } ++ ",\n"
    ++ shapeCaseJson "sibling-count-mismatch-rejected"
      { validShape with siblingCount := 2 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
