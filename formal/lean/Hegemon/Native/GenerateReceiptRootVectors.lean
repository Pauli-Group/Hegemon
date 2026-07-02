import Hegemon.Native.ReceiptRoot

open Hegemon
open Hegemon.Native.ReceiptRoot

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natArrayJson (values : List Nat) : String :=
  "[" ++ String.intercalate ", " (values.map fun value => toString value) ++ "]"

def foldSummaryJson (fold : FoldSummary) : String :=
  "{ \"challenge_count\": " ++ toString fold.challengeCount
    ++ ", \"row_count\": " ++ toString fold.rowCount
    ++ ", \"row_coeff_counts\": " ++ natArrayJson fold.rowCoeffCounts
    ++ " }"

def foldSummaryArrayJson (folds : List FoldSummary) : String :=
  "[" ++ String.intercalate ", " (folds.map foldSummaryJson) ++ "]"

def receiptRootSummaryJson (summary : ReceiptRootSummary) : String :=
  "{\n"
    ++ "        \"version\": " ++ toString summary.version ++ ",\n"
    ++ "        \"leaf_count\": " ++ toString summary.leafCount ++ ",\n"
    ++ "        \"fold_count\": " ++ toString summary.foldCount ++ ",\n"
    ++ "        \"folds\": " ++ foldSummaryArrayJson summary.folds ++ "\n"
    ++ "      }"

def resourceRequestJson (request : Hegemon.Resource.BoundedRequestAdmission.ResourceRequest) :
    String :=
  "{ \"raw_bytes\": " ++ toString request.rawBytes
    ++ ", \"decoded_bytes\": " ++ toString request.decodedBytes
    ++ ", \"item_count\": " ++ toString request.itemCount
    ++ ", \"max_item_bytes\": " ++ toString request.maxItemBytes
    ++ ", \"aggregate_bytes\": " ++ toString request.aggregateBytes
    ++ ", \"work_units\": " ++ toString request.workUnits
    ++ " }"

def summaryFieldJson (summary : Option ReceiptRootSummary) : String :=
  match summary with
  | none => "null"
  | some value => receiptRootSummaryJson value

def resourceFieldJson (artifact : List Byte) (summary : Option ReceiptRootSummary) : String :=
  match summary with
  | none => "null"
  | some value =>
      resourceRequestJson (receiptRootArtifactResourceRequest artifact value)

def receiptRootCaseJson (name : String) (expectedLeafCount : Nat) (artifact : List Byte) : String :=
  let summary := parseNativeReceiptRootArtifact artifact
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"artifact_hex\": \"" ++ hexBytes artifact ++ "\",\n"
    ++ "      \"expected_record_count\": " ++ toString expectedLeafCount ++ ",\n"
    ++ "      \"expected_parse_valid\": " ++ boolJson summary.isSome ++ ",\n"
    ++ "      \"expected_schedule_valid\": " ++ boolJson (receiptRootScheduleAccepts expectedLeafCount artifact) ++ ",\n"
    ++ "      \"expected_summary\": " ++ summaryFieldJson summary ++ ",\n"
    ++ "      \"expected_resource_request\": "
    ++ resourceFieldJson artifact summary ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_receipt_root_cases\": [\n"
    ++ receiptRootCaseJson "valid-single-leaf" 1 validSingleArtifact ++ ",\n"
    ++ receiptRootCaseJson "valid-two-leaf" 2 validTwoArtifact ++ ",\n"
    ++ receiptRootCaseJson "valid-three-leaf-carry" 3 validThreeArtifact ++ ",\n"
    ++ receiptRootCaseJson "zero-expected-leaves-rejected" 0 validSingleArtifact ++ ",\n"
    ++ receiptRootCaseJson "artifact-leaf-count-mismatch-rejected" 1 leafMismatchArtifact ++ ",\n"
    ++ receiptRootCaseJson "missing-fold-rejected" 2 missingFoldArtifact ++ ",\n"
    ++ receiptRootCaseJson "extra-fold-rejected" 1 extraFoldArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-few-challenges-rejected" 2 tooFewChallengesArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-many-challenges-rejected" 2 tooManyChallengesArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-few-rows-rejected" 2 tooFewRowsArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-many-rows-rejected" 2 tooManyRowsArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-few-coefficients-rejected" 2 tooFewCoefficientsArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-many-coefficients-rejected" 2 tooManyCoefficientsArtifact ++ ",\n"
    ++ receiptRootCaseJson "zero-artifact-leaves-rejected" 0 zeroLeafArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-many-leaves-rejected" 1 tooManyLeavesArtifact ++ ",\n"
    ++ receiptRootCaseJson "too-many-folds-rejected" 1 tooManyFoldsArtifact ++ ",\n"
    ++ receiptRootCaseJson "trailing-byte-rejected" 1 trailingArtifact ++ ",\n"
    ++ receiptRootCaseJson "truncated-artifact-rejected" 2 truncatedArtifact ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
