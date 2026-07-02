import Hegemon.Native.NativeBackendReviewPolicy

open Hegemon.Native.NativeBackendReviewPolicy

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option NativeBackendReviewReject -> String
  | none => "null"
  | some NativeBackendReviewReject.unsupportedReviewPosture =>
      "\"unsupported_review_posture\""
  | some NativeBackendReviewReject.insufficientSecurityClaim =>
      "\"insufficient_security_claim\""
  | some NativeBackendReviewReject.duplicateCaseName =>
      "\"duplicate_case_name\""
  | some NativeBackendReviewReject.unsupportedCaseKind =>
      "\"unsupported_case_kind\""
  | some NativeBackendReviewReject.invalidCaseExpectation =>
      "\"invalid_case_expectation\""
  | some NativeBackendReviewReject.missingRequiredCase =>
      "\"missing_required_case\""

def caseKindJson : ReviewCaseKind -> String
  | ReviewCaseKind.nativeTxLeaf => "\"native_tx_leaf\""
  | ReviewCaseKind.receiptRoot => "\"receipt_root\""
  | ReviewCaseKind.unsupported => "\"unsupported\""

def reviewCaseJson (case : ReviewCase) : String :=
  "        {\n"
    ++ "          \"name\": \"" ++ case.name ++ "\",\n"
    ++ "          \"kind\": " ++ caseKindJson case.kind ++ ",\n"
    ++ "          \"expected_valid\": " ++ boolJson case.expectedValid ++ ",\n"
    ++ "          \"has_expected_error\": " ++ boolJson case.hasExpectedError ++ "\n"
    ++ "        }"

def joinJsonItems : List String -> String
  | [] => ""
  | [item] => item
  | item :: rest => item ++ ",\n" ++ joinJsonItems rest

def reviewCasesJson (cases : List ReviewCase) : String :=
  joinJsonItems (cases.map reviewCaseJson)

def nativeBackendReviewPolicyCaseJson
    (name : String)
    (input : NativeBackendReviewInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"review_state_candidate_under_review\": "
      ++ boolJson input.reviewStateCandidateUnderReview ++ ",\n"
    ++ "      \"maturity_structural_candidate\": "
      ++ boolJson input.maturityStructuralCandidate ++ ",\n"
    ++ "      \"claimed_security_bits\": "
      ++ toString input.claimedSecurityBits ++ ",\n"
    ++ "      \"soundness_floor_bits\": "
      ++ toString input.soundnessFloorBits ++ ",\n"
    ++ "      \"commitment_binding_bits\": "
      ++ toString input.commitmentBindingBits ++ ",\n"
    ++ "      \"composition_loss_bits\": "
      ++ toString input.compositionLossBits ++ ",\n"
    ++ "      \"cases\": [\n"
    ++ reviewCasesJson input.cases ++ "\n"
    ++ "      ],\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (nativeBackendReviewAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (nativeBackendReviewRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_backend_review_policy_cases\": [\n"
    ++ nativeBackendReviewPolicyCaseJson "complete-review-bundle-accepts"
      completeReviewInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "wrong-review-posture-rejects"
      wrongReviewPostureInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "insufficient-security-floor-rejects"
      insufficientSecurityFloorInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "duplicate-case-name-rejects"
      duplicateCaseNameInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "unsupported-case-kind-rejects"
      unsupportedCaseKindInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "positive-case-with-error-rejects"
      positiveCaseWithErrorInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "negative-case-without-error-rejects"
      negativeCaseWithoutErrorInput ++ ",\n"
    ++ nativeBackendReviewPolicyCaseJson "missing-required-case-rejects"
      missingRequiredCaseInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
