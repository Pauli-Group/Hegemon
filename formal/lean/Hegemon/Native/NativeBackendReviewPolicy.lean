namespace Hegemon
namespace Native
namespace NativeBackendReviewPolicy

inductive ReviewCaseKind where
  | nativeTxLeaf
  | receiptRoot
  | unsupported
deriving DecidableEq, Repr

inductive NativeBackendReviewReject where
  | unsupportedReviewPosture
  | insufficientSecurityClaim
  | duplicateCaseName
  | unsupportedCaseKind
  | invalidCaseExpectation
  | missingRequiredCase
deriving DecidableEq, Repr

structure ReviewCase where
  name : String
  kind : ReviewCaseKind
  expectedValid : Bool
  hasExpectedError : Bool
deriving DecidableEq, Repr

structure NativeBackendReviewInput where
  reviewStateCandidateUnderReview : Bool
  maturityStructuralCandidate : Bool
  claimedSecurityBits : Nat
  soundnessFloorBits : Nat
  commitmentBindingBits : Nat
  compositionLossBits : Nat
  cases : List ReviewCase
deriving DecidableEq, Repr

structure RequiredReviewCase where
  name : String
  kind : ReviewCaseKind
  expectedValid : Bool
  requiresExpectedError : Bool
deriving DecidableEq, Repr

def reviewPostureValid (input : NativeBackendReviewInput) : Bool :=
  input.reviewStateCandidateUnderReview && input.maturityStructuralCandidate

def securityClaimMeetsPolicy (input : NativeBackendReviewInput) : Bool :=
  128 <= input.claimedSecurityBits
    && input.claimedSecurityBits <= input.soundnessFloorBits
    && input.claimedSecurityBits <= input.commitmentBindingBits
    && input.claimedSecurityBits + input.compositionLossBits <=
      input.soundnessFloorBits
    && input.compositionLossBits <= input.soundnessFloorBits

def caseKindSupported : ReviewCaseKind -> Bool
  | ReviewCaseKind.nativeTxLeaf => true
  | ReviewCaseKind.receiptRoot => true
  | ReviewCaseKind.unsupported => false

def caseExpectationValid (case : ReviewCase) : Bool :=
  if case.expectedValid then
    case.hasExpectedError = false
  else
    case.hasExpectedError = true

def caseNamesDistinctFrom (seen : List String) : List ReviewCase -> Bool
  | [] => true
  | case :: rest =>
      if seen.contains case.name then
        false
      else
        caseNamesDistinctFrom (case.name :: seen) rest

def caseNamesDistinct (cases : List ReviewCase) : Bool :=
  caseNamesDistinctFrom [] cases

def requiredNativeTxLeafValid : RequiredReviewCase :=
  {
    name := "native_tx_leaf_valid",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := true,
    requiresExpectedError := false
  }

def requiredNativeTxLeafInvalidSpecDigest : RequiredReviewCase :=
  {
    name := "native_tx_leaf_invalid_spec_digest",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredNativeTxLeafInvalidParamsFingerprint : RequiredReviewCase :=
  {
    name := "native_tx_leaf_invalid_params_fingerprint",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredNativeTxLeafInvalidStarkProof : RequiredReviewCase :=
  {
    name := "native_tx_leaf_invalid_stark_proof",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredNativeTxLeafInvalidProofDigest : RequiredReviewCase :=
  {
    name := "native_tx_leaf_invalid_proof_digest",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredNativeTxLeafInvalidTrailingBytes : RequiredReviewCase :=
  {
    name := "native_tx_leaf_invalid_trailing_bytes",
    kind := ReviewCaseKind.nativeTxLeaf,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredReceiptRootValid : RequiredReviewCase :=
  {
    name := "receipt_root_valid",
    kind := ReviewCaseKind.receiptRoot,
    expectedValid := true,
    requiresExpectedError := false
  }

def requiredReceiptRootInvalidSpecDigest : RequiredReviewCase :=
  {
    name := "receipt_root_invalid_spec_digest",
    kind := ReviewCaseKind.receiptRoot,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredReceiptRootInvalidFoldRows : RequiredReviewCase :=
  {
    name := "receipt_root_invalid_fold_rows",
    kind := ReviewCaseKind.receiptRoot,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredReceiptRootInvalidRootCommitment : RequiredReviewCase :=
  {
    name := "receipt_root_invalid_root_commitment",
    kind := ReviewCaseKind.receiptRoot,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredReceiptRootInvalidTrailingBytes : RequiredReviewCase :=
  {
    name := "receipt_root_invalid_trailing_bytes",
    kind := ReviewCaseKind.receiptRoot,
    expectedValid := false,
    requiresExpectedError := true
  }

def requiredReviewCases : List RequiredReviewCase :=
  [
    requiredNativeTxLeafValid,
    requiredNativeTxLeafInvalidSpecDigest,
    requiredNativeTxLeafInvalidParamsFingerprint,
    requiredNativeTxLeafInvalidStarkProof,
    requiredNativeTxLeafInvalidProofDigest,
    requiredNativeTxLeafInvalidTrailingBytes,
    requiredReceiptRootValid,
    requiredReceiptRootInvalidSpecDigest,
    requiredReceiptRootInvalidFoldRows,
    requiredReceiptRootInvalidRootCommitment,
    requiredReceiptRootInvalidTrailingBytes
  ]

def caseMatchesRequired (case : ReviewCase) (required : RequiredReviewCase) : Bool :=
  case.name == required.name
    && case.kind == required.kind
    && case.expectedValid == required.expectedValid
    && case.hasExpectedError == required.requiresExpectedError

def requiredCaseCovered
    (cases : List ReviewCase)
    (required : RequiredReviewCase) : Bool :=
  cases.any (fun case => caseMatchesRequired case required)

def requiredCaseCoverage (input : NativeBackendReviewInput) : Bool :=
  requiredReviewCases.all (requiredCaseCovered input.cases)

def nativeBackendReviewPreconditions
    (input : NativeBackendReviewInput) : Bool :=
  reviewPostureValid input
    && securityClaimMeetsPolicy input
    && caseNamesDistinct input.cases
    && input.cases.all (fun case => caseKindSupported case.kind)
    && input.cases.all caseExpectationValid
    && requiredCaseCoverage input

def evaluateNativeBackendReview
    (input : NativeBackendReviewInput) :
    Except NativeBackendReviewReject Unit :=
  if reviewPostureValid input = false then
    Except.error NativeBackendReviewReject.unsupportedReviewPosture
  else if securityClaimMeetsPolicy input = false then
    Except.error NativeBackendReviewReject.insufficientSecurityClaim
  else if caseNamesDistinct input.cases = false then
    Except.error NativeBackendReviewReject.duplicateCaseName
  else if input.cases.all (fun case => caseKindSupported case.kind) = false then
    Except.error NativeBackendReviewReject.unsupportedCaseKind
  else if input.cases.all caseExpectationValid = false then
    Except.error NativeBackendReviewReject.invalidCaseExpectation
  else if requiredCaseCoverage input = false then
    Except.error NativeBackendReviewReject.missingRequiredCase
  else
    Except.ok ()

def nativeBackendReviewAccepts (input : NativeBackendReviewInput) : Bool :=
  match evaluateNativeBackendReview input with
  | Except.ok _ => true
  | Except.error _ => false

def nativeBackendReviewRejection
    (input : NativeBackendReviewInput) : Option NativeBackendReviewReject :=
  match evaluateNativeBackendReview input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

theorem accepts_iff_native_backend_review_preconditions
    (input : NativeBackendReviewInput) :
    nativeBackendReviewAccepts input =
      nativeBackendReviewPreconditions input := by
  unfold nativeBackendReviewAccepts
    nativeBackendReviewPreconditions evaluateNativeBackendReview
  cases hPosture : reviewPostureValid input <;>
    cases hSecurity : securityClaimMeetsPolicy input <;>
    cases hDistinct : caseNamesDistinct input.cases <;>
    cases hSupported :
      input.cases.all (fun case => caseKindSupported case.kind) <;>
    cases hExpectations : input.cases.all caseExpectationValid <;>
    cases hCoverage : requiredCaseCoverage input <;>
    simp_all

def requiredCaseToReviewCase (required : RequiredReviewCase) : ReviewCase :=
  {
    name := required.name,
    kind := required.kind,
    expectedValid := required.expectedValid,
    hasExpectedError := required.requiresExpectedError
  }

def completeReviewCases : List ReviewCase :=
  requiredReviewCases.map requiredCaseToReviewCase

def completeReviewInput : NativeBackendReviewInput :=
  {
    reviewStateCandidateUnderReview := true,
    maturityStructuralCandidate := true,
    claimedSecurityBits := 128,
    soundnessFloorBits := 305,
    commitmentBindingBits := 872,
    compositionLossBits := 7,
    cases := completeReviewCases
  }

def wrongReviewPostureInput : NativeBackendReviewInput :=
  { completeReviewInput with reviewStateCandidateUnderReview := false }

def insufficientSecurityFloorInput : NativeBackendReviewInput :=
  { completeReviewInput with soundnessFloorBits := 127 }

def excessiveCompositionLossInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    soundnessFloorBits := 128,
    commitmentBindingBits := 128,
    compositionLossBits := 128
  }

def duplicateCaseNameInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    cases := requiredCaseToReviewCase requiredNativeTxLeafValid
      :: requiredCaseToReviewCase requiredNativeTxLeafValid
      :: completeReviewCases
  }

def unsupportedCaseKindInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    cases := {
      name := "unsupported_kind_case",
      kind := ReviewCaseKind.unsupported,
      expectedValid := false,
      hasExpectedError := true
    } :: completeReviewCases
  }

def positiveCaseWithErrorInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    cases := {
      name := "positive_case_with_error",
      kind := ReviewCaseKind.nativeTxLeaf,
      expectedValid := true,
      hasExpectedError := true
    } :: completeReviewCases
  }

def negativeCaseWithoutErrorInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    cases := {
      name := "negative_case_without_error",
      kind := ReviewCaseKind.nativeTxLeaf,
      expectedValid := false,
      hasExpectedError := false
    } :: completeReviewCases
  }

def missingRequiredCaseInput : NativeBackendReviewInput :=
  {
    completeReviewInput with
    cases := completeReviewCases.filter
      (fun case => case.name != requiredReceiptRootInvalidTrailingBytes.name)
  }

theorem complete_review_bundle_accepts :
    evaluateNativeBackendReview completeReviewInput = Except.ok () := by
  rfl

theorem wrong_review_posture_rejects :
    evaluateNativeBackendReview wrongReviewPostureInput =
      Except.error NativeBackendReviewReject.unsupportedReviewPosture := by
  rfl

theorem insufficient_security_floor_rejects :
    evaluateNativeBackendReview insufficientSecurityFloorInput =
      Except.error NativeBackendReviewReject.insufficientSecurityClaim := by
  rfl

theorem excessive_composition_loss_rejects :
    evaluateNativeBackendReview excessiveCompositionLossInput =
      Except.error NativeBackendReviewReject.insufficientSecurityClaim := by
  rfl

theorem duplicate_case_name_rejects :
    evaluateNativeBackendReview duplicateCaseNameInput =
      Except.error NativeBackendReviewReject.duplicateCaseName := by
  rfl

theorem unsupported_case_kind_rejects :
    evaluateNativeBackendReview unsupportedCaseKindInput =
      Except.error NativeBackendReviewReject.unsupportedCaseKind := by
  rfl

theorem positive_case_with_error_rejects :
    evaluateNativeBackendReview positiveCaseWithErrorInput =
      Except.error NativeBackendReviewReject.invalidCaseExpectation := by
  rfl

theorem negative_case_without_error_rejects :
    evaluateNativeBackendReview negativeCaseWithoutErrorInput =
      Except.error NativeBackendReviewReject.invalidCaseExpectation := by
  rfl

theorem missing_required_case_rejects :
    evaluateNativeBackendReview missingRequiredCaseInput =
      Except.error NativeBackendReviewReject.missingRequiredCase := by
  rfl

end NativeBackendReviewPolicy
end Native
end Hegemon
