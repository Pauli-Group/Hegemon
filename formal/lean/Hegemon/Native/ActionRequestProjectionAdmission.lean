namespace Hegemon
namespace Native
namespace ActionRequestProjectionAdmission

inductive ActionRequestProjectionReject where
  | jsonDecodeRejected
  | kernelEnvelopeFieldsPresent
  | unsupportedRoute
  | nonTransferNullifiers
  | tooManyNullifiers
  | invalidNullifierHex
  | publicArgsTooLarge
  | publicArgsBase64Rejected
  | decodedPublicArgsTooLarge
  | routePayloadDecodeNotExact
deriving DecidableEq, Repr

structure ActionRequestProjectionInput where
  jsonDecodeAccepts : Bool
  kernelEnvelopeFieldsAbsent : Bool
  routeSupported : Bool
  nullifierScopeValid : Bool
  nullifierCountWithinLimit : Bool
  nullifierHexValid : Bool
  publicArgsEncodedWithinLimit : Bool
  publicArgsBase64Decodes : Bool
  publicArgsDecodedWithinLimit : Bool
  routePayloadDecodesExactly : Bool
deriving DecidableEq, Repr

def evaluateActionRequestProjectionRejection
    (input : ActionRequestProjectionInput) :
    Option ActionRequestProjectionReject :=
  if input.jsonDecodeAccepts = false then
    some ActionRequestProjectionReject.jsonDecodeRejected
  else if input.kernelEnvelopeFieldsAbsent = false then
    some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent
  else if input.routeSupported = false then
    some ActionRequestProjectionReject.unsupportedRoute
  else if input.nullifierScopeValid = false then
    some ActionRequestProjectionReject.nonTransferNullifiers
  else if input.nullifierCountWithinLimit = false then
    some ActionRequestProjectionReject.tooManyNullifiers
  else if input.nullifierHexValid = false then
    some ActionRequestProjectionReject.invalidNullifierHex
  else if input.publicArgsEncodedWithinLimit = false then
    some ActionRequestProjectionReject.publicArgsTooLarge
  else if input.publicArgsBase64Decodes = false then
    some ActionRequestProjectionReject.publicArgsBase64Rejected
  else if input.publicArgsDecodedWithinLimit = false then
    some ActionRequestProjectionReject.decodedPublicArgsTooLarge
  else if input.routePayloadDecodesExactly = false then
    some ActionRequestProjectionReject.routePayloadDecodeNotExact
  else
    none

def actionRequestProjectionAccepts
    (input : ActionRequestProjectionInput) : Bool :=
  evaluateActionRequestProjectionRejection input = none

def actionRequestProjectionPreconditions
    (input : ActionRequestProjectionInput) : Bool :=
  input.jsonDecodeAccepts
    && input.kernelEnvelopeFieldsAbsent
    && input.routeSupported
    && input.nullifierScopeValid
    && input.nullifierCountWithinLimit
    && input.nullifierHexValid
    && input.publicArgsEncodedWithinLimit
    && input.publicArgsBase64Decodes
    && input.publicArgsDecodedWithinLimit
    && input.routePayloadDecodesExactly

theorem accepts_iff_action_request_projection_preconditions
    {input : ActionRequestProjectionInput} :
    actionRequestProjectionAccepts input = true ↔
      actionRequestProjectionPreconditions input = true := by
  cases input with
  | mk jsonDecodeAccepts kernelEnvelopeFieldsAbsent routeSupported
      nullifierScopeValid nullifierCountWithinLimit nullifierHexValid
      publicArgsEncodedWithinLimit publicArgsBase64Decodes
      publicArgsDecodedWithinLimit routePayloadDecodesExactly =>
      cases jsonDecodeAccepts <;>
        cases kernelEnvelopeFieldsAbsent <;>
        cases routeSupported <;>
        cases nullifierScopeValid <;>
        cases nullifierCountWithinLimit <;>
        cases nullifierHexValid <;>
        cases publicArgsEncodedWithinLimit <;>
        cases publicArgsBase64Decodes <;>
        cases publicArgsDecodedWithinLimit <;>
        cases routePayloadDecodesExactly <;>
        simp [
          actionRequestProjectionAccepts,
          actionRequestProjectionPreconditions,
          evaluateActionRequestProjectionRejection
        ]

theorem rejects_json_decode_failure
    {input : ActionRequestProjectionInput}
    (jsonRejected : input.jsonDecodeAccepts = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.jsonDecodeRejected := by
  unfold evaluateActionRequestProjectionRejection
  simp [jsonRejected]

theorem rejects_kernel_envelope_fields
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsPresent : input.kernelEnvelopeFieldsAbsent = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent := by
  unfold evaluateActionRequestProjectionRejection
  simp [jsonAccepted, kernelFieldsPresent]

theorem rejects_unsupported_route
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (unsupportedRoute : input.routeSupported = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.unsupportedRoute := by
  unfold evaluateActionRequestProjectionRejection
  simp [jsonAccepted, kernelFieldsAbsent, unsupportedRoute]

theorem rejects_non_transfer_nullifiers
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (badScope : input.nullifierScopeValid = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.nonTransferNullifiers := by
  unfold evaluateActionRequestProjectionRejection
  simp [jsonAccepted, kernelFieldsAbsent, routeSupported, badScope]

theorem rejects_too_many_nullifiers
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (tooMany : input.nullifierCountWithinLimit = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.tooManyNullifiers := by
  unfold evaluateActionRequestProjectionRejection
  simp [jsonAccepted, kernelFieldsAbsent, routeSupported, scopeValid, tooMany]

theorem rejects_invalid_nullifier_hex
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (countValid : input.nullifierCountWithinLimit = true)
    (invalidHex : input.nullifierHexValid = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.invalidNullifierHex := by
  unfold evaluateActionRequestProjectionRejection
  simp [
    jsonAccepted,
    kernelFieldsAbsent,
    routeSupported,
    scopeValid,
    countValid,
    invalidHex
  ]

theorem rejects_encoded_public_args_too_large
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (countValid : input.nullifierCountWithinLimit = true)
    (hexValid : input.nullifierHexValid = true)
    (tooLarge : input.publicArgsEncodedWithinLimit = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.publicArgsTooLarge := by
  unfold evaluateActionRequestProjectionRejection
  simp [
    jsonAccepted,
    kernelFieldsAbsent,
    routeSupported,
    scopeValid,
    countValid,
    hexValid,
    tooLarge
  ]

theorem rejects_base64_failure
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (countValid : input.nullifierCountWithinLimit = true)
    (hexValid : input.nullifierHexValid = true)
    (encodedWithinLimit : input.publicArgsEncodedWithinLimit = true)
    (base64Rejected : input.publicArgsBase64Decodes = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.publicArgsBase64Rejected := by
  unfold evaluateActionRequestProjectionRejection
  simp [
    jsonAccepted,
    kernelFieldsAbsent,
    routeSupported,
    scopeValid,
    countValid,
    hexValid,
    encodedWithinLimit,
    base64Rejected
  ]

theorem rejects_decoded_public_args_too_large
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (countValid : input.nullifierCountWithinLimit = true)
    (hexValid : input.nullifierHexValid = true)
    (encodedWithinLimit : input.publicArgsEncodedWithinLimit = true)
    (base64Accepted : input.publicArgsBase64Decodes = true)
    (decodedTooLarge : input.publicArgsDecodedWithinLimit = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.decodedPublicArgsTooLarge := by
  unfold evaluateActionRequestProjectionRejection
  simp [
    jsonAccepted,
    kernelFieldsAbsent,
    routeSupported,
    scopeValid,
    countValid,
    hexValid,
    encodedWithinLimit,
    base64Accepted,
    decodedTooLarge
  ]

theorem rejects_nonexact_route_payload
    {input : ActionRequestProjectionInput}
    (jsonAccepted : input.jsonDecodeAccepts = true)
    (kernelFieldsAbsent : input.kernelEnvelopeFieldsAbsent = true)
    (routeSupported : input.routeSupported = true)
    (scopeValid : input.nullifierScopeValid = true)
    (countValid : input.nullifierCountWithinLimit = true)
    (hexValid : input.nullifierHexValid = true)
    (encodedWithinLimit : input.publicArgsEncodedWithinLimit = true)
    (base64Accepted : input.publicArgsBase64Decodes = true)
    (decodedWithinLimit : input.publicArgsDecodedWithinLimit = true)
    (nonExactPayload : input.routePayloadDecodesExactly = false) :
    evaluateActionRequestProjectionRejection input =
      some ActionRequestProjectionReject.routePayloadDecodeNotExact := by
  unfold evaluateActionRequestProjectionRejection
  simp [
    jsonAccepted,
    kernelFieldsAbsent,
    routeSupported,
    scopeValid,
    countValid,
    hexValid,
    encodedWithinLimit,
    base64Accepted,
    decodedWithinLimit,
    nonExactPayload
  ]

def validRequest : ActionRequestProjectionInput :=
  {
    jsonDecodeAccepts := true,
    kernelEnvelopeFieldsAbsent := true,
    routeSupported := true,
    nullifierScopeValid := true,
    nullifierCountWithinLimit := true,
    nullifierHexValid := true,
    publicArgsEncodedWithinLimit := true,
    publicArgsBase64Decodes := true,
    publicArgsDecodedWithinLimit := true,
    routePayloadDecodesExactly := true
  }

theorem valid_request_accepts :
    evaluateActionRequestProjectionRejection validRequest = none := by
  rfl

theorem kernel_fields_present_rejects :
    evaluateActionRequestProjectionRejection
      { validRequest with kernelEnvelopeFieldsAbsent := false } =
        some ActionRequestProjectionReject.kernelEnvelopeFieldsPresent := by
  rfl

theorem route_payload_decode_failure_rejects :
    evaluateActionRequestProjectionRejection
      { validRequest with routePayloadDecodesExactly := false } =
        some ActionRequestProjectionReject.routePayloadDecodeNotExact := by
  rfl

end ActionRequestProjectionAdmission
end Native
end Hegemon
