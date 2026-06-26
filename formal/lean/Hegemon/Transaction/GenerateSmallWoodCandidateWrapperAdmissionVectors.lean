import Hegemon.Transaction.SmallWoodCandidateWrapperAdmission

open Hegemon.Transaction.SmallWoodCandidateWrapperAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def kindJson : Option WrapperKind -> String
  | none => "null"
  | some WrapperKind.current => "\"current\""
  | some WrapperKind.legacy => "\"legacy\""

def rejectJson : Option WrapperReject -> String
  | none => "null"
  | some WrapperReject.noCanonicalWrapper => "\"no_canonical_wrapper\""
  | some WrapperReject.auxiliaryWitnessWordsPresent =>
      "\"auxiliary_witness_words_present\""
  | some WrapperReject.missingArkProofBytes => "\"missing_ark_proof_bytes\""

def wrapperCaseJson
    (name fixture : String)
    (input : WrapperAdmissionInput) : String :=
  let rejection := evaluateWrapperRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"current_decode_ok\": " ++ boolJson input.current.decodeOk ++ ",\n"
    ++ "      \"current_exact_consumption\": "
    ++ boolJson input.current.exactConsumption ++ ",\n"
    ++ "      \"current_canonical_reencode\": "
    ++ boolJson input.current.canonicalReencode ++ ",\n"
    ++ "      \"current_ark_proof_bytes_present\": "
    ++ boolJson input.current.arkProofBytesPresent ++ ",\n"
    ++ "      \"current_auxiliary_witness_words_empty\": "
    ++ boolJson input.current.auxiliaryWitnessWordsEmpty ++ ",\n"
    ++ "      \"legacy_decode_ok\": " ++ boolJson input.legacy.decodeOk ++ ",\n"
    ++ "      \"legacy_exact_consumption\": "
    ++ boolJson input.legacy.exactConsumption ++ ",\n"
    ++ "      \"legacy_canonical_reencode\": "
    ++ boolJson input.legacy.canonicalReencode ++ ",\n"
    ++ "      \"legacy_ark_proof_bytes_present\": "
    ++ boolJson input.legacy.arkProofBytesPresent ++ ",\n"
    ++ "      \"legacy_auxiliary_witness_words_empty\": "
    ++ boolJson input.legacy.auxiliaryWitnessWordsEmpty ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson rejection.isNone ++ ",\n"
    ++ "      \"expected_kind\": " ++ kindJson (selectedWrapperKind input) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson rejection ++ "\n"
    ++ "    }"

def currentEmptyArk : WrapperAdmissionInput :=
  { validCurrentWrapper with
    current := { validCurrentWrapper.current with arkProofBytesPresent := false },
    legacy := validLegacyWrapper.legacy }

def currentAuxiliaryWitnessWordsPresent : WrapperAdmissionInput :=
  { validCurrentWrapper with
    current := { validCurrentWrapper.current with auxiliaryWitnessWordsEmpty := false },
    legacy := validLegacyWrapper.legacy }

def legacyEmptyArk : WrapperAdmissionInput :=
  { validLegacyWrapper with
    legacy := { validLegacyWrapper.legacy with arkProofBytesPresent := false } }

def malformedWrapper : WrapperAdmissionInput :=
  { current :=
      { decodeOk := false
        exactConsumption := false
        canonicalReencode := false
        arkProofBytesPresent := false
        auxiliaryWitnessWordsEmpty := true }
    legacy :=
      { decodeOk := false
        exactConsumption := false
        canonicalReencode := false
        arkProofBytesPresent := false
        auxiliaryWitnessWordsEmpty := true } }

def currentTrailingWrapper : WrapperAdmissionInput :=
  { malformedWrapper with
    current := { validCurrentWrapper.current with exactConsumption := false } }

def legacyTrailingWrapper : WrapperAdmissionInput :=
  { malformedWrapper with
    legacy := { validLegacyWrapper.legacy with exactConsumption := false } }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"smallwood_candidate_wrapper_admission_cases\": [\n"
    ++ wrapperCaseJson "valid-current-wrapper" "current_valid"
      validCurrentWrapper ++ ",\n"
    ++ wrapperCaseJson "current-empty-ark-rejected-before-legacy"
      "current_empty_ark"
      currentEmptyArk ++ ",\n"
    ++ wrapperCaseJson "current-auxiliary-witness-words-rejected" "current_nonempty"
      currentAuxiliaryWitnessWordsPresent ++ ",\n"
    ++ wrapperCaseJson "valid-legacy-wrapper" "legacy_nonempty"
      validLegacyWrapper ++ ",\n"
    ++ wrapperCaseJson "legacy-empty-ark-rejected"
      "legacy_empty_ark"
      legacyEmptyArk ++ ",\n"
    ++ wrapperCaseJson "malformed-wrapper-rejected"
      "malformed"
      malformedWrapper ++ ",\n"
    ++ wrapperCaseJson "current-trailing-bytes-rejected"
      "current_trailing"
      currentTrailingWrapper ++ ",\n"
    ++ wrapperCaseJson "legacy-trailing-bytes-rejected"
      "legacy_trailing"
      legacyTrailingWrapper ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
