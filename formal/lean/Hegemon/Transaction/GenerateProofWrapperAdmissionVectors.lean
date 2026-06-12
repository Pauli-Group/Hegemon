import Hegemon.Transaction.ProofWrapperAdmission

open Hegemon.Transaction.ProofWrapperAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option ProofWrapperReject -> String
  | none => "null"
  | some ProofWrapperReject.nonExactConsumption => "\"non_exact_consumption\""
  | some ProofWrapperReject.nonCanonicalReencode => "\"non_canonical_reencode\""
  | some ProofWrapperReject.unsupportedBackend => "\"unsupported_backend\""
  | some ProofWrapperReject.missingProofBytes => "\"missing_proof_bytes\""
  | some ProofWrapperReject.missingSerializedPublicInputs =>
      "\"missing_serialized_public_inputs\""
  | some ProofWrapperReject.invalidPublicInputs => "\"invalid_public_inputs\""
  | some ProofWrapperReject.balanceSlotMismatch => "\"balance_slot_mismatch\""
  | some ProofWrapperReject.verifierRejected => "\"verifier_rejected\""

def caseJson (name : String) (input : ProofWrapperInput) : String :=
  let rejection := evaluateProofWrapperRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"exact_consumption\": " ++ boolJson input.exactConsumption ++ ",\n"
    ++ "      \"canonical_reencode\": " ++ boolJson input.canonicalReencode ++ ",\n"
    ++ "      \"backend_supported\": " ++ boolJson input.backendSupported ++ ",\n"
    ++ "      \"proof_bytes_present\": " ++ boolJson input.proofBytesPresent ++ ",\n"
    ++ "      \"serialized_public_inputs_present\": "
    ++ boolJson input.serializedPublicInputsPresent ++ ",\n"
    ++ "      \"public_inputs_valid\": " ++ boolJson input.publicInputsValid ++ ",\n"
    ++ "      \"balance_slots_agree\": " ++ boolJson input.balanceSlotsAgree ++ ",\n"
    ++ "      \"verifier_accepts\": " ++ boolJson input.verifierAccepts ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rejection.isNone) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"proof_wrapper_admission_cases\": [\n"
    ++ caseJson "valid-wrapper" validWrapper ++ ",\n"
    ++ caseJson "non-exact-consumption-rejected"
        { validWrapper with exactConsumption := false } ++ ",\n"
    ++ caseJson "non-canonical-reencode-rejected"
        { validWrapper with canonicalReencode := false } ++ ",\n"
    ++ caseJson "unsupported-backend-rejected"
        { validWrapper with backendSupported := false } ++ ",\n"
    ++ caseJson "missing-proof-bytes-rejected"
        { validWrapper with proofBytesPresent := false } ++ ",\n"
    ++ caseJson "missing-serialized-public-inputs-rejected"
        { validWrapper with serializedPublicInputsPresent := false } ++ ",\n"
    ++ caseJson "invalid-public-inputs-rejected"
        { validWrapper with publicInputsValid := false } ++ ",\n"
    ++ caseJson "balance-slot-mismatch-rejected"
        { validWrapper with balanceSlotsAgree := false } ++ ",\n"
    ++ caseJson "verifier-rejection-rejected"
        { validWrapper with verifierAccepts := false } ++ ",\n"
    ++ caseJson "codec-precedence-before-backend"
        { validWrapper with exactConsumption := false, backendSupported := false } ++ ",\n"
    ++ caseJson "public-input-precedence-before-balance"
        { validWrapper with publicInputsValid := false, balanceSlotsAgree := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
