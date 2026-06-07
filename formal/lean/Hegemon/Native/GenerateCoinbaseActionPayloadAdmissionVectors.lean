import Hegemon.Native.CoinbaseActionPayloadAdmission

open Hegemon.Native.CoinbaseActionPayloadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CoinbasePayloadReject -> String
  | none => "null"
  | some CoinbasePayloadReject.amountZero => "\"amount_zero\""
  | some CoinbasePayloadReject.commitmentMismatch => "\"commitment_mismatch\""
  | some CoinbasePayloadReject.commitmentZero => "\"commitment_zero\""
  | some CoinbasePayloadReject.ciphertextTooLarge => "\"ciphertext_too_large\""
  | some CoinbasePayloadReject.ciphertextHashMismatch =>
      "\"ciphertext_hash_mismatch\""
  | some CoinbasePayloadReject.ciphertextSizeMismatch =>
      "\"ciphertext_size_mismatch\""

def coinbasePayloadCaseJson (name : String) (input : CoinbasePayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"amount_nonzero\": " ++ boolJson input.amountNonzero ++ ",\n"
    ++ "      \"commitment_matches\": " ++ boolJson input.commitmentMatches ++ ",\n"
    ++ "      \"commitment_nonzero\": " ++ boolJson input.commitmentNonzero ++ ",\n"
    ++ "      \"ciphertext_bytes\": " ++ toString input.ciphertextBytes ++ ",\n"
    ++ "      \"max_ciphertext_bytes\": " ++ toString input.maxCiphertextBytes ++ ",\n"
    ++ "      \"ciphertext_hash_matches\": "
      ++ boolJson input.ciphertextHashMatches ++ ",\n"
    ++ "      \"ciphertext_size_matches\": "
      ++ boolJson input.ciphertextSizeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (coinbasePayloadAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (coinbasePayloadRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"coinbase_action_payload_admission_cases\": [\n"
    ++ coinbasePayloadCaseJson "valid-coinbase-payload"
      validCoinbasePayload ++ ",\n"
    ++ coinbasePayloadCaseJson "exact-ciphertext-limit-accepts"
      { validCoinbasePayload with
        ciphertextBytes := validCoinbasePayload.maxCiphertextBytes } ++ ",\n"
    ++ coinbasePayloadCaseJson "amount-zero-rejected"
      { validCoinbasePayload with amountNonzero := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "commitment-mismatch-rejected"
      { validCoinbasePayload with commitmentMatches := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "commitment-zero-rejected"
      { validCoinbasePayload with commitmentNonzero := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "ciphertext-too-large-rejected"
      { validCoinbasePayload with
        ciphertextBytes := validCoinbasePayload.maxCiphertextBytes + 1 } ++ ",\n"
    ++ coinbasePayloadCaseJson "ciphertext-hash-mismatch-rejected"
      { validCoinbasePayload with ciphertextHashMatches := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "ciphertext-size-mismatch-rejected"
      { validCoinbasePayload with ciphertextSizeMatches := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "amount-precedes-commitment-mismatch"
      { validCoinbasePayload with
        amountNonzero := false,
        commitmentMatches := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "commitment-mismatch-precedes-zero"
      { validCoinbasePayload with
        commitmentMatches := false,
        commitmentNonzero := false } ++ ",\n"
    ++ coinbasePayloadCaseJson "ciphertext-too-large-precedes-hash"
      { validCoinbasePayload with
        ciphertextBytes := validCoinbasePayload.maxCiphertextBytes + 1,
        ciphertextHashMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
