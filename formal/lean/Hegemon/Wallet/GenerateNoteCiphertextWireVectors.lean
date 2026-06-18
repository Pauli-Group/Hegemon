import Hegemon.Wallet.NoteCiphertextDecrypt

open Hegemon
open Hegemon.Wallet.NoteCiphertextWire
open Hegemon.Wallet.NoteCiphertextDecrypt

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def summaryJson (summary : NoteCiphertextSummary) : String :=
  "{ \"version\": " ++ toString summary.version
    ++ ", \"crypto_suite\": " ++ toString summary.cryptoSuite
    ++ ", \"diversifier_index\": " ++ toString summary.diversifierIndex
    ++ ", \"kem_len\": " ++ toString summary.kemLen
    ++ ", \"note_payload_len\": " ++ toString summary.notePayloadLen
    ++ ", \"memo_payload_len\": " ++ toString summary.memoPayloadLen
    ++ " }"

def summaryFieldJson (summary : Option NoteCiphertextSummary) : String :=
  match summary with
  | none => "null"
  | some value => summaryJson value

def materialJson (material : DecryptMaterialSummary) : String :=
  "{ \"version\": " ++ toString material.version
    ++ ", \"crypto_suite\": " ++ toString material.cryptoSuite
    ++ ", \"diversifier_index\": " ++ toString material.diversifierIndex
    ++ " }"

def decryptRejectionJson : Option DecryptRejection -> String
  | none => "null"
  | some DecryptRejection.versionMismatch => "\"version_mismatch\""
  | some DecryptRejection.cryptoSuiteMismatch => "\"crypto_suite_mismatch\""
  | some DecryptRejection.diversifierMismatch => "\"diversifier_mismatch\""
  | some DecryptRejection.cryptoFailure => "\"crypto_failure\""

def bytesFieldJson (bytes : Option (List Byte)) : String :=
  match bytes with
  | none => "null"
  | some value => "\"" ++ hexBytes value ++ "\""

def natFieldJson (value : Option Nat) : String :=
  match value with
  | none => "null"
  | some count => toString count

def productionProfileJson : String :=
  "  \"production_profile\": {\n"
    ++ "    \"note_aead_label_hex\": \"" ++ hexBytes noteAeadPayloadLabel ++ "\",\n"
    ++ "    \"memo_aead_label_hex\": \"" ++ hexBytes memoAeadPayloadLabel ++ "\",\n"
    ++ "    \"aead_kdf_domain_hex\": \"" ++ hexBytes walletAeadKdfDomainTag ++ "\",\n"
    ++ "    \"kem_randomness_len\": " ++ toString noteCiphertextKemRandomnessLen ++ ",\n"
    ++ "    \"aead_key_len\": " ++ toString noteCiphertextAeadKeyLen ++ ",\n"
    ++ "    \"aead_nonce_len\": " ++ toString noteCiphertextAeadNonceLen ++ ",\n"
    ++ "    \"aead_tag_len\": " ++ toString noteCiphertextAeadTagLen ++ ",\n"
    ++ "    \"note_plaintext_payload_len\": "
      ++ toString noteCiphertextPlaintextPayloadLen ++ ",\n"
    ++ "    \"metadata_aad_len\": "
      ++ toString noteCiphertextMetadataAadLen ++ ",\n"
    ++ "    \"chain_ciphertext_size\": " ++ toString chainCiphertextSize ++ ",\n"
    ++ "    \"chain_compact_kem_len_hex\": \"" ++ hexBytes chainCompactKemLen ++ "\",\n"
    ++ "    \"ml_kem_ciphertext_len\": " ++ toString mlKemCiphertextLen ++ ",\n"
    ++ "    \"sample_metadata_aad_hex\": \""
      ++ hexBytes (productionAadBytes sampleCiphertextSummary) ++ "\"\n"
    ++ "  }"

def projectedDaBytesFor (format : String) (wire : List Byte) : Option (List Byte) :=
  if format = "chain" then
    projectChainDaBytes wire
  else
    none

def projectedDaSummaryFor (format : String) (wire : List Byte) :
    Option NoteCiphertextSummary :=
  match projectedDaBytesFor format wire with
  | none => none
  | some daBytes => parseDaNoteCiphertext daBytes

def noteCiphertextCaseJson
    (name format : String)
    (wire : List Byte)
    (summary : Option NoteCiphertextSummary) : String :=
  let projectedDaBytes := projectedDaBytesFor format wire;
  let projectedDaSummary := projectedDaSummaryFor format wire;
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"format\": \"" ++ format ++ "\",\n"
    ++ "      \"wire_hex\": \"" ++ hexBytes wire ++ "\",\n"
    ++ "      \"expected_wire_len\": " ++ toString wire.length ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson summary.isSome ++ ",\n"
    ++ "      \"expected_summary\": " ++ summaryFieldJson summary ++ ",\n"
    ++ "      \"expected_da_hex\": " ++ bytesFieldJson projectedDaBytes ++ ",\n"
    ++ "      \"expected_da_len\": " ++ natFieldJson (projectedDaBytes.map List.length) ++ ",\n"
    ++ "      \"expected_projected_da_valid\": "
      ++ boolJson projectedDaSummary.isSome ++ ",\n"
    ++ "      \"expected_projected_da_summary\": "
      ++ summaryFieldJson projectedDaSummary ++ "\n"
    ++ "    }"

def noteCiphertextDecryptCaseJson
    (name productionFixture : String)
    (attempt : DecryptAttempt) : String :=
  let result := evaluateDecrypt attempt;
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"production_fixture\": \"" ++ productionFixture ++ "\",\n"
    ++ "      \"ciphertext\": " ++ summaryJson attempt.ciphertext ++ ",\n"
    ++ "      \"material\": " ++ materialJson attempt.material ++ ",\n"
    ++ "      \"crypto_authenticates\": "
      ++ boolJson attempt.cryptoAuthenticates ++ ",\n"
    ++ "      \"expected_accept\": " ++ boolJson (! result.isSome) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ decryptRejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 7,\n"
    ++ productionProfileJson ++ ",\n"
    ++ "  \"note_ciphertext_wire_cases\": [\n"
    ++ noteCiphertextCaseJson "crypto-valid" "crypto" validCryptoWire
      (parseCryptoNoteCiphertext validCryptoWire) ++ ",\n"
    ++ noteCiphertextCaseJson "crypto-truncated-after-kem-rejected" "crypto" cryptoTruncatedWire
      (parseCryptoNoteCiphertext cryptoTruncatedWire) ++ ",\n"
    ++ noteCiphertextCaseJson "crypto-trailing-byte-rejected" "crypto" cryptoTrailingWire
      (parseCryptoNoteCiphertext cryptoTrailingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-valid" "chain" validChainWire
      (parseChainNoteCiphertext validChainWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-alternate-valid-same-summary-different-wire" "chain"
      alternateValidChainWire (parseChainNoteCiphertext alternateValidChainWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-memo-overrun-rejected" "chain" chainMemoOverrunWire
      (parseChainNoteCiphertext chainMemoOverrunWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-nonzero-padding-rejected" "chain" chainNonzeroPaddingWire
      (parseChainNoteCiphertext chainNonzeroPaddingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-wrong-version-rejected" "chain" chainWrongVersionWire
      (parseChainNoteCiphertext chainWrongVersionWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-noncanonical-compact-kem-length-rejected" "chain" chainNoncanonicalCompactWire
      (parseChainNoteCiphertext chainNoncanonicalCompactWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-trailing-byte-rejected" "chain" chainTrailingWire
      (parseChainNoteCiphertext chainTrailingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "da-valid" "da" validChainDaBytes
      (parseDaNoteCiphertext validChainDaBytes) ++ ",\n"
    ++ noteCiphertextCaseJson "da-memo-overrun-rejected" "da" daMemoOverrunWire
      (parseDaNoteCiphertext daMemoOverrunWire) ++ ",\n"
    ++ noteCiphertextCaseJson "da-nonzero-padding-rejected" "da" daNonzeroPaddingWire
      (parseDaNoteCiphertext daNonzeroPaddingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "da-wrong-version-rejected" "da" daWrongVersionWire
      (parseDaNoteCiphertext daWrongVersionWire) ++ ",\n"
    ++ noteCiphertextCaseJson "da-truncated-kem-rejected" "da" daTruncatedWire
      (parseDaNoteCiphertext daTruncatedWire) ++ ",\n"
    ++ noteCiphertextCaseJson "da-trailing-byte-rejected" "da" daTrailingWire
      (parseDaNoteCiphertext daTrailingWire) ++ "\n"
    ++ "  ],\n"
    ++ "  \"note_ciphertext_decrypt_cases\": [\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-valid" "valid"
      sampleAcceptedAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-wrong-version-rejected" "wrong-version"
      sampleWrongVersionAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-wrong-crypto-suite-rejected"
      "wrong-crypto-suite" sampleWrongSuiteAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-wrong-diversifier-rejected"
      "wrong-diversifier" sampleWrongDiversifierAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-wrong-recipient-rejected"
      "wrong-recipient" sampleCryptoFailureAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-malleated-kem-rejected"
      "malleated-kem" sampleCryptoFailureAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-malleated-note-payload-rejected"
      "malleated-note-payload" sampleCryptoFailureAttempt ++ ",\n"
    ++ noteCiphertextDecryptCaseJson "decrypt-malleated-memo-payload-rejected"
      "malleated-memo-payload" sampleCryptoFailureAttempt ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
