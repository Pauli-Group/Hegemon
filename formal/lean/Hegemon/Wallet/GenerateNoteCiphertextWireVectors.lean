import Hegemon.Wallet.NoteCiphertextWire

open Hegemon
open Hegemon.Wallet.NoteCiphertextWire

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

def bytesFieldJson (bytes : Option (List Byte)) : String :=
  match bytes with
  | none => "null"
  | some value => "\"" ++ hexBytes value ++ "\""

def natFieldJson (value : Option Nat) : String :=
  match value with
  | none => "null"
  | some count => toString count

def noteCiphertextCaseJson
    (name format : String)
    (wire : List Byte)
    (summary : Option NoteCiphertextSummary) : String :=
  let projectedDaBytes :=
    if format = "chain" then
      projectChainDaBytes wire
    else
      none;
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"format\": \"" ++ format ++ "\",\n"
    ++ "      \"wire_hex\": \"" ++ hexBytes wire ++ "\",\n"
    ++ "      \"expected_wire_len\": " ++ toString wire.length ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson summary.isSome ++ ",\n"
    ++ "      \"expected_summary\": " ++ summaryFieldJson summary ++ ",\n"
    ++ "      \"expected_da_hex\": " ++ bytesFieldJson projectedDaBytes ++ ",\n"
    ++ "      \"expected_da_len\": " ++ natFieldJson (projectedDaBytes.map List.length) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"note_ciphertext_wire_cases\": [\n"
    ++ noteCiphertextCaseJson "crypto-valid" "crypto" validCryptoWire
      (parseCryptoNoteCiphertext validCryptoWire) ++ ",\n"
    ++ noteCiphertextCaseJson "crypto-truncated-after-kem-rejected" "crypto" cryptoTruncatedWire
      (parseCryptoNoteCiphertext cryptoTruncatedWire) ++ ",\n"
    ++ noteCiphertextCaseJson "crypto-trailing-byte-rejected" "crypto" cryptoTrailingWire
      (parseCryptoNoteCiphertext cryptoTrailingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-valid" "chain" validChainWire
      (parseChainNoteCiphertext validChainWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-memo-overrun-rejected" "chain" chainMemoOverrunWire
      (parseChainNoteCiphertext chainMemoOverrunWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-nonzero-padding-rejected" "chain" chainNonzeroPaddingWire
      (parseChainNoteCiphertext chainNonzeroPaddingWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-noncanonical-compact-kem-length-rejected" "chain" chainNoncanonicalCompactWire
      (parseChainNoteCiphertext chainNoncanonicalCompactWire) ++ ",\n"
    ++ noteCiphertextCaseJson "chain-trailing-byte-rejected" "chain" chainTrailingWire
      (parseChainNoteCiphertext chainTrailingWire) ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
