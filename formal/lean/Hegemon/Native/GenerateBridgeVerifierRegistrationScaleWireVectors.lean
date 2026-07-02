import Hegemon.Bytes
import Hegemon.Native.BridgeVerifierRegistrationScaleWire

open Hegemon
open Hegemon.Native.BridgeVerifierRegistrationScaleWire

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectJson : Option BridgeVerifierRegistrationScaleWireReject -> String
  | none => "null"
  | some BridgeVerifierRegistrationScaleWireReject.parserRejected =>
      "\"parser_rejected\""
  | some BridgeVerifierRegistrationScaleWireReject.trailingBytes =>
      "\"trailing_bytes\""
  | some BridgeVerifierRegistrationScaleWireReject.nonCanonicalEncoding =>
      "\"non_canonical_encoding\""

def repeated (length value : Nat) : List Byte :=
  List.replicate length (byte value)

def bridgeVerifierRegistrationBytes
    (sourceChainIdValue verifierProgramHashValue rulesHashValue
      enabledAtHeight : Nat) : List Byte :=
  repeated 32 sourceChainIdValue
    ++ repeated 32 verifierProgramHashValue
    ++ repeated 32 rulesHashValue
    ++ u64le enabledAtHeight

def validRegistrationBytes : List Byte :=
  bridgeVerifierRegistrationBytes 1 2 3 42

def shortRegistrationBytes : List Byte :=
  (List.range (bridgeVerifierRegistrationEncodedLen - 1)).map (fun _ => 0)

def trailingRegistrationBytes : List Byte :=
  validRegistrationBytes ++ [0xff]

def caseJson
    (name fixture : String)
    (input : BridgeVerifierRegistrationScaleWireInput)
    (rawBytes : List Byte) : String :=
  let result := evaluateBridgeVerifierRegistrationScaleWireRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"raw_hex\": \"" ++ hexBytes rawBytes ++ "\",\n"
    ++ "      \"source_chain_id_bytes\": "
    ++ toString input.sourceChainIdBytes ++ ",\n"
    ++ "      \"verifier_program_hash_bytes\": "
    ++ toString input.verifierProgramHashBytes ++ ",\n"
    ++ "      \"rules_hash_bytes\": "
    ++ toString input.rulesHashBytes ++ ",\n"
    ++ "      \"enabled_at_height_bytes\": "
    ++ toString input.enabledAtHeightBytes ++ ",\n"
    ++ "      \"total_bytes\": " ++ toString input.totalBytes ++ ",\n"
    ++ "      \"consumed_all_bytes\": "
    ++ boolJson input.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": "
    ++ boolJson input.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_verifier_registration_scale_wire_cases\": [\n"
    ++ caseJson "valid-registration" "valid_registration"
      validRegistration validRegistrationBytes ++ ",\n"
    ++ caseJson "empty-bytes-rejected" "empty_bytes"
      { validRegistration with
        totalBytes := 0,
        canonicalReencodeMatches := false }
      [] ++ ",\n"
    ++ caseJson "short-registration-rejected"
      "short_registration"
      shortRegistration
      shortRegistrationBytes ++ ",\n"
    ++ caseJson "trailing-byte-rejected" "trailing_registration"
      trailingByteCase trailingRegistrationBytes ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
