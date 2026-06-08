import Hegemon.Network.PqNoise

open Hegemon
open Hegemon.Network.PqNoise

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullableNatStringJson (value : Option Nat) : String :=
  match value with
  | none => "null"
  | some raw => "\"" ++ toString raw ++ "\""

def roleJson : Role -> String
  | Role.initiator => "\"initiator\""
  | Role.responder => "\"responder\""

def keySlotName : KeySlot -> String
  | KeySlot.initiatorToResponder => "initiator_to_responder"
  | KeySlot.responderToInitiator => "responder_to_initiator"

def keySlotJson (slot : KeySlot) : String :=
  "\"" ++ keySlotName slot ++ "\""

def sessionKeyCaseJson (name : String) (input : SessionKeyInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"transcript_hash_hex\": \"" ++ hexBytes input.transcriptHash ++ "\",\n"
    ++ "      \"shared_1_hex\": \"" ++ hexBytes input.shared1 ++ "\",\n"
    ++ "      \"shared_2_hex\": \"" ++ hexBytes input.shared2 ++ "\",\n"
    ++ "      \"expected_salt_hex\": \"" ++ hexBytes (hkdfSalt input) ++ "\",\n"
    ++ "      \"expected_ikm_hex\": \"" ++ hexBytes (hkdfIkm input) ++ "\",\n"
    ++ "      \"i2r_info_hex\": \"" ++ hexBytes initiatorToResponderInfo ++ "\",\n"
    ++ "      \"r2i_info_hex\": \"" ++ hexBytes responderToInitiatorInfo ++ "\",\n"
    ++ "      \"aad_info_hex\": \"" ++ hexBytes sessionAadInfo ++ "\",\n"
    ++ "      \"expected_i2r_equals_r2i_info\": "
      ++ boolJson (initiatorToResponderInfo == responderToInitiatorInfo) ++ ",\n"
    ++ "      \"expected_i2r_equals_aad_info\": "
      ++ boolJson (initiatorToResponderInfo == sessionAadInfo) ++ "\n"
    ++ "    }"

def roleCaseJson (role : Role) : String :=
  "    {\n"
    ++ "      \"role\": " ++ roleJson role ++ ",\n"
    ++ "      \"expected_send_slot\": " ++ keySlotJson (sendSlot role) ++ ",\n"
    ++ "      \"expected_recv_slot\": " ++ keySlotJson (recvSlot role) ++ ",\n"
    ++ "      \"expected_send_recv_distinct\": "
      ++ boolJson (sendSlot role != recvSlot role) ++ "\n"
    ++ "    }"

def nonceCaseJson (name : String) (counter : Nat) : String :=
  let next := nextCounter counter
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"counter\": \"" ++ toString counter ++ "\",\n"
    ++ "      \"expected_nonce_hex\": \"" ++ hexBytes (nonceFromCounter counter) ++ "\",\n"
    ++ "      \"expected_valid\": " ++ boolJson (next != none) ++ ",\n"
    ++ "      \"expected_next_counter\": " ++ nullableNatStringJson next ++ "\n"
    ++ "    }"

def initSigningCaseJson (name : String) (input : InitHelloSigningInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version\": " ++ toString input.version ++ ",\n"
    ++ "      \"mlkem_public_key_hex\": \"" ++ hexBytes input.mlkemPublicKey ++ "\",\n"
    ++ "      \"identity_key_hex\": \"" ++ hexBytes input.identityKey ++ "\",\n"
    ++ "      \"nonce\": \"" ++ toString input.nonce ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \""
      ++ hexBytes (initHelloSigningPreimage input) ++ "\"\n"
    ++ "    }"

def respSigningCaseJson (name : String) (input : RespHelloSigningInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"version\": " ++ toString input.version ++ ",\n"
    ++ "      \"mlkem_public_key_hex\": \"" ++ hexBytes input.mlkemPublicKey ++ "\",\n"
    ++ "      \"mlkem_ciphertext_hex\": \"" ++ hexBytes input.mlkemCiphertext ++ "\",\n"
    ++ "      \"identity_key_hex\": \"" ++ hexBytes input.identityKey ++ "\",\n"
    ++ "      \"nonce\": \"" ++ toString input.nonce ++ "\",\n"
    ++ "      \"transcript_hash_hex\": \"" ++ hexBytes input.transcriptHash ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \""
      ++ hexBytes (respHelloSigningPreimage input) ++ "\"\n"
    ++ "    }"

def finishSigningCaseJson (name : String) (input : FinishSigningInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"mlkem_ciphertext_hex\": \"" ++ hexBytes input.mlkemCiphertext ++ "\",\n"
    ++ "      \"nonce\": \"" ++ toString input.nonce ++ "\",\n"
    ++ "      \"transcript_hash_hex\": \"" ++ hexBytes input.transcriptHash ++ "\",\n"
    ++ "      \"expected_preimage_hex\": \""
      ++ hexBytes (finishSigningPreimage input) ++ "\"\n"
    ++ "    }"

def alternateSessionInput : SessionKeyInput := {
  transcriptHash := patternedBytes 32 211,
  shared1 := patternedBytes 32 5,
  shared2 := patternedBytes 32 97
}

def alternateInitSigningInput : InitHelloSigningInput := {
  version := 1,
  mlkemPublicKey := patternedBytes 3 7,
  identityKey := patternedBytes 5 31,
  nonce := 1
}

def alternateRespSigningInput : RespHelloSigningInput := {
  version := 1,
  mlkemPublicKey := patternedBytes 7 43,
  mlkemCiphertext := patternedBytes 9 71,
  identityKey := patternedBytes 5 113,
  nonce := 0,
  transcriptHash := patternedBytes 32 149
}

def alternateFinishSigningInput : FinishSigningInput := {
  mlkemCiphertext := patternedBytes 9 191,
  nonce := u64Max,
  transcriptHash := patternedBytes 32 229
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"session_key_cases\": [\n"
    ++ sessionKeyCaseJson "patterned-session" sampleSessionInput ++ ",\n"
    ++ sessionKeyCaseJson "alternate-session" alternateSessionInput ++ "\n"
    ++ "  ],\n"
    ++ "  \"role_cases\": [\n"
    ++ roleCaseJson Role.initiator ++ ",\n"
    ++ roleCaseJson Role.responder ++ "\n"
    ++ "  ],\n"
    ++ "  \"nonce_cases\": [\n"
    ++ nonceCaseJson "zero" 0 ++ ",\n"
    ++ nonceCaseJson "one" 1 ++ ",\n"
    ++ nonceCaseJson "pattern" 72623859790382856 ++ ",\n"
    ++ nonceCaseJson "max-minus-one" (u64Max - 1) ++ ",\n"
    ++ nonceCaseJson "max-rejected" u64Max ++ "\n"
    ++ "  ],\n"
    ++ "  \"init_signing_cases\": [\n"
    ++ initSigningCaseJson "patterned-init" sampleInitSigningInput ++ ",\n"
    ++ initSigningCaseJson "alternate-init" alternateInitSigningInput ++ "\n"
    ++ "  ],\n"
    ++ "  \"resp_signing_cases\": [\n"
    ++ respSigningCaseJson "patterned-resp" sampleRespSigningInput ++ ",\n"
    ++ respSigningCaseJson "alternate-resp" alternateRespSigningInput ++ "\n"
    ++ "  ],\n"
    ++ "  \"finish_signing_cases\": [\n"
    ++ finishSigningCaseJson "patterned-finish" sampleFinishSigningInput ++ ",\n"
    ++ finishSigningCaseJson "alternate-finish" alternateFinishSigningInput ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
