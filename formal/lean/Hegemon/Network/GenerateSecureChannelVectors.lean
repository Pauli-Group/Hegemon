import Hegemon.Network.SecureChannel

open Hegemon
open Hegemon.Network.SecureChannel

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

def keyScheduleCaseJson (name : String) (input : KeyScheduleInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"offer_hex\": \"" ++ hexBytes input.offer ++ "\",\n"
    ++ "      \"acceptance_hex\": \"" ++ hexBytes input.acceptance ++ "\",\n"
    ++ "      \"confirmation_hex\": \"" ++ hexBytes input.confirmation ++ "\",\n"
    ++ "      \"secret_a_hex\": \"" ++ hexBytes input.secretA ++ "\",\n"
    ++ "      \"secret_b_hex\": \"" ++ hexBytes input.secretB ++ "\",\n"
    ++ "      \"domain_hex\": \"" ++ hexBytes networkKdfDomain ++ "\",\n"
    ++ "      \"i2r_label_hex\": \"" ++ hexBytes initiatorToResponderLabel ++ "\",\n"
    ++ "      \"r2i_label_hex\": \"" ++ hexBytes responderToInitiatorLabel ++ "\",\n"
    ++ "      \"aad_label_hex\": \"" ++ hexBytes sessionAadLabel ++ "\",\n"
    ++ "      \"i2r_preimage_hex\": \""
      ++ hexBytes (initiatorToResponderPreimage input) ++ "\",\n"
    ++ "      \"r2i_preimage_hex\": \""
      ++ hexBytes (responderToInitiatorPreimage input) ++ "\",\n"
    ++ "      \"aad_preimage_hex\": \""
      ++ hexBytes (sessionAadPreimage input) ++ "\",\n"
    ++ "      \"expected_i2r_equals_r2i\": "
      ++ boolJson (initiatorToResponderPreimage input ==
        responderToInitiatorPreimage input) ++ ",\n"
    ++ "      \"expected_i2r_equals_aad\": "
      ++ boolJson (initiatorToResponderPreimage input ==
        sessionAadPreimage input) ++ "\n"
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

def alternateInput : KeyScheduleInput := {
  offer := patternedBytes 3 7,
  acceptance := patternedBytes 5 29,
  confirmation := patternedBytes 7 101,
  secretA := patternedBytes 32 203,
  secretB := patternedBytes 32 11
}

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"key_schedule_cases\": [\n"
    ++ keyScheduleCaseJson "patterned-handshake" sampleInput ++ ",\n"
    ++ keyScheduleCaseJson "alternate-handshake" alternateInput ++ "\n"
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
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
