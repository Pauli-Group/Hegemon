import Hegemon.Network.PqNoise
import Hegemon.Network.PqNoiseHandshakeChannel

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

def kemUseJson : KemEncapsulationUse -> String
  | KemEncapsulationUse.responderEncapsulatesToInitiator =>
      "\"responder_encapsulates_to_initiator\""
  | KemEncapsulationUse.initiatorEncapsulatesToResponder =>
      "\"initiator_encapsulates_to_responder\""

def kemSeedSourceJson : KemSeedSource -> String
  | KemSeedSource.osRng32 => "\"os_rng_32\""
  | KemSeedSource.publicTranscriptDerived => "\"public_transcript_derived\""
  | KemSeedSource.fixedDeterministic => "\"fixed_deterministic\""
  | KemSeedSource.callerProvidedTest => "\"caller_provided_test\""

def peerRole : Role -> Role
  | Role.initiator => Role.responder
  | Role.responder => Role.initiator

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

def kemRngSourceCaseJson
    (name : String)
    (facts : MlKemEncapsulationSeedFacts) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"use_kind\": " ++ kemUseJson facts.use ++ ",\n"
    ++ "      \"expected_source\": " ++ kemSeedSourceJson facts.source ++ ",\n"
    ++ "      \"expected_seed_byte_length\": \""
      ++ toString facts.seedByteLength ++ "\",\n"
    ++ "      \"expected_consumed_by_mlkem_encapsulate\": true,\n"
    ++ "      \"expected_public_transcript_derived\": "
      ++ boolJson (facts.source == KemSeedSource.publicTranscriptDerived) ++ "\n"
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

def frameCaseJson (role : Role) (frameIndex : Nat) : String :=
  let plaintext := patternedBytes (3 + frameIndex) (17 + frameIndex * 29)
  "        {\n"
    ++ "          \"frame_index\": \"" ++ toString frameIndex ++ "\",\n"
    ++ "          \"expected_protect_slot\": " ++ keySlotJson (sendSlot role) ++ ",\n"
    ++ "          \"expected_peer_open_slot\": "
      ++ keySlotJson (recvSlot (peerRole role)) ++ ",\n"
    ++ "          \"expected_nonce_hex\": \""
      ++ hexBytes (nonceFromCounter frameIndex) ++ "\",\n"
    ++ "          \"expected_protected_next_send_counter\": \""
      ++ toString (frameIndex + 1) ++ "\",\n"
    ++ "          \"expected_peer_next_recv_counter\": \""
      ++ toString (frameIndex + 1) ++ "\",\n"
    ++ "          \"expected_protected_slot_matches_peer_open\": "
      ++ boolJson (sendSlot role == recvSlot (peerRole role)) ++ ",\n"
    ++ "          \"expected_aad_distinct_from_key_info\": "
      ++ boolJson (sessionAadInfo != expandInfo (sendSlot role)) ++ ",\n"
    ++ "          \"plaintext_hex\": \""
      ++ hexBytes plaintext ++ "\"\n"
    ++ "        }"

def frameSequenceCaseJson (name : String) (role : Role) (sequenceLength : Nat) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"role\": " ++ roleJson role ++ ",\n"
    ++ "      \"peer_role\": " ++ roleJson (peerRole role) ++ ",\n"
    ++ "      \"sequence_length\": \"" ++ toString sequenceLength ++ "\",\n"
    ++ "      \"frames\": [\n"
    ++ String.intercalate ",\n" ((List.range sequenceLength).map (frameCaseJson role))
    ++ "\n"
    ++ "      ]\n"
    ++ "    }"

def transportCompletionCaseJson
    (name : String)
    (localRole : Role)
    (plaintextLen seed : Nat) : String :=
  let peer := peerRole localRole
  let plaintext := patternedBytes plaintextLen seed
  let firstFrameWireBytes := plaintext.length + 16
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"local_role\": " ++ roleJson localRole ++ ",\n"
    ++ "      \"peer_role\": " ++ roleJson peer ++ ",\n"
    ++ "      \"expected_local_is_initiator\": "
      ++ boolJson (localRole == Role.initiator) ++ ",\n"
    ++ "      \"expected_peer_is_initiator\": "
      ++ boolJson (peer == Role.initiator) ++ ",\n"
    ++ "      \"expected_roles_distinct\": "
      ++ boolJson (localRole != peer) ++ ",\n"
    ++ "      \"expected_local_send_slot\": "
      ++ keySlotJson (sendSlot localRole) ++ ",\n"
    ++ "      \"expected_local_recv_slot\": "
      ++ keySlotJson (recvSlot localRole) ++ ",\n"
    ++ "      \"expected_peer_send_slot\": "
      ++ keySlotJson (sendSlot peer) ++ ",\n"
    ++ "      \"expected_peer_recv_slot\": "
      ++ keySlotJson (recvSlot peer) ++ ",\n"
    ++ "      \"expected_local_send_matches_peer_recv\": "
      ++ boolJson (sendSlot localRole == recvSlot peer) ++ ",\n"
    ++ "      \"expected_local_recv_matches_peer_send\": "
      ++ boolJson (recvSlot localRole == sendSlot peer) ++ ",\n"
    ++ "      \"expected_initial_local_bytes_sent\": \"0\",\n"
    ++ "      \"expected_initial_local_bytes_received\": \"0\",\n"
    ++ "      \"expected_initial_peer_bytes_sent\": \"0\",\n"
    ++ "      \"expected_initial_peer_bytes_received\": \"0\",\n"
    ++ "      \"expected_first_frame_wire_bytes\": \""
      ++ toString firstFrameWireBytes ++ "\",\n"
    ++ "      \"plaintext_hex\": \"" ++ hexBytes plaintext ++ "\"\n"
    ++ "    }"

def wrapperCompletionCaseJson
    (name wrapperKind : String)
    (plaintextLen seed : Nat) : String :=
  let localRole := Role.initiator
  let peer := peerRole localRole
  let plaintext := patternedBytes plaintextLen seed
  let tagBytes := Hegemon.Network.PqNoiseHandshakeChannel.pqAeadTagBytes
  let firstFrameWireBytes := plaintext.length + tagBytes
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"wrapper_kind\": \"" ++ wrapperKind ++ "\",\n"
    ++ "      \"local_role\": " ++ roleJson localRole ++ ",\n"
    ++ "      \"peer_role\": " ++ roleJson peer ++ ",\n"
    ++ "      \"expected_completed\": true,\n"
    ++ "      \"expected_local_is_initiator\": true,\n"
    ++ "      \"expected_peer_is_initiator\": false,\n"
    ++ "      \"expected_roles_distinct\": true,\n"
    ++ "      \"expected_local_send_slot\": "
      ++ keySlotJson (sendSlot localRole) ++ ",\n"
    ++ "      \"expected_local_recv_slot\": "
      ++ keySlotJson (recvSlot localRole) ++ ",\n"
    ++ "      \"expected_peer_send_slot\": "
      ++ keySlotJson (sendSlot peer) ++ ",\n"
    ++ "      \"expected_peer_recv_slot\": "
      ++ keySlotJson (recvSlot peer) ++ ",\n"
    ++ "      \"expected_local_send_matches_peer_recv\": true,\n"
    ++ "      \"expected_local_recv_matches_peer_send\": true,\n"
    ++ "      \"expected_initial_local_bytes_sent\": \"0\",\n"
    ++ "      \"expected_initial_local_bytes_received\": \"0\",\n"
    ++ "      \"expected_initial_peer_bytes_sent\": \"0\",\n"
    ++ "      \"expected_initial_peer_bytes_received\": \"0\",\n"
    ++ "      \"expected_first_frame_payload_bytes\": \""
      ++ toString plaintext.length ++ "\",\n"
    ++ "      \"expected_first_frame_tag_bytes\": \""
      ++ toString tagBytes ++ "\",\n"
    ++ "      \"expected_first_frame_wire_bytes\": \""
      ++ toString firstFrameWireBytes ++ "\",\n"
    ++ "      \"expected_after_first_local_bytes_sent\": \""
      ++ toString firstFrameWireBytes ++ "\",\n"
    ++ "      \"expected_after_first_peer_bytes_received\": \""
      ++ toString firstFrameWireBytes ++ "\",\n"
    ++ "      \"plaintext_hex\": \"" ++ hexBytes plaintext ++ "\"\n"
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
    ++ "  \"schema_version\": 4,\n"
    ++ "  \"kem_rng_source_cases\": [\n"
    ++ kemRngSourceCaseJson
      "responder-os-rng-encapsulates-to-initiator"
      (osRngMlKemSeedFacts
        KemEncapsulationUse.responderEncapsulatesToInitiator True) ++ ",\n"
    ++ kemRngSourceCaseJson
      "initiator-os-rng-encapsulates-to-responder"
      (osRngMlKemSeedFacts
        KemEncapsulationUse.initiatorEncapsulatesToResponder True) ++ "\n"
    ++ "  ],\n"
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
    ++ "  \"frame_sequence_cases\": [\n"
    ++ frameSequenceCaseJson "initiator-eight-frames" Role.initiator 8 ++ ",\n"
    ++ frameSequenceCaseJson "responder-eight-frames" Role.responder 8 ++ "\n"
    ++ "  ],\n"
    ++ "  \"transport_completion_cases\": [\n"
    ++ transportCompletionCaseJson "local-initiator-transport-completion"
      Role.initiator 19 37 ++ ",\n"
    ++ transportCompletionCaseJson "local-responder-transport-completion"
      Role.responder 23 89 ++ "\n"
    ++ "  ],\n"
    ++ "  \"wrapper_completion_cases\": [\n"
    ++ wrapperCompletionCaseJson "network-pq-transport-wrapper-completion"
      "network_pq_transport" 29 131 ++ ",\n"
    ++ wrapperCompletionCaseJson "native-pq-transport-wrapper-completion"
      "native_pq_transport" 31 173 ++ "\n"
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
