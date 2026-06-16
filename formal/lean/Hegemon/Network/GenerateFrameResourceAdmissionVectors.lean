import Hegemon.Network.FrameResourceAdmission

open Hegemon
open Hegemon.Network.FrameResourceAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def frameKindName : FrameKind -> String
  | FrameKind.networkHandshake => "network_handshake"
  | FrameKind.networkWire => "network_wire"
  | FrameKind.networkPeerStore => "network_peer_store"
  | FrameKind.pqHandshake => "pq_handshake"
  | FrameKind.pqSessionPlaintext => "pq_session_plaintext"
  | FrameKind.pqTranscript => "pq_transcript"

def frameKindJson (kind : FrameKind) : String :=
  "\"" ++ frameKindName kind ++ "\""

def frameRejectName : FrameReject -> String
  | FrameReject.encodedBytesExceeded => "encoded_bytes_exceeded"
  | FrameReject.missingMarker => "missing_marker"
  | FrameReject.postcardDecodeFailed => "postcard_decode_failed"
  | FrameReject.trailingBytes => "trailing_bytes"

def optionalRejectJson : Option FrameReject -> String
  | none => "null"
  | some rejection => "\"" ++ frameRejectName rejection ++ "\""

def constantCaseJson (kind : FrameKind) : String :=
  "    {\n"
    ++ "      \"kind\": " ++ frameKindJson kind ++ ",\n"
    ++ "      \"max_len\": " ++ toString (frameKindMaxLen kind) ++ ",\n"
    ++ "      \"magic_hex\": \"" ++ hexBytes (frameKindMagic kind) ++ "\",\n"
    ++ "      \"postcard_encoded\": " ++ boolJson (frameKindIsPostcardEncoded kind) ++ "\n"
    ++ "    }"

def decodeCaseJson
    (name : String)
    (input : FrameDecodeInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": " ++ frameKindJson input.kind ++ ",\n"
    ++ "      \"encoded_bytes\": " ++ toString input.encodedBytes ++ ",\n"
    ++ "      \"marker_matches\": " ++ boolJson input.markerMatches ++ ",\n"
    ++ "      \"postcard_decodes\": " ++ boolJson input.postcardDecodes ++ ",\n"
    ++ "      \"postcard_consumes_all\": " ++ boolJson input.postcardConsumesAll ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (evaluateFrameDecode input == none) ++ ",\n"
    ++ "      \"expected_reject\": "
      ++ optionalRejectJson (evaluateFrameDecode input) ++ ",\n"
    ++ "      \"expected_max_len\": "
      ++ toString (frameKindMaxLen input.kind) ++ ",\n"
    ++ "      \"expected_magic_hex\": \""
      ++ hexBytes (frameKindMagic input.kind) ++ "\",\n"
    ++ "      \"expected_postcard_encoded\": "
      ++ boolJson (frameKindIsPostcardEncoded input.kind) ++ "\n"
    ++ "    }"

def encodeCaseJson
    (name : String)
    (input : FrameEncodeInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": " ++ frameKindJson input.kind ++ ",\n"
    ++ "      \"body_bytes\": " ++ toString input.bodyBytes ++ ",\n"
    ++ "      \"expected_total_len\": "
      ++ toString (encodedFrameBytes input) ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (evaluateFrameEncode input == none) ++ ",\n"
    ++ "      \"expected_reject\": "
      ++ optionalRejectJson (evaluateFrameEncode input) ++ ",\n"
    ++ "      \"expected_max_len\": "
      ++ toString (frameKindMaxLen input.kind) ++ ",\n"
    ++ "      \"expected_magic_hex\": \""
      ++ hexBytes (frameKindMagic input.kind) ++ "\"\n"
    ++ "    }"

def decodeCases : List (String × FrameDecodeInput) := [
  ("network-wire-valid",
    { kind := FrameKind.networkWire, encodedBytes := 12, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("network-wire-oversize-precedes-marker",
    { kind := FrameKind.networkWire, encodedBytes := networkWireMaxFrameLen + 1,
      markerMatches := false, postcardDecodes := false, postcardConsumesAll := false }),
  ("network-wire-missing-marker",
    { kind := FrameKind.networkWire, encodedBytes := 12, markerMatches := false,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("network-wire-postcard-failure",
    { kind := FrameKind.networkWire, encodedBytes := 4, markerMatches := true,
      postcardDecodes := false, postcardConsumesAll := true }),
  ("network-wire-trailing-bytes",
    { kind := FrameKind.networkWire, encodedBytes := 13, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := false }),
  ("network-handshake-valid",
    { kind := FrameKind.networkHandshake, encodedBytes := 12, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("network-peer-store-oversize",
    { kind := FrameKind.networkPeerStore, encodedBytes := networkPeerStoreMaxFrameLen + 1,
      markerMatches := true, postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-handshake-valid",
    { kind := FrameKind.pqHandshake, encodedBytes := 12, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-handshake-oversize-precedes-marker",
    { kind := FrameKind.pqHandshake, encodedBytes := pqHandshakeMaxFrameLen + 1,
      markerMatches := false, postcardDecodes := false, postcardConsumesAll := false }),
  ("pq-handshake-missing-marker",
    { kind := FrameKind.pqHandshake, encodedBytes := 12, markerMatches := false,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-handshake-postcard-failure",
    { kind := FrameKind.pqHandshake, encodedBytes := 4, markerMatches := true,
      postcardDecodes := false, postcardConsumesAll := true }),
  ("pq-handshake-trailing-bytes",
    { kind := FrameKind.pqHandshake, encodedBytes := 13, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := false }),
  ("pq-session-plaintext-valid",
    { kind := FrameKind.pqSessionPlaintext, encodedBytes := 12, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-session-plaintext-oversize",
    { kind := FrameKind.pqSessionPlaintext, encodedBytes := pqSessionPlaintextMaxLen + 1,
      markerMatches := true, postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-session-plaintext-missing-marker",
    { kind := FrameKind.pqSessionPlaintext, encodedBytes := 12, markerMatches := false,
      postcardDecodes := true, postcardConsumesAll := true }),
  ("pq-session-plaintext-trailing-bytes",
    { kind := FrameKind.pqSessionPlaintext, encodedBytes := 13, markerMatches := true,
      postcardDecodes := true, postcardConsumesAll := false })
]

def encodeCases : List (String × FrameEncodeInput) := [
  ("network-wire-exact-limit",
    { kind := FrameKind.networkWire, bodyBytes := networkWireMaxFrameLen - 4 }),
  ("network-wire-over-limit",
    { kind := FrameKind.networkWire, bodyBytes := networkWireMaxFrameLen - 3 }),
  ("network-handshake-exact-limit",
    { kind := FrameKind.networkHandshake, bodyBytes := networkHandshakeMaxFrameLen - 4 }),
  ("network-peer-store-over-limit",
    { kind := FrameKind.networkPeerStore, bodyBytes := networkPeerStoreMaxFrameLen - 3 }),
  ("pq-handshake-exact-limit",
    { kind := FrameKind.pqHandshake, bodyBytes := pqHandshakeMaxFrameLen - 4 }),
  ("pq-handshake-over-limit",
    { kind := FrameKind.pqHandshake, bodyBytes := pqHandshakeMaxFrameLen - 3 }),
  ("pq-session-plaintext-exact-limit",
    { kind := FrameKind.pqSessionPlaintext, bodyBytes := pqSessionPlaintextMaxLen - 4 }),
  ("pq-session-plaintext-over-limit",
    { kind := FrameKind.pqSessionPlaintext, bodyBytes := pqSessionPlaintextMaxLen - 3 }),
  ("pq-transcript-exact-limit",
    { kind := FrameKind.pqTranscript, bodyBytes := pqHandshakeMaxFrameLen - 4 }),
  ("pq-transcript-over-limit",
    { kind := FrameKind.pqTranscript, bodyBytes := pqHandshakeMaxFrameLen - 3 })
]

def constantKinds : List FrameKind := [
  FrameKind.networkHandshake,
  FrameKind.networkWire,
  FrameKind.networkPeerStore,
  FrameKind.pqHandshake,
  FrameKind.pqSessionPlaintext,
  FrameKind.pqTranscript
]

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"constants\": [\n"
    ++ String.intercalate ",\n" (constantKinds.map constantCaseJson) ++ "\n"
    ++ "  ],\n"
    ++ "  \"decode_cases\": [\n"
    ++ String.intercalate ",\n" (decodeCases.map fun item => decodeCaseJson item.fst item.snd)
    ++ "\n"
    ++ "  ],\n"
    ++ "  \"encode_cases\": [\n"
    ++ String.intercalate ",\n" (encodeCases.map fun item => encodeCaseJson item.fst item.snd)
    ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
