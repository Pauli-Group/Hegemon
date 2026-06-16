import Hegemon.Bytes

namespace Hegemon
namespace Network
namespace FrameResourceAdmission

def kib (value : Nat) : Nat :=
  value * 1024

def mib (value : Nat) : Nat :=
  value * 1024 * 1024

def networkWireMagic : List Byte :=
  asciiBytes "HNW1"

def pqHandshakeMagic : List Byte :=
  asciiBytes "PNH1"

def pqSessionMagic : List Byte :=
  asciiBytes "PNS1"

def pqTranscriptMagic : List Byte :=
  asciiBytes "PNT1"

def networkHandshakeMaxFrameLen : Nat :=
  kib 64

def networkWireMaxFrameLen : Nat :=
  mib 16

def networkPeerStoreMaxFrameLen : Nat :=
  mib 2

def pqHandshakeMaxFrameLen : Nat :=
  kib 64

def pqSessionMaxFrameLen : Nat :=
  mib 8

def pqSessionAeadTagLen : Nat :=
  16

def pqSessionPlaintextMaxLen : Nat :=
  pqSessionMaxFrameLen - pqSessionAeadTagLen

inductive FrameKind where
  | networkHandshake
  | networkWire
  | networkPeerStore
  | pqHandshake
  | pqSessionPlaintext
  | pqTranscript
deriving DecidableEq, Repr

def frameKindMagic : FrameKind -> List Byte
  | FrameKind.networkHandshake => networkWireMagic
  | FrameKind.networkWire => networkWireMagic
  | FrameKind.networkPeerStore => networkWireMagic
  | FrameKind.pqHandshake => pqHandshakeMagic
  | FrameKind.pqSessionPlaintext => pqSessionMagic
  | FrameKind.pqTranscript => pqTranscriptMagic

def frameKindMaxLen : FrameKind -> Nat
  | FrameKind.networkHandshake => networkHandshakeMaxFrameLen
  | FrameKind.networkWire => networkWireMaxFrameLen
  | FrameKind.networkPeerStore => networkPeerStoreMaxFrameLen
  | FrameKind.pqHandshake => pqHandshakeMaxFrameLen
  | FrameKind.pqSessionPlaintext => pqSessionPlaintextMaxLen
  | FrameKind.pqTranscript => pqHandshakeMaxFrameLen

def frameKindIsPostcardEncoded : FrameKind -> Bool
  | _ => true

structure FrameDecodeInput where
  kind : FrameKind
  encodedBytes : Nat
  markerMatches : Bool
  postcardDecodes : Bool
  postcardConsumesAll : Bool
deriving DecidableEq, Repr

inductive FrameReject where
  | encodedBytesExceeded
  | missingMarker
  | postcardDecodeFailed
  | trailingBytes
deriving DecidableEq, Repr

def evaluateFrameDecode (input : FrameDecodeInput) : Option FrameReject :=
  if input.encodedBytes > frameKindMaxLen input.kind then
    some FrameReject.encodedBytesExceeded
  else if input.markerMatches != true then
    some FrameReject.missingMarker
  else if frameKindIsPostcardEncoded input.kind && input.postcardDecodes != true then
    some FrameReject.postcardDecodeFailed
  else if frameKindIsPostcardEncoded input.kind && input.postcardConsumesAll != true then
    some FrameReject.trailingBytes
  else
    none

def frameDecodePreconditions (input : FrameDecodeInput) : Prop :=
  input.encodedBytes <= frameKindMaxLen input.kind
    ∧ input.markerMatches = true
    ∧ (frameKindIsPostcardEncoded input.kind = true -> input.postcardDecodes = true)
    ∧ (frameKindIsPostcardEncoded input.kind = true -> input.postcardConsumesAll = true)

structure AcceptedFrameDecodeFacts (input : FrameDecodeInput) where
  withinBound : input.encodedBytes <= frameKindMaxLen input.kind
  markerDomainSeparated : frameKindMagic input.kind = frameKindMagic input.kind
  markerAccepted : input.markerMatches = true
  postcardDecodeAccepted :
    frameKindIsPostcardEncoded input.kind = true -> input.postcardDecodes = true
  noTrailingBytes :
    frameKindIsPostcardEncoded input.kind = true -> input.postcardConsumesAll = true

theorem evaluate_frame_decode_accepts_iff
    (input : FrameDecodeInput) :
    evaluateFrameDecode input = none <-> frameDecodePreconditions input := by
  constructor
  · intro accepted
    have within : input.encodedBytes <= frameKindMaxLen input.kind := by
      by_cases inside : input.encodedBytes <= frameKindMaxLen input.kind
      · exact inside
      have oversize : input.encodedBytes > frameKindMaxLen input.kind := by
        omega
      simp [evaluateFrameDecode, oversize] at accepted
    have markerAccepted : input.markerMatches = true := by
      by_cases marker : input.markerMatches = true
      · exact marker
      · have missing : input.markerMatches = false := by
          cases h : input.markerMatches
          · rfl
          · have impossible : False := by
              simp [h] at marker
            exact False.elim impossible
        have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
          omega
        simp [evaluateFrameDecode, notOversize, missing] at accepted
    have postcardDecodeAccepted :
        frameKindIsPostcardEncoded input.kind = true -> input.postcardDecodes = true := by
      intro postcard
      by_cases decoded : input.postcardDecodes = true
      · exact decoded
      · have failed : input.postcardDecodes = false := by
          cases h : input.postcardDecodes
          · rfl
          · have impossible : False := by
              simp [h] at decoded
            exact False.elim impossible
        have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
          omega
        simp [evaluateFrameDecode, notOversize, markerAccepted, postcard, failed] at accepted
    have noTrailing :
        frameKindIsPostcardEncoded input.kind = true -> input.postcardConsumesAll = true := by
      intro postcard
      by_cases consumed : input.postcardConsumesAll = true
      · exact consumed
      · have trailing : input.postcardConsumesAll = false := by
          cases h : input.postcardConsumesAll
          · rfl
          · have impossible : False := by
              simp [h] at consumed
            exact False.elim impossible
        have decoded := postcardDecodeAccepted postcard
        have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
          omega
        simp [evaluateFrameDecode, notOversize, markerAccepted, postcard, decoded,
          trailing] at accepted
    exact ⟨within, markerAccepted, postcardDecodeAccepted, noTrailing⟩
  · intro preconditions
    obtain ⟨within, markerAccepted, postcardDecodeAccepted, noTrailing⟩ := preconditions
    have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
      omega
    by_cases postcard : frameKindIsPostcardEncoded input.kind = true
    · have decoded := postcardDecodeAccepted postcard
      have consumed := noTrailing postcard
      simp [evaluateFrameDecode, notOversize, markerAccepted, postcard, decoded, consumed]
    · have notPostcard : frameKindIsPostcardEncoded input.kind = false := by
        cases h : frameKindIsPostcardEncoded input.kind
        · rfl
        · have impossible : False := by
            simp [h] at postcard
          exact False.elim impossible
      simp [evaluateFrameDecode, notOversize, markerAccepted, notPostcard]

theorem accepted_frame_decode_exposes_facts
    {input : FrameDecodeInput}
    (accepted : evaluateFrameDecode input = none) :
    AcceptedFrameDecodeFacts input := by
  have preconditions := (evaluate_frame_decode_accepts_iff input).mp accepted
  exact {
    withinBound := preconditions.left,
    markerDomainSeparated := rfl,
    markerAccepted := preconditions.right.left,
    postcardDecodeAccepted := preconditions.right.right.left,
    noTrailingBytes := preconditions.right.right.right
  }

theorem decode_oversize_rejected
    {input : FrameDecodeInput}
    (oversize : input.encodedBytes > frameKindMaxLen input.kind) :
    evaluateFrameDecode input = some FrameReject.encodedBytesExceeded := by
  simp [evaluateFrameDecode, oversize]

theorem decode_missing_marker_rejected
    {input : FrameDecodeInput}
    (withinBound : input.encodedBytes <= frameKindMaxLen input.kind)
    (missing : input.markerMatches = false) :
    evaluateFrameDecode input = some FrameReject.missingMarker := by
  have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
    omega
  simp [evaluateFrameDecode, missing, notOversize]

theorem decode_postcard_failure_rejected
    {input : FrameDecodeInput}
    (withinBound : input.encodedBytes <= frameKindMaxLen input.kind)
    (marker : input.markerMatches = true)
    (postcard : frameKindIsPostcardEncoded input.kind = true)
    (failed : input.postcardDecodes = false) :
    evaluateFrameDecode input = some FrameReject.postcardDecodeFailed := by
  have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
    omega
  simp [evaluateFrameDecode, marker, postcard, failed, notOversize]

theorem decode_trailing_bytes_rejected
    {input : FrameDecodeInput}
    (withinBound : input.encodedBytes <= frameKindMaxLen input.kind)
    (marker : input.markerMatches = true)
    (postcard : frameKindIsPostcardEncoded input.kind = true)
    (decoded : input.postcardDecodes = true)
    (trailing : input.postcardConsumesAll = false) :
    evaluateFrameDecode input = some FrameReject.trailingBytes := by
  have notOversize : ¬ input.encodedBytes > frameKindMaxLen input.kind := by
    omega
  simp [evaluateFrameDecode, marker, postcard, decoded, trailing, notOversize]

structure FrameEncodeInput where
  kind : FrameKind
  bodyBytes : Nat
deriving DecidableEq, Repr

def encodedFrameBytes (input : FrameEncodeInput) : Nat :=
  (frameKindMagic input.kind).length + input.bodyBytes

def evaluateFrameEncode (input : FrameEncodeInput) : Option FrameReject :=
  if encodedFrameBytes input > frameKindMaxLen input.kind then
    some FrameReject.encodedBytesExceeded
  else
    none

def frameEncodePreconditions (input : FrameEncodeInput) : Prop :=
  encodedFrameBytes input <= frameKindMaxLen input.kind

theorem evaluate_frame_encode_accepts_iff
    (input : FrameEncodeInput) :
    evaluateFrameEncode input = none <-> frameEncodePreconditions input := by
  cases input with
  | mk kind bodyBytes =>
      by_cases oversize : encodedFrameBytes { kind := kind, bodyBytes := bodyBytes } >
          frameKindMaxLen kind
      · cases kind <;>
        simp [evaluateFrameEncode, frameEncodePreconditions, encodedFrameBytes,
          frameKindMaxLen, frameKindMagic, networkWireMagic, pqHandshakeMagic,
          pqSessionMagic, pqTranscriptMagic] at * <;> omega
      · cases kind <;>
        simp [evaluateFrameEncode, frameEncodePreconditions, encodedFrameBytes,
          frameKindMaxLen, frameKindMagic, networkWireMagic, pqHandshakeMagic,
          pqSessionMagic, pqTranscriptMagic] at * <;> omega

theorem accepted_frame_encode_within_bound
    {input : FrameEncodeInput}
    (accepted : evaluateFrameEncode input = none) :
    encodedFrameBytes input <= frameKindMaxLen input.kind :=
  (evaluate_frame_encode_accepts_iff input).mp accepted

theorem frame_kind_magic_length_four
    (kind : FrameKind) :
    (frameKindMagic kind).length = 4 := by
  cases kind <;> decide

theorem pq_session_plaintext_plus_tag_eq_ciphertext_bound :
    pqSessionPlaintextMaxLen + pqSessionAeadTagLen = pqSessionMaxFrameLen := by
  decide

theorem pq_session_plaintext_bound_below_ciphertext_bound :
    pqSessionPlaintextMaxLen < pqSessionMaxFrameLen := by
  decide

theorem pq_handshake_magic_distinct_from_session :
    pqHandshakeMagic ≠ pqSessionMagic := by
  decide

theorem pq_transcript_magic_distinct_from_session :
    pqTranscriptMagic ≠ pqSessionMagic := by
  decide

theorem network_magic_distinct_from_pq_handshake :
    networkWireMagic ≠ pqHandshakeMagic := by
  decide

end FrameResourceAdmission
end Network
end Hegemon
