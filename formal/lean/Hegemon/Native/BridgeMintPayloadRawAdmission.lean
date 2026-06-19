import Hegemon.Bridge.MintPayloadAdmission
import Hegemon.Native.CodecAdmission

namespace Hegemon
namespace Native
namespace BridgeMintPayloadRawAdmission

open Hegemon.Bridge.MintPayloadAdmission
open Hegemon.Native.CodecAdmission

structure BridgeMintPayloadRawAdmissionInput where
  parserAccepts : Bool
  consumedAllBytes : Bool
  canonicalReencodeMatches : Bool
  payloadHashMatches : Bool
  receiptMessageHashMatches : Bool
  versionMatches : Bool
  destinationMatches : Bool
  recipientCommitmentNonzero : Bool
  amountNonzero : Bool
  amountWithinBound : Bool
  assetNonNative : Bool
deriving DecidableEq, Repr

def exactDecodeInputOfBridgeMintPayloadRaw
    (input : BridgeMintPayloadRawAdmissionInput) : ExactDecodeInput :=
  {
    parserAccepts := input.parserAccepts,
    consumedAllBytes := input.consumedAllBytes,
    canonicalReencodeMatches := input.canonicalReencodeMatches
  }

def bridgeMintPayloadInputOfRaw
    (input : BridgeMintPayloadRawAdmissionInput) : BridgeMintPayloadInput :=
  {
    payloadDecoded :=
      exactDecodeAccepts (exactDecodeInputOfBridgeMintPayloadRaw input),
    payloadHashMatches := input.payloadHashMatches,
    receiptMessageHashMatches := input.receiptMessageHashMatches,
    versionMatches := input.versionMatches,
    destinationMatches := input.destinationMatches,
    recipientCommitmentNonzero := input.recipientCommitmentNonzero,
    amountNonzero := input.amountNonzero,
    amountWithinBound := input.amountWithinBound,
    assetNonNative := input.assetNonNative
  }

def bridgeMintPayloadRawAccepts
    (input : BridgeMintPayloadRawAdmissionInput) : Bool :=
  bridgeMintPayloadAccepts (bridgeMintPayloadInputOfRaw input)

def bridgeMintPayloadRawRejection
    (input : BridgeMintPayloadRawAdmissionInput) :
      Option BridgeMintPayloadReject :=
  bridgeMintPayloadRejection (bridgeMintPayloadInputOfRaw input)

theorem accepted_bridge_mint_payload_raw_exposes_exact_decode
    {input : BridgeMintPayloadRawAdmissionInput}
    (accepted : bridgeMintPayloadRawAccepts input = true) :
    exactDecodeAccepts
      (exactDecodeInputOfBridgeMintPayloadRaw input) = true := by
  have facts :=
    accepted_bridge_mint_payload_exposes_facts
      (input := bridgeMintPayloadInputOfRaw input) accepted
  simpa [bridgeMintPayloadInputOfRaw] using facts.1

theorem accepted_bridge_mint_payload_raw_excludes_malleability
    {input : BridgeMintPayloadRawAdmissionInput}
    (accepted : bridgeMintPayloadRawAccepts input = true) :
    input.parserAccepts = true ∧
      input.consumedAllBytes = true ∧
      input.canonicalReencodeMatches = true := by
  exact
    exact_decode_acceptance_excludes_malleability
      (accepted_bridge_mint_payload_raw_exposes_exact_decode accepted)

theorem accepted_bridge_mint_payload_raw_exposes_policy_facts
    {input : BridgeMintPayloadRawAdmissionInput}
    (accepted : bridgeMintPayloadRawAccepts input = true) :
    BridgeMintPayloadFacts (bridgeMintPayloadInputOfRaw input) :=
  accepted_bridge_mint_payload_exposes_facts accepted

def validRawBridgeMintPayload : BridgeMintPayloadRawAdmissionInput :=
  {
    parserAccepts := true,
    consumedAllBytes := true,
    canonicalReencodeMatches := true,
    payloadHashMatches := true,
    receiptMessageHashMatches := true,
    versionMatches := true,
    destinationMatches := true,
    recipientCommitmentNonzero := true,
    amountNonzero := true,
    amountWithinBound := true,
    assetNonNative := true
  }

theorem valid_raw_bridge_mint_payload_accepts :
    bridgeMintPayloadRawAccepts validRawBridgeMintPayload = true := by
  rfl

theorem raw_decode_failure_precedes_payload_hash
    {input : BridgeMintPayloadRawAdmissionInput}
    (parserRejected : input.parserAccepts = false) :
    bridgeMintPayloadRawRejection input =
      some BridgeMintPayloadReject.payloadDecodeFailed := by
  unfold bridgeMintPayloadRawRejection
    bridgeMintPayloadRejection
    bridgeMintPayloadInputOfRaw
  unfold exactDecodeAccepts
    exactDecodeInputOfBridgeMintPayloadRaw
    evaluateExactDecodeRejection
  simp [parserRejected, evaluateBridgeMintPayload]

theorem raw_trailing_bytes_precede_payload_hash
    {input : BridgeMintPayloadRawAdmissionInput}
    (parserAccepted : input.parserAccepts = true)
    (hasTrailing : input.consumedAllBytes = false) :
    bridgeMintPayloadRawRejection input =
      some BridgeMintPayloadReject.payloadDecodeFailed := by
  unfold bridgeMintPayloadRawRejection
    bridgeMintPayloadRejection
    bridgeMintPayloadInputOfRaw
  unfold exactDecodeAccepts
    exactDecodeInputOfBridgeMintPayloadRaw
    evaluateExactDecodeRejection
  simp [parserAccepted, hasTrailing, evaluateBridgeMintPayload]

end BridgeMintPayloadRawAdmission
end Native
end Hegemon
