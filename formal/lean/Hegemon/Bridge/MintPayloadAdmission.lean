namespace Hegemon
namespace Bridge
namespace MintPayloadAdmission

inductive BridgeMintPayloadReject where
  | payloadDecodeFailed
  | payloadHashMismatch
  | receiptMessageHashMismatch
  | versionMismatch
  | destinationMismatch
  | mintNonceMismatch
  | recipientCommitmentZero
  | amountZero
  | amountOutOfBounds
  | nativeAssetNotAllowed
deriving DecidableEq, Repr

structure BridgeMintPayloadInput where
  payloadDecoded : Bool
  payloadHashMatches : Bool
  receiptMessageHashMatches : Bool
  versionMatches : Bool
  destinationMatches : Bool
  mintNonceMatches : Bool
  recipientCommitmentNonzero : Bool
  amountNonzero : Bool
  amountWithinBound : Bool
  assetNonNative : Bool
deriving DecidableEq, Repr

def evaluateBridgeMintPayload
    (input : BridgeMintPayloadInput) :
      Except BridgeMintPayloadReject Unit :=
  if input.payloadDecoded = false then
    Except.error BridgeMintPayloadReject.payloadDecodeFailed
  else if input.payloadHashMatches = false then
    Except.error BridgeMintPayloadReject.payloadHashMismatch
  else if input.receiptMessageHashMatches = false then
    Except.error BridgeMintPayloadReject.receiptMessageHashMismatch
  else if input.versionMatches = false then
    Except.error BridgeMintPayloadReject.versionMismatch
  else if input.destinationMatches = false then
    Except.error BridgeMintPayloadReject.destinationMismatch
  else if input.mintNonceMatches = false then
    Except.error BridgeMintPayloadReject.mintNonceMismatch
  else if input.recipientCommitmentNonzero = false then
    Except.error BridgeMintPayloadReject.recipientCommitmentZero
  else if input.amountNonzero = false then
    Except.error BridgeMintPayloadReject.amountZero
  else if input.amountWithinBound = false then
    Except.error BridgeMintPayloadReject.amountOutOfBounds
  else if input.assetNonNative = false then
    Except.error BridgeMintPayloadReject.nativeAssetNotAllowed
  else
    Except.ok ()

def bridgeMintPayloadAccepts
    (input : BridgeMintPayloadInput) : Bool :=
  match evaluateBridgeMintPayload input with
  | Except.ok _ => true
  | Except.error _ => false

def bridgeMintPayloadRejection
    (input : BridgeMintPayloadInput) :
      Option BridgeMintPayloadReject :=
  match evaluateBridgeMintPayload input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def bridgeMintPayloadPreconditions
    (input : BridgeMintPayloadInput) : Bool :=
  input.payloadDecoded
    && input.payloadHashMatches
    && input.receiptMessageHashMatches
    && input.versionMatches
    && input.destinationMatches
    && input.mintNonceMatches
    && input.recipientCommitmentNonzero
    && input.amountNonzero
    && input.amountWithinBound
    && input.assetNonNative

def BridgeMintPayloadFacts
    (input : BridgeMintPayloadInput) : Prop :=
  input.payloadDecoded = true
    ∧ input.payloadHashMatches = true
    ∧ input.receiptMessageHashMatches = true
    ∧ input.versionMatches = true
    ∧ input.destinationMatches = true
    ∧ input.mintNonceMatches = true
    ∧ input.recipientCommitmentNonzero = true
    ∧ input.amountNonzero = true
    ∧ input.amountWithinBound = true
    ∧ input.assetNonNative = true

theorem accepts_iff_bridge_mint_payload_preconditions
    (input : BridgeMintPayloadInput) :
    bridgeMintPayloadAccepts input =
      bridgeMintPayloadPreconditions input := by
  cases input with
  | mk payloadDecoded payloadHashMatches receiptMessageHashMatches
      versionMatches destinationMatches mintNonceMatches recipientCommitmentNonzero
      amountNonzero amountWithinBound assetNonNative =>
      unfold bridgeMintPayloadAccepts
        bridgeMintPayloadPreconditions
        evaluateBridgeMintPayload
      cases payloadDecoded <;>
        cases payloadHashMatches <;>
        cases receiptMessageHashMatches <;>
        cases versionMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        rfl

theorem accepted_bridge_mint_payload_exposes_facts
    {input : BridgeMintPayloadInput}
    (accepted : bridgeMintPayloadAccepts input = true) :
    BridgeMintPayloadFacts input := by
  cases input with
  | mk payloadDecoded payloadHashMatches receiptMessageHashMatches
      versionMatches destinationMatches mintNonceMatches recipientCommitmentNonzero
      amountNonzero amountWithinBound assetNonNative =>
      cases payloadDecoded <;>
        cases payloadHashMatches <;>
        cases receiptMessageHashMatches <;>
        cases versionMatches <;>
        cases destinationMatches <;>
        cases mintNonceMatches <;>
        cases recipientCommitmentNonzero <;>
        cases amountNonzero <;>
        cases amountWithinBound <;>
        cases assetNonNative <;>
        simp [
          bridgeMintPayloadAccepts,
          evaluateBridgeMintPayload,
          BridgeMintPayloadFacts
        ] at accepted ⊢

def validBridgeMintPayload : BridgeMintPayloadInput :=
  {
    payloadDecoded := true,
    payloadHashMatches := true,
    receiptMessageHashMatches := true,
    versionMatches := true,
    destinationMatches := true,
    mintNonceMatches := true,
    recipientCommitmentNonzero := true,
    amountNonzero := true,
    amountWithinBound := true,
    assetNonNative := true
  }

theorem valid_bridge_mint_payload_accepts :
    bridgeMintPayloadAccepts validBridgeMintPayload = true := by
  decide

theorem payload_decode_failure_precedes_hash
    {input : BridgeMintPayloadInput}
    (decodeFailed : input.payloadDecoded = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.payloadDecodeFailed := by
  unfold evaluateBridgeMintPayload
  simp [decodeFailed]

theorem payload_hash_mismatch_rejects
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (hashMismatch : input.payloadHashMatches = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.payloadHashMismatch := by
  unfold evaluateBridgeMintPayload
  simp [decoded, hashMismatch]

theorem receipt_message_hash_mismatch_rejects
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptMismatch : input.receiptMessageHashMatches = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.receiptMessageHashMismatch := by
  unfold evaluateBridgeMintPayload
  simp [decoded, payloadHash, receiptMismatch]

theorem amount_zero_precedes_amount_bound
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptHash : input.receiptMessageHashMatches = true)
    (version : input.versionMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amountZero : input.amountNonzero = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.amountZero := by
  unfold evaluateBridgeMintPayload
  simp [
    decoded,
    payloadHash,
    receiptHash,
    version,
    destination,
    mintNonce,
    recipient,
    amountZero
  ]

theorem native_asset_rejected_after_amount_bound
    {input : BridgeMintPayloadInput}
    (decoded : input.payloadDecoded = true)
    (payloadHash : input.payloadHashMatches = true)
    (receiptHash : input.receiptMessageHashMatches = true)
    (version : input.versionMatches = true)
    (destination : input.destinationMatches = true)
    (mintNonce : input.mintNonceMatches = true)
    (recipient : input.recipientCommitmentNonzero = true)
    (amount : input.amountNonzero = true)
    (bound : input.amountWithinBound = true)
    (nativeAsset : input.assetNonNative = false) :
    evaluateBridgeMintPayload input =
      Except.error BridgeMintPayloadReject.nativeAssetNotAllowed := by
  unfold evaluateBridgeMintPayload
  simp [
    decoded,
    payloadHash,
    receiptHash,
    version,
    destination,
    mintNonce,
    recipient,
    amount,
    bound,
    nativeAsset
  ]

end MintPayloadAdmission
end Bridge
end Hegemon
