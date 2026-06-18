namespace Hegemon
namespace Consensus
namespace RecursiveBlockV2VerifierSurface

inductive SurfaceReject where
  | publicMismatch
  | proofWidthMismatch
  | versionedCapMismatch
  | unsupportedTxCount
  | headerMismatch
  | proofDecodeFailed
  | proofCanonicalEncoding
  | proofPadding
  | proofProjectionFailed
  | proofProjectedWidthMismatch
  | cryptoVerificationFailed
deriving DecidableEq, Repr

structure SurfaceInput where
  publicMatches : Bool
  proofWidthMatches : Bool
  versionedCapMatches : Bool
  supportedTxCount : Bool
  headerMatches : Bool
  proofTraceDecodes : Bool
  proofCanonicalEncoding : Bool
  proofPaddingZero : Bool
  proofProjectionSucceeds : Bool
  proofProjectedWidthFits : Bool
  cryptoVerifierAccepts : Bool
deriving DecidableEq, Repr

def evaluateSurfaceRejection (input : SurfaceInput) : Option SurfaceReject :=
  if input.publicMatches = false then
    some SurfaceReject.publicMismatch
  else if input.proofWidthMatches = false then
    some SurfaceReject.proofWidthMismatch
  else if input.versionedCapMatches = false then
    some SurfaceReject.versionedCapMismatch
  else if input.supportedTxCount = false then
    some SurfaceReject.unsupportedTxCount
  else if input.headerMatches = false then
    some SurfaceReject.headerMismatch
  else if input.proofTraceDecodes = false then
    some SurfaceReject.proofDecodeFailed
  else if input.proofCanonicalEncoding = false then
    some SurfaceReject.proofCanonicalEncoding
  else if input.proofPaddingZero = false then
    some SurfaceReject.proofPadding
  else if input.proofProjectionSucceeds = false then
    some SurfaceReject.proofProjectionFailed
  else if input.proofProjectedWidthFits = false then
    some SurfaceReject.proofProjectedWidthMismatch
  else
    none

def evaluateFullVerifierRejection (input : SurfaceInput) : Option SurfaceReject :=
  match evaluateSurfaceRejection input with
  | some rejection => some rejection
  | none =>
      if input.cryptoVerifierAccepts = false then
        some SurfaceReject.cryptoVerificationFailed
      else
        none

def surfacePreconditions (input : SurfaceInput) : Bool :=
  if input.publicMatches = false then
    false
  else if input.proofWidthMatches = false then
    false
  else if input.versionedCapMatches = false then
    false
  else if input.supportedTxCount = false then
    false
  else if input.headerMatches = false then
    false
  else if input.proofTraceDecodes = false then
    false
  else if input.proofCanonicalEncoding = false then
    false
  else if input.proofPaddingZero = false then
    false
  else if input.proofProjectionSucceeds = false then
    false
  else if input.proofProjectedWidthFits = false then
    false
  else
    true

def fullVerifierPreconditions (input : SurfaceInput) : Bool :=
  surfacePreconditions input && input.cryptoVerifierAccepts

def surfaceAccepts (input : SurfaceInput) : Bool :=
  evaluateSurfaceRejection input = none

def fullVerifierAccepts (input : SurfaceInput) : Bool :=
  evaluateFullVerifierRejection input = none

theorem surface_accepts_iff_preconditions (input : SurfaceInput) :
    surfaceAccepts input = surfacePreconditions input := by
  cases input with
  | mk publicMatches proofWidthMatches versionedCapMatches supportedTxCount headerMatches
      proofTraceDecodes proofCanonicalEncoding proofPaddingZero proofProjectionSucceeds
      proofProjectedWidthFits cryptoVerifierAccepts =>
      unfold surfaceAccepts surfacePreconditions evaluateSurfaceRejection
      cases publicMatches <;> cases proofWidthMatches <;> cases versionedCapMatches <;>
        cases supportedTxCount <;> cases headerMatches <;> cases proofTraceDecodes <;>
        cases proofCanonicalEncoding <;> cases proofPaddingZero <;>
        cases proofProjectionSucceeds <;> cases proofProjectedWidthFits <;>
        cases cryptoVerifierAccepts <;> simp

theorem full_verifier_accepts_iff_surface_and_crypto (input : SurfaceInput) :
    fullVerifierAccepts input = fullVerifierPreconditions input := by
  cases input with
  | mk publicMatches proofWidthMatches versionedCapMatches supportedTxCount headerMatches
      proofTraceDecodes proofCanonicalEncoding proofPaddingZero proofProjectionSucceeds
      proofProjectedWidthFits cryptoVerifierAccepts =>
      unfold fullVerifierAccepts fullVerifierPreconditions surfacePreconditions
        evaluateFullVerifierRejection evaluateSurfaceRejection
      cases publicMatches <;> cases proofWidthMatches <;> cases versionedCapMatches <;>
        cases supportedTxCount <;> cases headerMatches <;> cases proofTraceDecodes <;>
        cases proofCanonicalEncoding <;> cases proofPaddingZero <;>
        cases proofProjectionSucceeds <;> cases proofProjectedWidthFits <;>
        cases cryptoVerifierAccepts <;> simp

theorem full_accepts_implies_surface_accepts (input : SurfaceInput) :
    fullVerifierAccepts input = true -> surfaceAccepts input = true := by
  cases input with
  | mk publicMatches proofWidthMatches versionedCapMatches supportedTxCount headerMatches
      proofTraceDecodes proofCanonicalEncoding proofPaddingZero proofProjectionSucceeds
      proofProjectedWidthFits cryptoVerifierAccepts =>
      unfold fullVerifierAccepts surfaceAccepts evaluateFullVerifierRejection
        evaluateSurfaceRejection
      cases publicMatches <;> cases proofWidthMatches <;> cases versionedCapMatches <;>
        cases supportedTxCount <;> cases headerMatches <;> cases proofTraceDecodes <;>
        cases proofCanonicalEncoding <;> cases proofPaddingZero <;>
        cases proofProjectionSucceeds <;> cases proofProjectedWidthFits <;>
        cases cryptoVerifierAccepts <;> simp

def validSurface : SurfaceInput :=
  {
    publicMatches := true,
    proofWidthMatches := true,
    versionedCapMatches := true,
    supportedTxCount := true,
    headerMatches := true,
    proofTraceDecodes := true,
    proofCanonicalEncoding := true,
    proofPaddingZero := true,
    proofProjectionSucceeds := true,
    proofProjectedWidthFits := true,
    cryptoVerifierAccepts := true
  }

theorem valid_surface_accepts :
    evaluateSurfaceRejection validSurface = none := by
  decide

theorem public_mismatch_rejects :
    evaluateSurfaceRejection { validSurface with publicMatches := false } =
      some SurfaceReject.publicMismatch := by
  decide

theorem proof_width_mismatch_rejects :
    evaluateSurfaceRejection { validSurface with proofWidthMatches := false } =
      some SurfaceReject.proofWidthMismatch := by
  decide

theorem versioned_cap_mismatch_rejects :
    evaluateSurfaceRejection { validSurface with versionedCapMatches := false } =
      some SurfaceReject.versionedCapMismatch := by
  decide

theorem unsupported_tx_count_rejects :
    evaluateSurfaceRejection { validSurface with supportedTxCount := false } =
      some SurfaceReject.unsupportedTxCount := by
  decide

theorem header_mismatch_rejects :
    evaluateSurfaceRejection { validSurface with headerMatches := false } =
      some SurfaceReject.headerMismatch := by
  decide

theorem proof_decode_failed_rejects :
    evaluateSurfaceRejection { validSurface with proofTraceDecodes := false } =
      some SurfaceReject.proofDecodeFailed := by
  decide

theorem proof_canonical_encoding_rejects :
    evaluateSurfaceRejection { validSurface with proofCanonicalEncoding := false } =
      some SurfaceReject.proofCanonicalEncoding := by
  decide

theorem proof_padding_rejects :
    evaluateSurfaceRejection { validSurface with proofPaddingZero := false } =
      some SurfaceReject.proofPadding := by
  decide

theorem proof_projection_failed_rejects :
    evaluateSurfaceRejection { validSurface with proofProjectionSucceeds := false } =
      some SurfaceReject.proofProjectionFailed := by
  decide

theorem proof_projected_width_mismatch_rejects :
    evaluateSurfaceRejection { validSurface with proofProjectedWidthFits := false } =
      some SurfaceReject.proofProjectedWidthMismatch := by
  decide

theorem crypto_verification_failed_is_after_surface_boundary :
    evaluateFullVerifierRejection { validSurface with cryptoVerifierAccepts := false } =
      some SurfaceReject.cryptoVerificationFailed := by
  decide

end RecursiveBlockV2VerifierSurface
end Consensus
end Hegemon
