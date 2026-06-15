import Hegemon.Consensus.RecursiveBlockV2VerifierSurface

open Hegemon.Consensus.RecursiveBlockV2VerifierSurface

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def surfaceRejectJson : Option SurfaceReject -> String
  | none => "null"
  | some SurfaceReject.publicMismatch => "\"public_mismatch\""
  | some SurfaceReject.proofWidthMismatch => "\"proof_width_mismatch\""
  | some SurfaceReject.unsupportedTxCount => "\"unsupported_tx_count\""
  | some SurfaceReject.headerMismatch => "\"header_mismatch\""
  | some SurfaceReject.proofDecodeFailed => "\"proof_decode_failed\""
  | some SurfaceReject.proofCanonicalEncoding => "\"proof_canonical_encoding\""
  | some SurfaceReject.proofPadding => "\"proof_padding\""
  | some SurfaceReject.proofProjectionFailed => "\"proof_projection_failed\""
  | some SurfaceReject.proofProjectedWidthMismatch => "\"proof_projected_width_mismatch\""
  | some SurfaceReject.cryptoVerificationFailed => "\"crypto_verification_failed\""

def surfaceCaseJson (name mutation : String) (input : SurfaceInput) : String :=
  let surfaceRejection := evaluateSurfaceRejection input
  let fullRejection := evaluateFullVerifierRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"mutation\": \"" ++ mutation ++ "\",\n"
    ++ "      \"public_matches\": " ++ boolJson input.publicMatches ++ ",\n"
    ++ "      \"proof_width_matches\": " ++ boolJson input.proofWidthMatches ++ ",\n"
    ++ "      \"supported_tx_count\": " ++ boolJson input.supportedTxCount ++ ",\n"
    ++ "      \"header_matches\": " ++ boolJson input.headerMatches ++ ",\n"
    ++ "      \"proof_trace_decodes\": " ++ boolJson input.proofTraceDecodes ++ ",\n"
    ++ "      \"proof_canonical_encoding\": "
    ++ boolJson input.proofCanonicalEncoding ++ ",\n"
    ++ "      \"proof_padding_zero\": " ++ boolJson input.proofPaddingZero ++ ",\n"
    ++ "      \"proof_projection_succeeds\": "
    ++ boolJson input.proofProjectionSucceeds ++ ",\n"
    ++ "      \"proof_projected_width_fits\": "
    ++ boolJson input.proofProjectedWidthFits ++ ",\n"
    ++ "      \"crypto_verifier_accepts\": "
    ++ boolJson input.cryptoVerifierAccepts ++ ",\n"
    ++ "      \"expected_surface_valid\": " ++ boolJson (surfaceRejection == none) ++ ",\n"
    ++ "      \"expected_surface_rejection\": " ++ surfaceRejectJson surfaceRejection ++ ",\n"
    ++ "      \"expected_full_valid\": " ++ boolJson (fullRejection == none) ++ ",\n"
    ++ "      \"expected_full_rejection\": " ++ surfaceRejectJson fullRejection ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"surface_cases\": [\n"
    ++ surfaceCaseJson "valid-surface" "none" validSurface ++ ",\n"
    ++ surfaceCaseJson "public-mismatch" "public_mismatch"
      { validSurface with publicMatches := false } ++ ",\n"
    ++ surfaceCaseJson "proof-width-mismatch" "proof_width_mismatch"
      { validSurface with proofWidthMatches := false } ++ ",\n"
    ++ surfaceCaseJson "unsupported-tx-count" "unsupported_tx_count"
      { validSurface with supportedTxCount := false } ++ ",\n"
    ++ surfaceCaseJson "header-mismatch" "header_mismatch"
      { validSurface with headerMatches := false } ++ ",\n"
    ++ surfaceCaseJson "proof-decode-failed" "proof_decode_failed"
      { validSurface with proofTraceDecodes := false } ++ ",\n"
    ++ surfaceCaseJson "proof-padding-rejected" "proof_padding"
      { validSurface with proofPaddingZero := false } ++ ",\n"
    ++ surfaceCaseJson "proof-projection-failed" "proof_projection_failed"
      { validSurface with proofProjectionSucceeds := false } ++ ",\n"
    ++ surfaceCaseJson "proof-projected-width-mismatch" "proof_projected_width_mismatch"
      { validSurface with proofProjectedWidthFits := false } ++ ",\n"
    ++ surfaceCaseJson "crypto-verification-failed" "crypto_verification_failed"
      { validSurface with cryptoVerifierAccepts := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
