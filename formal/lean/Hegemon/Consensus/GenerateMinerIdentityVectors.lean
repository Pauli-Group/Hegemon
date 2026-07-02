import Hegemon.Consensus.MinerIdentity

open Hegemon.Consensus

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def minerIdentityRejectionJson : Option PowMinerIdentityReject -> String
  | none => "null"
  | some PowMinerIdentityReject.powHeaderSignatureBitmap =>
      "\"pow_header_signature_bitmap\""
  | some PowMinerIdentityReject.unregisteredPowMiner =>
      "\"unregistered_pow_miner\""
  | some PowMinerIdentityReject.invalidPowMinerSignatureLength =>
      "\"invalid_pow_miner_signature_length\""
  | some PowMinerIdentityReject.invalidPowMinerSignatureBytes =>
      "\"invalid_pow_miner_signature_bytes\""
  | some PowMinerIdentityReject.powMinerSignatureVerificationFailed =>
      "\"pow_miner_signature_verification_failed\""

def minerIdentityCaseJson
    (name : String)
    (input : PowMinerIdentityInput) : String :=
  let result := evaluatePowMinerIdentity input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"has_signature_bitmap\": " ++ boolJson input.hasSignatureBitmap ++ ",\n"
    ++ "      \"miner_registered\": " ++ boolJson input.minerRegistered ++ ",\n"
    ++ "      \"signature_len\": " ++ toString input.signatureLen ++ ",\n"
    ++ "      \"signature_bytes_parse\": " ++ boolJson input.signatureBytesParse ++ ",\n"
    ++ "      \"signature_verifies\": " ++ boolJson input.signatureVerifies ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ minerIdentityRejectionJson result ++ "\n"
    ++ "    }"

def validMinerIdentity : PowMinerIdentityInput :=
  {
    hasSignatureBitmap := false,
    minerRegistered := true,
    signatureLen := mlDsa65SignatureBytes,
    signatureBytesParse := true,
    signatureVerifies := true
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"miner_identity_cases\": [\n"
    ++ minerIdentityCaseJson "valid-miner-signature-accepted" validMinerIdentity ++ ",\n"
    ++ minerIdentityCaseJson "pow-header-bft-bitmap-rejected"
      { validMinerIdentity with hasSignatureBitmap := true } ++ ",\n"
    ++ minerIdentityCaseJson "unregistered-miner-rejected"
      { validMinerIdentity with minerRegistered := false } ++ ",\n"
    ++ minerIdentityCaseJson "missing-signature-rejected"
      { validMinerIdentity with signatureLen := 0 } ++ ",\n"
    ++ minerIdentityCaseJson "oversized-signature-rejected"
      { validMinerIdentity with signatureLen := mlDsa65SignatureBytes + 1 } ++ ",\n"
    ++ minerIdentityCaseJson "invalid-signature-bytes-rejected"
      { validMinerIdentity with signatureBytesParse := false } ++ ",\n"
    ++ minerIdentityCaseJson "signature-verification-failure-rejected"
      { validMinerIdentity with signatureVerifies := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
