import Hegemon.Native.MinerIdentity

open Hegemon.Native.MinerIdentity

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option NativeMinerIdentityReject -> String
  | none => "null"
  | some NativeMinerIdentityReject.invalidMinerPublicKeyLength =>
      "\"invalid_miner_public_key_length\""
  | some NativeMinerIdentityReject.invalidMinerPublicKeyBytes =>
      "\"invalid_miner_public_key_bytes\""
  | some NativeMinerIdentityReject.minerCommitmentMismatch =>
      "\"miner_commitment_mismatch\""
  | some NativeMinerIdentityReject.invalidMinerSignatureLength =>
      "\"invalid_miner_signature_length\""
  | some NativeMinerIdentityReject.invalidMinerSignatureBytes =>
      "\"invalid_miner_signature_bytes\""
  | some NativeMinerIdentityReject.nativeMinerSignatureVerificationFailed =>
      "\"native_miner_signature_verification_failed\""

def nativeMinerIdentityCaseJson
    (name : String)
    (input : NativeMinerIdentityInput) : String :=
  let result := evaluateNativeMinerIdentityRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"height\": " ++ toString input.height ++ ",\n"
    ++ "      \"public_key_len\": " ++ toString input.publicKeyLen ++ ",\n"
    ++ "      \"signature_len\": " ++ toString input.signatureLen ++ ",\n"
    ++ "      \"public_key_bytes_parse\": " ++ boolJson input.publicKeyBytesParse ++ ",\n"
    ++ "      \"miner_commitment_matches\": " ++ boolJson input.minerCommitmentMatches ++ ",\n"
    ++ "      \"signature_bytes_parse\": " ++ boolJson input.signatureBytesParse ++ ",\n"
    ++ "      \"signature_verifies\": " ++ boolJson input.signatureVerifies ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"native_miner_identity_cases\": [\n"
    ++ nativeMinerIdentityCaseJson "valid-native-miner-signature-accepted" valid ++ ",\n"
    ++ nativeMinerIdentityCaseJson "genesis-without-identity-accepted" genesisWithoutIdentity ++ ",\n"
    ++ nativeMinerIdentityCaseJson "missing-public-key-rejected" missingPublicKey ++ ",\n"
    ++ nativeMinerIdentityCaseJson "invalid-public-key-bytes-rejected"
      invalidPublicKeyBytes ++ ",\n"
    ++ nativeMinerIdentityCaseJson "miner-commitment-mismatch-rejected"
      commitmentMismatch ++ ",\n"
    ++ nativeMinerIdentityCaseJson "missing-signature-rejected" missingSignature ++ ",\n"
    ++ nativeMinerIdentityCaseJson "invalid-signature-bytes-rejected"
      invalidSignatureBytes ++ ",\n"
    ++ nativeMinerIdentityCaseJson "signature-verification-failure-rejected"
      signatureVerificationFails ++ ",\n"
    ++ nativeMinerIdentityCaseJson "public-key-failure-precedes-signature-failure"
      public_key_precedes_signature_failure_input ++ ",\n"
    ++ nativeMinerIdentityCaseJson "commitment-failure-precedes-signature-failure"
      commitment_precedes_signature_failure_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
