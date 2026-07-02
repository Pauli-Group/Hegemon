namespace Hegemon
namespace Native
namespace MinerIdentity

def mlDsa65PublicKeyBytes : Nat := 1952
def mlDsa65SignatureBytes : Nat := 3309

inductive NativeMinerIdentityReject where
  | invalidMinerPublicKeyLength
  | invalidMinerPublicKeyBytes
  | minerCommitmentMismatch
  | invalidMinerSignatureLength
  | invalidMinerSignatureBytes
  | nativeMinerSignatureVerificationFailed
deriving DecidableEq, Repr

structure NativeMinerIdentityInput where
  height : Nat
  publicKeyLen : Nat
  signatureLen : Nat
  publicKeyBytesParse : Bool
  minerCommitmentMatches : Bool
  signatureBytesParse : Bool
  signatureVerifies : Bool
deriving DecidableEq, Repr

def publicKeyLengthMatches (input : NativeMinerIdentityInput) : Bool :=
  input.publicKeyLen == mlDsa65PublicKeyBytes

def signatureLengthMatches (input : NativeMinerIdentityInput) : Bool :=
  input.signatureLen == mlDsa65SignatureBytes

def isGenesis (input : NativeMinerIdentityInput) : Bool :=
  input.height == 0

def evaluateNativeMinerIdentityRejection
    (input : NativeMinerIdentityInput) : Option NativeMinerIdentityReject :=
  if isGenesis input then
    none
  else if publicKeyLengthMatches input = false then
    some NativeMinerIdentityReject.invalidMinerPublicKeyLength
  else if !input.publicKeyBytesParse then
    some NativeMinerIdentityReject.invalidMinerPublicKeyBytes
  else if !input.minerCommitmentMatches then
    some NativeMinerIdentityReject.minerCommitmentMismatch
  else if signatureLengthMatches input = false then
    some NativeMinerIdentityReject.invalidMinerSignatureLength
  else if !input.signatureBytesParse then
    some NativeMinerIdentityReject.invalidMinerSignatureBytes
  else if !input.signatureVerifies then
    some NativeMinerIdentityReject.nativeMinerSignatureVerificationFailed
  else
    none

def nativeMinerIdentityAccepts (input : NativeMinerIdentityInput) : Bool :=
  evaluateNativeMinerIdentityRejection input = none

def nativeMinerIdentityPreconditions (input : NativeMinerIdentityInput) : Bool :=
  isGenesis input ||
    (publicKeyLengthMatches input &&
      input.publicKeyBytesParse &&
      input.minerCommitmentMatches &&
      signatureLengthMatches input &&
      input.signatureBytesParse &&
      input.signatureVerifies)

theorem accepts_iff_native_miner_identity_preconditions
    {input : NativeMinerIdentityInput} :
    nativeMinerIdentityAccepts input = true ↔
      nativeMinerIdentityPreconditions input = true := by
  unfold nativeMinerIdentityAccepts nativeMinerIdentityPreconditions
  unfold evaluateNativeMinerIdentityRejection
  cases genesis : isGenesis input <;>
    cases pkLen : publicKeyLengthMatches input <;>
    cases pkParse : input.publicKeyBytesParse <;>
    cases commitment : input.minerCommitmentMatches <;>
    cases sigLen : signatureLengthMatches input <;>
    cases sigParse : input.signatureBytesParse <;>
    cases verifies : input.signatureVerifies <;>
    simp

def valid : NativeMinerIdentityInput :=
  {
    height := 42,
    publicKeyLen := mlDsa65PublicKeyBytes,
    signatureLen := mlDsa65SignatureBytes,
    publicKeyBytesParse := true,
    minerCommitmentMatches := true,
    signatureBytesParse := true,
    signatureVerifies := true
  }

theorem valid_accepts :
    evaluateNativeMinerIdentityRejection valid = none := by
  decide

def genesisWithoutIdentity : NativeMinerIdentityInput :=
  {
    height := 0,
    publicKeyLen := 0,
    signatureLen := 0,
    publicKeyBytesParse := false,
    minerCommitmentMatches := false,
    signatureBytesParse := false,
    signatureVerifies := false
  }

theorem genesis_accepts_without_identity :
    evaluateNativeMinerIdentityRejection genesisWithoutIdentity = none := by
  decide

def missingPublicKey : NativeMinerIdentityInput :=
  { valid with publicKeyLen := 0 }

theorem missing_public_key_rejects :
    evaluateNativeMinerIdentityRejection missingPublicKey =
      some NativeMinerIdentityReject.invalidMinerPublicKeyLength := by
  decide

def invalidPublicKeyBytes : NativeMinerIdentityInput :=
  { valid with publicKeyBytesParse := false }

theorem invalid_public_key_bytes_rejects :
    evaluateNativeMinerIdentityRejection invalidPublicKeyBytes =
      some NativeMinerIdentityReject.invalidMinerPublicKeyBytes := by
  decide

def commitmentMismatch : NativeMinerIdentityInput :=
  { valid with minerCommitmentMatches := false }

theorem commitment_mismatch_rejects :
    evaluateNativeMinerIdentityRejection commitmentMismatch =
      some NativeMinerIdentityReject.minerCommitmentMismatch := by
  decide

def missingSignature : NativeMinerIdentityInput :=
  { valid with signatureLen := 0 }

theorem missing_signature_rejects :
    evaluateNativeMinerIdentityRejection missingSignature =
      some NativeMinerIdentityReject.invalidMinerSignatureLength := by
  decide

def invalidSignatureBytes : NativeMinerIdentityInput :=
  { valid with signatureBytesParse := false }

theorem invalid_signature_bytes_rejects :
    evaluateNativeMinerIdentityRejection invalidSignatureBytes =
      some NativeMinerIdentityReject.invalidMinerSignatureBytes := by
  decide

def signatureVerificationFails : NativeMinerIdentityInput :=
  { valid with signatureVerifies := false }

theorem signature_verification_failure_rejects :
    evaluateNativeMinerIdentityRejection signatureVerificationFails =
      some NativeMinerIdentityReject.nativeMinerSignatureVerificationFailed := by
  decide

def public_key_precedes_signature_failure_input : NativeMinerIdentityInput :=
  { valid with publicKeyLen := 0, signatureLen := 0 }

theorem public_key_precedes_signature_failure :
    evaluateNativeMinerIdentityRejection public_key_precedes_signature_failure_input =
      some NativeMinerIdentityReject.invalidMinerPublicKeyLength := by
  decide

def commitment_precedes_signature_failure_input : NativeMinerIdentityInput :=
  { valid with minerCommitmentMatches := false, signatureLen := 0 }

theorem commitment_precedes_signature_failure :
    evaluateNativeMinerIdentityRejection commitment_precedes_signature_failure_input =
      some NativeMinerIdentityReject.minerCommitmentMismatch := by
  decide

end MinerIdentity
end Native
end Hegemon
