namespace Hegemon
namespace Consensus

def mlDsa65SignatureBytes : Nat := 3309

inductive PowMinerIdentityReject where
  | powHeaderSignatureBitmap
  | unregisteredPowMiner
  | invalidPowMinerSignatureLength
  | invalidPowMinerSignatureBytes
  | powMinerSignatureVerificationFailed
deriving DecidableEq, Repr

structure PowMinerIdentityInput where
  hasSignatureBitmap : Bool
  minerRegistered : Bool
  signatureLen : Nat
  signatureBytesParse : Bool
  signatureVerifies : Bool
deriving DecidableEq, Repr

def evaluatePowMinerIdentity
    (input : PowMinerIdentityInput) : Option PowMinerIdentityReject :=
  if input.hasSignatureBitmap then
    some PowMinerIdentityReject.powHeaderSignatureBitmap
  else if !input.minerRegistered then
    some PowMinerIdentityReject.unregisteredPowMiner
  else if input.signatureLen != mlDsa65SignatureBytes then
    some PowMinerIdentityReject.invalidPowMinerSignatureLength
  else if !input.signatureBytesParse then
    some PowMinerIdentityReject.invalidPowMinerSignatureBytes
  else if !input.signatureVerifies then
    some PowMinerIdentityReject.powMinerSignatureVerificationFailed
  else
    none

theorem powMinerIdentity_accepts_valid
    {input : PowMinerIdentityInput}
    (noBitmap : input.hasSignatureBitmap = false)
    (registered : input.minerRegistered = true)
    (lengthOk : input.signatureLen = mlDsa65SignatureBytes)
    (parseOk : input.signatureBytesParse = true)
    (verifyOk : input.signatureVerifies = true) :
    evaluatePowMinerIdentity input = none := by
  unfold evaluatePowMinerIdentity
  simp [noBitmap, registered, lengthOk, parseOk, verifyOk]

theorem powMinerIdentity_rejects_signature_bitmap
    {input : PowMinerIdentityInput}
    (hasBitmap : input.hasSignatureBitmap = true) :
    evaluatePowMinerIdentity input =
      some PowMinerIdentityReject.powHeaderSignatureBitmap := by
  unfold evaluatePowMinerIdentity
  simp [hasBitmap]

theorem powMinerIdentity_rejects_unregistered
    {input : PowMinerIdentityInput}
    (noBitmap : input.hasSignatureBitmap = false)
    (unregistered : input.minerRegistered = false) :
    evaluatePowMinerIdentity input =
      some PowMinerIdentityReject.unregisteredPowMiner := by
  unfold evaluatePowMinerIdentity
  simp [noBitmap, unregistered]

theorem powMinerIdentity_rejects_bad_signature_length
    {input : PowMinerIdentityInput}
    (noBitmap : input.hasSignatureBitmap = false)
    (registered : input.minerRegistered = true)
    (lengthMismatch : input.signatureLen != mlDsa65SignatureBytes) :
    evaluatePowMinerIdentity input =
      some PowMinerIdentityReject.invalidPowMinerSignatureLength := by
  unfold evaluatePowMinerIdentity
  simp [noBitmap, registered, lengthMismatch]

theorem powMinerIdentity_rejects_bad_signature_bytes
    {input : PowMinerIdentityInput}
    (noBitmap : input.hasSignatureBitmap = false)
    (registered : input.minerRegistered = true)
    (lengthOk : input.signatureLen = mlDsa65SignatureBytes)
    (parseFailed : input.signatureBytesParse = false) :
    evaluatePowMinerIdentity input =
      some PowMinerIdentityReject.invalidPowMinerSignatureBytes := by
  unfold evaluatePowMinerIdentity
  simp [noBitmap, registered, lengthOk, parseFailed]

theorem powMinerIdentity_rejects_failed_signature_verification
    {input : PowMinerIdentityInput}
    (noBitmap : input.hasSignatureBitmap = false)
    (registered : input.minerRegistered = true)
    (lengthOk : input.signatureLen = mlDsa65SignatureBytes)
    (parseOk : input.signatureBytesParse = true)
    (verifyFailed : input.signatureVerifies = false) :
    evaluatePowMinerIdentity input =
      some PowMinerIdentityReject.powMinerSignatureVerificationFailed := by
  unfold evaluatePowMinerIdentity
  simp [noBitmap, registered, lengthOk, parseOk, verifyFailed]

end Consensus
end Hegemon
