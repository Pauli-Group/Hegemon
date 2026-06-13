import Hegemon.Wallet.NoteCiphertextWire

namespace Hegemon
namespace Wallet
namespace NoteCiphertextDecrypt

open NoteCiphertextWire

structure DecryptMaterialSummary where
  version : Nat
  cryptoSuite : Nat
  diversifierIndex : Nat
deriving DecidableEq, Repr

structure DecryptAttempt where
  ciphertext : NoteCiphertextSummary
  material : DecryptMaterialSummary
  cryptoAuthenticates : Bool
deriving DecidableEq, Repr

inductive DecryptRejection where
  | versionMismatch
  | cryptoSuiteMismatch
  | diversifierMismatch
  | cryptoFailure
deriving DecidableEq, Repr

def evaluateDecrypt (attempt : DecryptAttempt) : Option DecryptRejection :=
  if attempt.ciphertext.version = attempt.material.version then
    if attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite then
      if attempt.ciphertext.diversifierIndex = attempt.material.diversifierIndex then
        if attempt.cryptoAuthenticates then
          none
        else
          some DecryptRejection.cryptoFailure
      else
        some DecryptRejection.diversifierMismatch
    else
      some DecryptRejection.cryptoSuiteMismatch
  else
    some DecryptRejection.versionMismatch

def sampleCiphertextSummary : NoteCiphertextSummary :=
  {
    version := 3,
    cryptoSuite := cryptoSuiteGamma,
    diversifierIndex := 7,
    kemLen := mlKemCiphertextLen,
    notePayloadLen := 112 + 16,
    memoPayloadLen := 4 + 16
  }

def sampleMaterialSummary : DecryptMaterialSummary :=
  {
    version := 3,
    cryptoSuite := cryptoSuiteGamma,
    diversifierIndex := 7
  }

def sampleAcceptedAttempt : DecryptAttempt :=
  {
    ciphertext := sampleCiphertextSummary,
    material := sampleMaterialSummary,
    cryptoAuthenticates := true
  }

def sampleWrongVersionAttempt : DecryptAttempt :=
  {
    sampleAcceptedAttempt with
    ciphertext := { sampleCiphertextSummary with version := 4 }
  }

def sampleWrongSuiteAttempt : DecryptAttempt :=
  {
    sampleAcceptedAttempt with
    ciphertext := { sampleCiphertextSummary with cryptoSuite := cryptoSuiteGamma + 1 }
  }

def sampleWrongDiversifierAttempt : DecryptAttempt :=
  {
    sampleAcceptedAttempt with
    ciphertext := { sampleCiphertextSummary with diversifierIndex := 8 }
  }

def sampleCryptoFailureAttempt : DecryptAttempt :=
  {
    sampleAcceptedAttempt with
    cryptoAuthenticates := false
  }

theorem decrypt_valid_accepts :
    evaluateDecrypt sampleAcceptedAttempt = none := by
  decide

theorem decrypt_wrong_version_rejects :
    evaluateDecrypt sampleWrongVersionAttempt =
      some DecryptRejection.versionMismatch := by
  decide

theorem decrypt_wrong_crypto_suite_rejects :
    evaluateDecrypt sampleWrongSuiteAttempt =
      some DecryptRejection.cryptoSuiteMismatch := by
  decide

theorem decrypt_wrong_diversifier_rejects :
    evaluateDecrypt sampleWrongDiversifierAttempt =
      some DecryptRejection.diversifierMismatch := by
  decide

theorem decrypt_crypto_failure_rejects :
    evaluateDecrypt sampleCryptoFailureAttempt =
      some DecryptRejection.cryptoFailure := by
  decide

theorem decrypt_admission_rejects_version_mismatch
    {attempt : DecryptAttempt}
    (versionMismatch : attempt.ciphertext.version ≠ attempt.material.version) :
    evaluateDecrypt attempt = some DecryptRejection.versionMismatch := by
  simp [evaluateDecrypt, versionMismatch]

theorem decrypt_admission_rejects_crypto_suite_mismatch
    {attempt : DecryptAttempt}
    (versionMatches : attempt.ciphertext.version = attempt.material.version)
    (suiteMismatch : attempt.ciphertext.cryptoSuite ≠ attempt.material.cryptoSuite) :
    evaluateDecrypt attempt = some DecryptRejection.cryptoSuiteMismatch := by
  simp [evaluateDecrypt, versionMatches, suiteMismatch]

theorem decrypt_admission_rejects_diversifier_mismatch
    {attempt : DecryptAttempt}
    (versionMatches : attempt.ciphertext.version = attempt.material.version)
    (suiteMatches : attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite)
    (diversifierMismatch :
      attempt.ciphertext.diversifierIndex ≠ attempt.material.diversifierIndex) :
    evaluateDecrypt attempt = some DecryptRejection.diversifierMismatch := by
  simp [evaluateDecrypt, versionMatches, suiteMatches, diversifierMismatch]

theorem wrong_recipient_or_malleated_ciphertext_fails_under_crypto_assumptions
    {attempt : DecryptAttempt}
    (versionMatches : attempt.ciphertext.version = attempt.material.version)
    (suiteMatches : attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite)
    (diversifierMatches :
      attempt.ciphertext.diversifierIndex = attempt.material.diversifierIndex)
    (cryptoDoesNotAuthenticate : attempt.cryptoAuthenticates = false) :
    evaluateDecrypt attempt = some DecryptRejection.cryptoFailure := by
  simp [
    evaluateDecrypt,
    versionMatches,
    suiteMatches,
    diversifierMatches,
    cryptoDoesNotAuthenticate
  ]

theorem decrypt_success_implies_metadata_matches
    {attempt : DecryptAttempt}
    (accepted : evaluateDecrypt attempt = none) :
    attempt.ciphertext.version = attempt.material.version
      ∧ attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite
      ∧ attempt.ciphertext.diversifierIndex = attempt.material.diversifierIndex
      ∧ attempt.cryptoAuthenticates = true := by
  unfold evaluateDecrypt at accepted
  by_cases versionMatches : attempt.ciphertext.version = attempt.material.version
  · by_cases suiteMatches : attempt.ciphertext.cryptoSuite = attempt.material.cryptoSuite
    · by_cases diversifierMatches :
        attempt.ciphertext.diversifierIndex = attempt.material.diversifierIndex
      · by_cases cryptoAuthenticates : attempt.cryptoAuthenticates = true
        · exact ⟨versionMatches, suiteMatches, diversifierMatches, cryptoAuthenticates⟩
        · simp [versionMatches, suiteMatches, diversifierMatches, cryptoAuthenticates] at accepted
      · simp [versionMatches, suiteMatches, diversifierMatches] at accepted
    · simp [versionMatches, suiteMatches] at accepted
  · simp [versionMatches] at accepted

end NoteCiphertextDecrypt
end Wallet
end Hegemon
