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

structure ChainCiphertextDecryptBoundaryFacts
    (wire : List Byte)
    (summary : NoteCiphertextSummary)
    (material : DecryptMaterialSummary)
    (cryptoAuthenticates : Bool) : Prop where
  parsedChainWire :
    parseChainNoteCiphertext wire = some summary
  chainFormat :
    summary.cryptoSuite = cryptoSuiteGamma
      ∧ summary.kemLen = mlKemCiphertextLen
  supportedVersion :
    summary.version = noteEncryptionVersion
  fixedChainWireLength :
    wire.length =
      chainCiphertextSize + chainCompactKemLen.length + mlKemCiphertextLen
  projectedDaBytes :
    ∃ daBytes,
      projectChainDaBytes wire = some daBytes
        ∧ daBytes.length = chainCiphertextSize + mlKemCiphertextLen
  projectedDaParsesAsSameSummary :
    ∃ daBytes,
      projectChainDaBytes wire = some daBytes
        ∧ parseDaNoteCiphertext daBytes = some summary
        ∧ daBytes.length = chainCiphertextSize + mlKemCiphertextLen
  metadataMatches :
    summary.version = material.version
      ∧ summary.cryptoSuite = material.cryptoSuite
      ∧ summary.diversifierIndex = material.diversifierIndex
  cryptoAuthenticatesAccepted :
    cryptoAuthenticates = true

structure NoteCiphertextPrimitiveResidualAssumptions where
  mlKemIndCcaSecurity : Prop
  aeadCiphertextSecurity : Prop
  walletKdfDomainSeparation : Prop
  encryptionRngFreshness : Prop

structure ChainCiphertextDecryptDaHashResidualCertificate
    (wire daBytes publicCiphertextHash : List Byte)
    (summary : NoteCiphertextSummary)
    (material : DecryptMaterialSummary)
    (cryptoAuthenticates : Bool)
    (ciphertextHashMatches : List Byte -> List Byte -> Prop)
    (residuals : NoteCiphertextPrimitiveResidualAssumptions) :
    Prop where
  decryptBoundary :
    ChainCiphertextDecryptBoundaryFacts
      wire
      summary
      material
      cryptoAuthenticates
  daHashBoundary :
    ChainDaHashCommitmentBoundaryFacts
      wire
      daBytes
      publicCiphertextHash
      summary
      ciphertextHashMatches
  mlKemIndCcaSecurity :
    residuals.mlKemIndCcaSecurity
  aeadCiphertextSecurity :
    residuals.aeadCiphertextSecurity
  walletKdfDomainSeparation :
    residuals.walletKdfDomainSeparation
  encryptionRngFreshness :
    residuals.encryptionRngFreshness

def productionAadBytesFromMaterial
    (material : DecryptMaterialSummary) : List Byte :=
  [material.version]
    ++ u16le material.cryptoSuite
    ++ u32le material.diversifierIndex

structure ChainCiphertextProductionDecryptEquivalenceFacts
    (wire daBytes publicCiphertextHash : List Byte)
    (summary : NoteCiphertextSummary)
    (material : DecryptMaterialSummary)
    (cryptoAuthenticates : Bool)
    (ciphertextHashMatches : List Byte -> List Byte -> Prop)
    (residuals : NoteCiphertextPrimitiveResidualAssumptions) :
    Prop where
  decryptDaHashResidualCertificate :
    ChainCiphertextDecryptDaHashResidualCertificate
      wire
      daBytes
      publicCiphertextHash
      summary
      material
      cryptoAuthenticates
      ciphertextHashMatches
      residuals
  productionWireProfile :
    NoteCiphertextProductionWireProfile summary
  productionAadMatchesDecryptMaterial :
    productionAadBytes summary = productionAadBytesFromMaterial material
  productionAadLength :
    (productionAadBytesFromMaterial material).length =
      noteCiphertextMetadataAadLen
  malformedCiphertextsFailClosed :
    NoteCiphertextMalformedFailClosedFacts

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

theorem accepted_chain_ciphertext_decrypt_binds_wire_parser_metadata
    {wire : List Byte}
    {summary : NoteCiphertextSummary}
    {material : DecryptMaterialSummary}
    {cryptoAuthenticates : Bool}
    (bounded : bytesBounded wire)
    (parsed : parseChainNoteCiphertext wire = some summary)
    (accepted :
      evaluateDecrypt
        {
          ciphertext := summary,
          material := material,
          cryptoAuthenticates := cryptoAuthenticates
        } = none) :
    ChainCiphertextDecryptBoundaryFacts
      wire
      summary
      material
      cryptoAuthenticates := by
  have decryptFacts :=
    decrypt_success_implies_metadata_matches accepted
  exact {
    parsedChainWire := parsed
    chainFormat :=
      parsed_chain_ciphertext_has_gamma_suite_and_fixed_kem parsed
    supportedVersion :=
      parsed_chain_ciphertext_has_supported_version parsed
    fixedChainWireLength :=
      parsed_chain_ciphertext_has_fixed_wire_length_of_bounded
        bounded
        parsed
    projectedDaBytes :=
      parsed_chain_ciphertext_has_projected_da_bytes_of_bounded
        bounded
        parsed
    projectedDaParsesAsSameSummary :=
      parsed_chain_ciphertext_projected_da_parses_same_summary_of_bounded
        bounded
        parsed
    metadataMatches :=
      ⟨decryptFacts.left,
        decryptFacts.right.left,
        decryptFacts.right.right.left⟩
    cryptoAuthenticatesAccepted :=
      decryptFacts.right.right.right
  }

theorem accepted_chain_ciphertext_decrypt_binds_da_hash_and_residuals
    {wire daBytes publicCiphertextHash : List Byte}
    {summary : NoteCiphertextSummary}
    {material : DecryptMaterialSummary}
    {cryptoAuthenticates : Bool}
    {ciphertextHashMatches : List Byte -> List Byte -> Prop}
    {residuals : NoteCiphertextPrimitiveResidualAssumptions}
    (bounded : bytesBounded wire)
    (parsed : parseChainNoteCiphertext wire = some summary)
    (projected : projectChainDaBytes wire = some daBytes)
    (accepted :
      evaluateDecrypt
        {
          ciphertext := summary,
          material := material,
          cryptoAuthenticates := cryptoAuthenticates
        } = none)
    (hashMatches : ciphertextHashMatches daBytes publicCiphertextHash)
    (mlKemAssumption : residuals.mlKemIndCcaSecurity)
    (aeadAssumption : residuals.aeadCiphertextSecurity)
    (kdfAssumption : residuals.walletKdfDomainSeparation)
    (rngAssumption : residuals.encryptionRngFreshness) :
    ChainCiphertextDecryptDaHashResidualCertificate
      wire
      daBytes
      publicCiphertextHash
      summary
      material
      cryptoAuthenticates
      ciphertextHashMatches
      residuals := by
  exact {
    decryptBoundary :=
      accepted_chain_ciphertext_decrypt_binds_wire_parser_metadata
        bounded
        parsed
        accepted
    daHashBoundary :=
      accepted_chain_ciphertext_binds_da_hash_preimage_of_bounded
        bounded
        parsed
        projected
        hashMatches
    mlKemIndCcaSecurity := mlKemAssumption
    aeadCiphertextSecurity := aeadAssumption
    walletKdfDomainSeparation := kdfAssumption
    encryptionRngFreshness := rngAssumption
  }

theorem accepted_chain_ciphertext_decrypt_binds_production_serialization_profile
    {wire daBytes publicCiphertextHash : List Byte}
    {summary : NoteCiphertextSummary}
    {material : DecryptMaterialSummary}
    {cryptoAuthenticates : Bool}
    {ciphertextHashMatches : List Byte -> List Byte -> Prop}
    {residuals : NoteCiphertextPrimitiveResidualAssumptions}
    (bounded : bytesBounded wire)
    (parsed : parseChainNoteCiphertext wire = some summary)
    (projected : projectChainDaBytes wire = some daBytes)
    (accepted :
      evaluateDecrypt
        {
          ciphertext := summary,
          material := material,
          cryptoAuthenticates := cryptoAuthenticates
        } = none)
    (hashMatches : ciphertextHashMatches daBytes publicCiphertextHash)
    (mlKemAssumption : residuals.mlKemIndCcaSecurity)
    (aeadAssumption : residuals.aeadCiphertextSecurity)
    (kdfAssumption : residuals.walletKdfDomainSeparation)
    (rngAssumption : residuals.encryptionRngFreshness) :
    ChainCiphertextProductionDecryptEquivalenceFacts
      wire
      daBytes
      publicCiphertextHash
      summary
      material
      cryptoAuthenticates
      ciphertextHashMatches
      residuals := by
  have decryptFacts :=
    decrypt_success_implies_metadata_matches accepted
  rcases decryptFacts with
    ⟨versionMatches, suiteMatches, diversifierMatches, _cryptoAccepted⟩
  exact {
    decryptDaHashResidualCertificate :=
      accepted_chain_ciphertext_decrypt_binds_da_hash_and_residuals
        bounded
        parsed
        projected
        accepted
        hashMatches
        mlKemAssumption
        aeadAssumption
        kdfAssumption
        rngAssumption
    productionWireProfile :=
      parsed_chain_ciphertext_binds_production_wire_profile parsed
    productionAadMatchesDecryptMaterial := by
      unfold productionAadBytes productionAadBytesFromMaterial
      rw [versionMatches, suiteMatches, diversifierMatches]
    productionAadLength := by
      simp [
        productionAadBytesFromMaterial,
        noteCiphertextMetadataAadLen,
        u16le_length,
        u32le_length
      ]
    malformedCiphertextsFailClosed :=
      note_ciphertext_wire_malformed_fixtures_fail_closed
  }

end NoteCiphertextDecrypt
end Wallet
end Hegemon
