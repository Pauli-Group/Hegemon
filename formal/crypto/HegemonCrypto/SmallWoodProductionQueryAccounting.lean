import HegemonCrypto.SmallWoodProductionTranscriptRefinement

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
# Exact production SHA-512 query accounting

The logical four-round transcript hides two operational details that matter to a QROM accounting:

* one field-XOF request consumes as many SHA-512 counter blocks as rejection sampling needs; and
* canonical PIOP opening selection evaluates every nonce through the first valid nonce.

This module records the successful native block scan for every such request.  Its query total is
the exact sum of the executed SHA-512 calls, not the output-word lower bound.  Each scan also
refines to the prefix-consistent logical field oracle used by the round-by-round proof.
-/

namespace HegemonCrypto.SmallWood.ProductionQueryAccounting

open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.PiopOpeningSampling
open HegemonCrypto.SmallWood.ProductionTranscriptRefinement
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript

noncomputable section

def productionDecsChallengeSeedWords
    (rawOracle : RawOracle)
    (transcript : Transcript) : List Word :=
  (rawMerkleRootDigest rawOracle transcript.commitment
    transcript.statementBindingWords).words

def productionPiopChallengeSeedWords
    (rawOracle : RawOracle)
    (transcript : Transcript) : List Word :=
  (rawHashFpp rawOracle transcript.commitment
    transcript.statementBindingWords).words

def productionPiopOpeningSeedWords
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (nonce : Fin piopNonceTrialBound) : List Word :=
  activeNonceWord nonce ::
    (rawPiopDigest rawOracle transcript.commitment
      transcript.statementBindingWords transcript.piop).words

def productionDecsOpeningSeedWords
    (rawOracle : RawOracle)
    (transcript : Transcript) : List Word :=
  (rawDecsOpeningDigest rawOracle
    (rawPiopDigest rawOracle transcript.commitment
      transcript.statementBindingWords transcript.piop)
    transcript.opening).words

def productionDecsChallengeOutputCount : Nat :=
  decsEta * lvcsRowCount

def productionPiopChallengeOutputCount (statement : Statement) : Nat :=
  rho *
    productionPiopRowWidth
      statement.nonlinearConstraintCount statement.linearConstraintCount

theorem production_decs_challenge_output_count :
    productionDecsChallengeOutputCount = 690 := by
  decide

def productionOpeningAttemptCount (selectedNonce : Fin piopNonceTrialBound) : Nat :=
  selectedNonce.val + 1

def productionOpeningAttemptNonce
    (selectedNonce : Fin piopNonceTrialBound)
    (attempt : Fin (productionOpeningAttemptCount selectedNonce)) :
    Fin piopNonceTrialBound :=
  ⟨attempt.val, by
    have attemptBound := attempt.isLt
    have selectedBound := selectedNonce.isLt
    unfold productionOpeningAttemptCount at attemptBound
    omega⟩

/--
Every successful native field-XOF execution on an accepted transcript.  The opening scans are
indexed by exactly the attempted nonce range `0 .. selectedNonce`, inclusive.
-/
structure NativeAcceptedTranscriptScans
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (statement : Statement) where
  selectedNonce : Fin piopNonceTrialBound
  decsChallenge :
    NativeBlockScan rawOracle decsCoefficientDomain
      (productionDecsChallengeSeedWords rawOracle transcript)
      productionDecsChallengeOutputCount
  piopChallenge :
    NativeBlockScan rawOracle piopCoefficientDomain
      (productionPiopChallengeSeedWords rawOracle transcript)
      (productionPiopChallengeOutputCount statement)
  piopOpening :
    (attempt : Fin (productionOpeningAttemptCount selectedNonce)) ->
      NativeBlockScan rawOracle piopOpeningDomain
        (productionPiopOpeningSeedWords rawOracle transcript
          (productionOpeningAttemptNonce selectedNonce attempt))
        openedEvaluations
  decsOpening :
    NativeBlockScan rawOracle decsFixedSamplingDomain
      (productionDecsOpeningSeedWords rawOracle transcript)
      activeDecsFixedCandidateCount

/--
Accepted scan package tied to the verifier's first-valid transmitted nonce.  Keeping the equality
outside the dependent scan structure avoids hiding a cast while still ruling out accounting a
shorter or unrelated nonce range.
-/
structure CanonicalNativeAcceptedTranscriptScans
    (rawOracle : RawOracle)
    (transcript : Transcript)
    (statement : Statement) where
  canonicalNonce : ProductionCanonicalOpeningNonce rawOracle transcript
  scans : NativeAcceptedTranscriptScans rawOracle transcript statement
  selectedNonce_eq :
    scans.selectedNonce = productionNonceIndex canonicalNonce

theorem canonical_scan_selected_nonce_word
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (canonicalScans :
      CanonicalNativeAcceptedTranscriptScans rawOracle transcript statement) :
    activeNonceWord canonicalScans.scans.selectedNonce =
      transcript.openingNonce := by
  rw [canonicalScans.selectedNonce_eq]
  exact active_nonce_word_productionNonceIndex canonicalScans.canonicalNonce

theorem canonical_scan_attempt_count
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (canonicalScans :
      CanonicalNativeAcceptedTranscriptScans rawOracle transcript statement) :
    productionOpeningAttemptCount canonicalScans.scans.selectedNonce =
      transcript.openingNonce.val + 1 := by
  unfold productionOpeningAttemptCount
  have selectedWord :=
    canonical_scan_selected_nonce_word canonicalScans
  exact congrArg (fun nonce : Word => nonce.val + 1) selectedWord

def openingDigestCalls
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    Nat :=
  ∑ attempt : Fin (productionOpeningAttemptCount scans.selectedNonce),
    (scans.piopOpening attempt).digestCalls

/-- Exact number of physical SHA-512 calls made by all challenge-producing scans. -/
def physicalDigestCalls
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    Nat :=
  scans.decsChallenge.digestCalls +
    scans.piopChallenge.digestCalls +
    openingDigestCalls scans +
    scans.decsOpening.digestCalls

def openingQueryPreimages
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    List (List CanonicalBytes.Byte) :=
  (List.ofFn fun attempt : Fin (productionOpeningAttemptCount scans.selectedNonce) =>
      queriedBlockPreimages piopOpeningDomain
        (productionPiopOpeningSeedWords rawOracle transcript
          (productionOpeningAttemptNonce scans.selectedNonce attempt))
        (scans.piopOpening attempt).digestCalls).flatten

/-- Exact ordered physical SHA-512 request ledger for the four challenge stages. -/
def physicalQueryPreimages
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    List (List CanonicalBytes.Byte) :=
  queriedBlockPreimages decsCoefficientDomain
      (productionDecsChallengeSeedWords rawOracle transcript)
      scans.decsChallenge.digestCalls
    ++ queriedBlockPreimages piopCoefficientDomain
      (productionPiopChallengeSeedWords rawOracle transcript)
      scans.piopChallenge.digestCalls
    ++ openingQueryPreimages scans
    ++ queriedBlockPreimages decsFixedSamplingDomain
      (productionDecsOpeningSeedWords rawOracle transcript)
      scans.decsOpening.digestCalls

theorem opening_query_preimages_length
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    (openingQueryPreimages scans).length = openingDigestCalls scans := by
  classical
  simp only [openingQueryPreimages, List.length_flatten, List.map_ofFn,
    List.sum_ofFn, openingDigestCalls]
  apply Finset.sum_congr rfl
  intro attempt _
  exact queriedBlockPreimages_length _ _ _

theorem physical_query_preimages_length
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    (physicalQueryPreimages scans).length = physicalDigestCalls scans := by
  simp only [physicalQueryPreimages, List.length_append,
    queriedBlockPreimages_length, opening_query_preimages_length,
    physicalDigestCalls]

theorem every_piop_opening_scan_is_nodup
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement)
    (attempt : Fin (productionOpeningAttemptCount scans.selectedNonce)) :
    (queriedBlockPreimages piopOpeningDomain
      (productionPiopOpeningSeedWords rawOracle transcript
        (productionOpeningAttemptNonce scans.selectedNonce attempt))
      (scans.piopOpening attempt).digestCalls).Nodup :=
  (scans.piopOpening attempt).queried_raw_digest_preimages_nodup

theorem decs_challenge_scan_refines_logical_oracle
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    fieldHashWords (productionFieldOracle rawOracle)
        decsCoefficientDomain
        (productionDecsChallengeSeedWords rawOracle transcript)
        productionDecsChallengeOutputCount =
      scans.decsChallenge.output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    rawOracle decsCoefficientDomain
      (productionDecsChallengeSeedWords rawOracle transcript)
      productionDecsChallengeOutputCount
      scans.decsChallenge.toOutputPrefix

theorem piop_challenge_scan_refines_logical_oracle
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    fieldHashWords (productionFieldOracle rawOracle)
        piopCoefficientDomain
        (productionPiopChallengeSeedWords rawOracle transcript)
        (productionPiopChallengeOutputCount statement) =
      scans.piopChallenge.output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    rawOracle piopCoefficientDomain
      (productionPiopChallengeSeedWords rawOracle transcript)
      (productionPiopChallengeOutputCount statement)
      scans.piopChallenge.toOutputPrefix

theorem piop_opening_scan_refines_logical_oracle
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement)
    (attempt : Fin (productionOpeningAttemptCount scans.selectedNonce)) :
    fieldHashWords (productionFieldOracle rawOracle)
        piopOpeningDomain
        (productionPiopOpeningSeedWords rawOracle transcript
          (productionOpeningAttemptNonce scans.selectedNonce attempt))
        openedEvaluations =
      (scans.piopOpening attempt).output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    rawOracle piopOpeningDomain
      (productionPiopOpeningSeedWords rawOracle transcript
        (productionOpeningAttemptNonce scans.selectedNonce attempt))
      openedEvaluations
      (scans.piopOpening attempt).toOutputPrefix

theorem decs_opening_scan_refines_logical_oracle
    {rawOracle : RawOracle}
    {transcript : Transcript}
    {statement : Statement}
    (scans :
      NativeAcceptedTranscriptScans rawOracle transcript statement) :
    fieldHashWords (productionFieldOracle rawOracle)
        decsFixedSamplingDomain
        (productionDecsOpeningSeedWords rawOracle transcript)
        activeDecsFixedCandidateCount =
      scans.decsOpening.output := by
  exact fieldHashWords_logicalFieldOracleOfRaw_eq_bounded_output
    rawOracle decsFixedSamplingDomain
      (productionDecsOpeningSeedWords rawOracle transcript)
      activeDecsFixedCandidateCount
      scans.decsOpening.toOutputPrefix

end

end HegemonCrypto.SmallWood.ProductionQueryAccounting
