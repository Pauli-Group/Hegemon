import SmzaRp04RawAcceptedOpeningChecks
import SmzaRp04RawHeadReadback
import SmzaRp04PublicTargetReadback

/-! Assemble accepted-extraction checks from the verifier's concrete scalar
equations and recorded raw hashes. Head binding and every-source restored
transcript equality are conclusions, not additional acceptance assumptions. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RawVerifierChecks

open HegemonCrypto.FiniteOracleDatabase
open SmzaRp04RawAcceptedOpeningChecks SmzaRp04RawHeadReadback
open SmzaRp04PublicTargetReadback SmzaRp04RawRecordedTranscript
open SmzaRp04RecordedTranscript SmzaRp04TracePrefixes
open SmzaRp04RawDecsReadback SmzaRp04ChronologicalAlgebra
open SmzaRp04PublicContext SmzaRecordedTracePath SmzaRawStageGeometry
open SmzaQ38McaSourceBinding SmzaQ38LvcsOpening
open V8Smz9CoherentMerkleGeometry V8Smz9PiopSoundness
open V8Smz9PiopReconstruction V8Smz9AdaptiveFiniteAccounting
open V8Smz9ZeroKnowledge V8Smz9EagerPrivacy V8Smz9EagerSimulator

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

def verifierStrategy (publicWords : List Nat) (response : ClaimedTranscript)
    (decsPrefix : V8Smz9HonestWholeViewFinalInput.Prefix)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks) (high : ProofHighs)
    (tails : Fin 12 → Fin 38 → Goldilocks) : Strategy publicWords where
  piopResponse _ _ := response
  afterOpening _ matrix opening :=
    { witness := witness
      masks := masks
      partials := partials
      nonlinearHigh := fun row => nonlinearHighPart (high.nonlinear row)
      linearHigh := fun row => linearHighPart (high.linear row)
      correction := publicCorrection publicWords matrix opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
      claimedCoefficients := queryCoefficients ⟨.decs, decsPayload decsPrefix
        (reconstructedWireEvaluations (baseOpeningPoints opening.1)
          witness masks partials tails)⟩ }

theorem recorded_raw_verifier_checks_supply_accepted_checks
    (publicWords : List Nat)
    (records : V8Smz9CoherentMerkleGeometry.Records
      V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (recordCollisionFree : RecordsCollisionFree records)
    (root : V8SmzaOracleParser.RawDigest) (query : Query)
    (claims : RawQueryReadback records root query)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (decsResponse : ResponseStrategy) (coefficients : Coefficients)
    (response : ClaimedTranscript) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) (decsPrefix : V8Smz9HonestWholeViewFinalInput.Prefix)
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (partials : SourcePcsView Goldilocks) (high : ProofHighs)
    (tails : Fin 12 → Fin 38 → Goldilocks)
    (five : RawFiveMcaChecks claims decsResponse coefficients)
    (twelve : RawTwelveLvcsChecks claims (baseOpeningPoints opening.1)
      (claimedPolynomials (queryCoefficients ⟨.decs, decsPayload decsPrefix
        (reconstructedWireEvaluations (baseOpeningPoints opening.1)
          witness masks partials tails)⟩)))
    (database : Database V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (databaseCollisionFree : CollisionFree database)
    (commitmentPrefix digest : V8SmzaOracleParser.RawDigest)
    (recordedBefore : database (rawInputOf
      (transcriptInput commitmentPrefix response)) = some digest)
    (recordedAfter : database (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (publicBatchedTarget publicWords matrix)))) = some digest) :
    AcceptedChecks publicWords
      (rootOracle (extract rawOnlineNext records fuel .root root)) decsResponse
      (verifierStrategy publicWords response decsPrefix witness masks partials high tails)
      coefficients matrix opening query := by
  constructor
  · exact raw_five_checks_supply_query_acceptance claims recordCollisionFree fuel
      enough decsResponse coefficients five
  · exact reconstructed_decs_heads_supply_head_binding decsPrefix
      (baseOpeningPoints opening.1) witness masks partials tails
  · exact raw_twelve_checks_supply_oracle_opening_checks claims recordCollisionFree
      fuel enough (baseOpeningPoints opening.1) _ twelve
  · intro source _recovered
    exact one_recorded_reconstruction_binds_every_recovered_source database
      databaseCollisionFree commitmentPrefix digest publicWords matrix response opening
      witness masks high recordedBefore recordedAfter source.data

end
end HegemonCrypto.SmallWood.SmzaRp04RawVerifierChecks
