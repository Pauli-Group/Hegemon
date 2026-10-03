import SmzaRp04RawVerifierChecks
import SmzaRp04RawRecordReconstruction

/-! The full deterministic verifier-to-extraction readback uses one raw
record relation for Merkle openings and both PIOP hash checks. No independent
collision-free database or equivalence between two databases is assumed. -/
namespace HegemonCrypto.SmallWood.SmzaRp04SameDatabaseVerifier

open SmzaRp04RawVerifierChecks SmzaRp04RawRecordReconstruction
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

theorem same_database_verifier_checks_supply_accepted_checks
    (publicWords : List Nat)
    (records : V8Smz9CoherentMerkleGeometry.Records
      V8SmzaOracleParser.RawInput V8SmzaOracleParser.RawDigest)
    (collisionFree : RecordsCollisionFree records)
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
    (commitmentPrefix digest : V8SmzaOracleParser.RawDigest)
    (recordedBefore : (rawInputOf
      (transcriptInput commitmentPrefix response), digest) ∈ records)
    (recordedAfter : (rawInputOf (transcriptInput commitmentPrefix
      (reconstructedTranscript opening high
        (verifierEvaluationTrace publicWords matrix opening witness masks)
        (publicBatchedTarget publicWords matrix))), digest) ∈ records) :
    AcceptedChecks publicWords
      (rootOracle (extract rawOnlineNext records fuel .root root)) decsResponse
      (verifierStrategy publicWords response decsPrefix witness masks partials high tails)
      coefficients matrix opening query := by
  constructor
  · exact raw_five_checks_supply_query_acceptance claims collisionFree fuel
      enough decsResponse coefficients five
  · exact reconstructed_decs_heads_supply_head_binding decsPrefix
      (baseOpeningPoints opening.1) witness masks partials tails
  · exact raw_twelve_checks_supply_oracle_opening_checks claims collisionFree
      fuel enough (baseOpeningPoints opening.1) _ twelve
  · intro source _recovered
    exact one_raw_record_reconstruction_binds_every_source records collisionFree
      commitmentPrefix digest publicWords matrix response opening witness masks high
      recordedBefore recordedAfter source.data

end
end HegemonCrypto.SmallWood.SmzaRp04SameDatabaseVerifier
