import Hegemon.Consensus.AcceptedSmallWoodBlockComposition
import HegemonCrypto.SmallWoodCmsExtraction
import HegemonCrypto.SmallWoodProductionAcceptanceClosure

set_option maxHeartbeats 0
set_option maxRecDepth 100000

/-!
# Conditional caller-evidence to accepted block supply

This module contains two deliberately separate conditional paths:

* caller-supplied modeled-verifier evidence plus recorded-database collision freedom
  implies a good modeled transition; and
* caller-supplied modeled-verifier evidence plus an explicit negation of
  `NoValidExtraction` and a canonical semantic-refinement assumption implies the
  transaction relation used by block composition.

The second path does not consume the first path or its collision-freedom premise. The
credited block theorem therefore names its actual assumptions: per-transaction
extraction success, semantic refinement, and separate Poseidon2 output-security
assumptions. This module neither
proves that compiled-Rust acceptance constructs the evidence nor derives extraction
success from the ideal-QROM probability theorem.
-/

namespace HegemonCrypto.SmallWood.ProductionSupplyChain

open HegemonCrypto.SecurityAuthority
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.SmallWood.BcsQrom
open HegemonCrypto.SmallWood.CmsExtraction
open HegemonCrypto.SmallWood.LogicalOracle
open HegemonCrypto.SmallWood.NativeDecsReconstruction
open HegemonCrypto.SmallWood.NativeLvcsReconstruction
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.ProductionAcceptanceClosure
open HegemonCrypto.SmallWood.ProductionAccumulatedExtraction
open HegemonCrypto.SmallWood.ProductionBcsInstantiation
open HegemonCrypto.SmallWood.ProductionMerkleExtraction
open HegemonCrypto.SmallWood.ProductionTranscriptRefinement
open HegemonCrypto.SmallWood.RoundByRound
open HegemonCrypto.SmallWood.RoundByRound.Interactive
open HegemonCrypto.SmallWood.Sha512Xof
open HegemonCrypto.SmallWoodTranscript
open Hegemon.Transaction
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Consensus.AcceptedSmallWoodBlockComposition

noncomputable section

def callerEvidenceCommittedOracle
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    CommittedOracle :=
  accumulatedCommittedOracle (acceptedTrace accepted)

def callerEvidenceDecsMessage
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    DecsPolynomialMessage :=
  reconstructNativeDecsMessage
    (productionDecsChallenge rawOracle accepted.transcript)
    accepted.coordinates
    (reconstructNativeProductionRows
      (productionPiopOpening accepted.canonicalOpeningNonce)
      accepted.pcsMessage accepted.coordinates
      accepted.baseRows accepted.maskingRows)
    accepted.nativeDecsHigh

/-- The exact final logical-oracle query represented by caller-supplied evidence. -/
def callerEvidenceFourthQuery
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    VerifierQuery statement :=
  .fourth
    { oracle := callerEvidenceCommittedOracle accepted
      decsChallenge :=
        productionDecsChallenge rawOracle accepted.transcript
      decsMessage := callerEvidenceDecsMessage accepted
      piopChallenge :=
        productionPiopChallenge rawOracle accepted.transcript statement
      piopMessage := accepted.piopMessage
      piopOpening :=
        productionPiopOpening accepted.canonicalOpeningNonce
      pcsMessage := accepted.pcsMessage }

def callerEvidenceLogicalOutput
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database) :
    LogicalOutput statement :=
  { decsChallenge :=
      productionDecsChallenge rawOracle accepted.transcript
    piopChallenge :=
      productionPiopChallenge rawOracle accepted.transcript statement
    piopOpening :=
      productionPiopOpening accepted.canonicalOpeningNonce
    decsOpening :=
      productionDecsOpening accepted.decsSamplerSucceeds }

/--
Caller-supplied modeled-verifier evidence reaches a good final transition when
the separately supplied hash-database collision-freedom premise holds. This is
not a theorem about an accepted compiled-Rust execution, and the conditional
supply theorem below does not consume this result.
-/
theorem caller_supplied_evidence_with_collision_freedom_reaches_good_state
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (hashDatabaseCollisionFree : CollisionFree database) :
    semanticState
        (verifierExtension
          (queryPrefix accepted.active (callerEvidenceFourthQuery accepted))
          (queryChallenge accepted.active
            (callerEvidenceFourthQuery accepted)
            (callerEvidenceLogicalOutput accepted))) =
      true := by
  apply (semantic_state_true_iff _).2
  simpa [callerEvidenceFourthQuery, callerEvidenceLogicalOutput, queryPrefix,
    queryChallenge, verifierExtension, SemanticGood,
    callerEvidenceCommittedOracle] using
      (caller_supplied_verifier_evidence_implies_fourth_round_good
        accepted hashDatabaseCollisionFree).holds

/--
Conditional on the explicit negation of `NoValidExtraction`, the oracle described
by caller-supplied evidence yields a witness for the exact production constraint
map. This theorem does not itself bound or discharge that premise.
-/
theorem caller_supplied_evidence_and_extraction_success_yield_exact_relation
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (extractionSucceeds :
      ¬NoValidExtraction accepted.active
        (callerEvidenceFourthQuery accepted)) :
    ∃ witness,
      (statement, witness) ∈ HegemonCrypto.SmallWood.Relation := by
  unfold NoValidExtraction at extractionSucceeds
  have extracted :
      ∃ witness,
        extractedWitnessAtPrefix
            (queryPrefix accepted.active (callerEvidenceFourthQuery accepted)) =
          some witness ∧
        ((queryPrefix accepted.active
            (callerEvidenceFourthQuery accepted)).statement, witness) ∈
          HegemonCrypto.SmallWood.Relation := by
    by_contra missing
    exact extractionSucceeds missing
  obtain ⟨witness, witnessAtPrefix, relation⟩ := extracted
  refine ⟨witness, ?_⟩
  rw [query_prefix_statement accepted.active
    (callerEvidenceFourthQuery accepted)] at relation
  exact relation

theorem caller_supplied_evidence_and_extraction_success_yield_exact_constraints
    {proofBytes : List HegemonCrypto.CanonicalBytes.Byte}
    {statement : Statement}
    {rawOracle : RawOracle}
    {fallback : ActiveDigest}
    {database : ProductionHashDatabase}
    (accepted :
      CallerSuppliedVerifierEvidence
        proofBytes statement rawOracle fallback database)
    (extractionSucceeds :
      ¬NoValidExtraction accepted.active
        (callerEvidenceFourthQuery accepted)) :
    ∃ witness,
      ProductionSmallWoodSemanticConstraintsSatisfied statement witness := by
  obtain ⟨witness, relation⟩ :=
    caller_supplied_evidence_and_extraction_success_yield_exact_relation
      accepted extractionSucceeds
  exact
    ⟨witness,
      production_smallwood_air_rows_are_implementation_equivalent
        relation.1 relation.2⟩

/--
Caller-supplied extraction-success and canonical-semantic-refinement evidence
for the same statement map and exact proof bytes as one consensus proof. The
modeled canonical bytes must decode to the exact deployed proof-byte list; this
closes byte-identity substitution without claiming compiled-verifier refinement.
Hash-database collision freedom remains absent because the conditional
extraction-to-relation proof does not consume it. This record is still not
compiled-verifier refinement evidence.
-/
structure CallerSuppliedTransactionConditionalEvidence
    (proof : DeployedSmallWoodProof) : Type where
  modeledProofBytes : List HegemonCrypto.CanonicalBytes.Byte
  modeledProofBytesMatch : modeledProofBytes.map Fin.val = proof.proofBytes
  rawOracle : RawOracle
  fallback : ActiveDigest
  database : ProductionHashDatabase
  verifierEvidence :
    CallerSuppliedVerifierEvidence modeledProofBytes proof.exactMap
      rawOracle fallback database
  extractionSucceeds :
    ¬NoValidExtraction verifierEvidence.active
      (callerEvidenceFourthQuery verifierEvidence)
  semanticRefinement :
    ProductionSmallWoodCanonicalSemanticRefinementAssumption
      proof.exactMap proof.shape proof.merkleRoot

theorem caller_supplied_extraction_and_semantic_refinement_yield_transaction_relation
    {verifier : ProductionSmallWoodProofVerifier}
    {hashes : ProductionIdentityFunctions}
    {proof : DeployedSmallWoodProof}
    (accepted :
      DeployedSmallWoodProofAccepted verifier hashes proof)
    (conditionalEvidence : CallerSuppliedTransactionConditionalEvidence proof) :
    ProductionAcceptedTransactionRelation verifier proof.exactMap
      (productionVerifierPublicValues proof.bound proof.statementFields)
      proof.shape proof.merkleRoot proof.proofBytes proof.serializedPublicInputBytes
      proof.verifierProfile proof.wrapper :=
  { wrapperAccepted := accepted.canonicalSurface.accepted
    exactProofArtifactAccepted := by
      have modeledBytesAccepted :
          verifier.accepts
              (conditionalEvidence.modeledProofBytes.map Fin.val)
              proof.serializedPublicInputBytes proof.verifierProfile proof.wrapper = true := by
        rw [conditionalEvidence.modeledProofBytesMatch]
        exact accepted.exactArtifactAccepted
      rw [← conditionalEvidence.modeledProofBytesMatch]
      exact modeledBytesAccepted
    constraintMapBound := accepted.constraintMapBound
    canonicalPublicValuesBound := accepted.constraintPublicValuesBound
    sameWitnessCanonicalSemanticClosure := by
      obtain ⟨witnessValues, exactSemanticConstraints⟩ :=
        caller_supplied_evidence_and_extraction_success_yield_exact_constraints
          conditionalEvidence.verifierEvidence
          conditionalEvidence.extractionSucceeds
      exact
        ⟨conditionalEvidence.semanticRefinement.projection,
          witnessValues,
          exactSemanticConstraints,
          conditionalEvidence.semanticRefinement.exactRowsRefine
            witnessValues exactSemanticConstraints⟩ }

def AcceptedBlockCallerSuppliedConditionalEvidence
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (block : AcceptedCanonicalBlock) : Type :=
  forall actions,
    decodeCanonicalActionStream codec block.actionBytes = some actions ->
    forall proof, proof ∈ canonicalTransfers actions ->
      CallerSuppliedTransactionConditionalEvidence proof

/--
Conditional supply-composition theorem. Its hypotheses explicitly assume, for
every accepted transaction, caller-supplied modeled-verifier evidence, the
negation of `NoValidExtraction`, and canonical semantic refinement, plus separate
Poseidon2 output-security assumptions. It is not a deployed end-to-end soundness
theorem.
-/
theorem accepted_block_given_caller_extraction_semantic_refinement_and_output_security_yields_no_counterfeit
    {hashes : ProductionIdentityFunctions}
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (conditionalEvidence :
      AcceptedBlockCallerSuppliedConditionalEvidence codec block)
    (poseidon2OutputSecurity :
      DeployedSmallWoodBlockPoseidon2OutputSecurityAssumptions codec block) :
    ScopedSecurityClaim .conditionalSupply
      (DeployedNoCounterfeitCriticalPathCertificate
        hashes codec verifier acceptedParent block) := by
  apply ScopedSecurityClaim.ofConditionalSupply
  apply
    accepted_deployed_smallwood_block_of_assumed_transaction_relations_and_poseidon_boundaries_yields_no_counterfeit_critical_path
      accepted
  · intro actions decoded proof membership
    exact
      caller_supplied_extraction_and_semantic_refinement_yield_transaction_relation
      (accepted.decodedProofsAccepted actions decoded proof membership)
      (conditionalEvidence actions decoded proof membership)
  · exact poseidon2OutputSecurity

end

end HegemonCrypto.SmallWood.ProductionSupplyChain
